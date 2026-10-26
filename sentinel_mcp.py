#!/usr/bin/env python3
"""
The Sentinels v1.0 - Single-File Tier-1 Control Plane (Stage 1 + Stage 2)
Repository: git@github.com:huri70459-png/The-Sentinels-v1.0-.git

Features (Zero Placeholders, Fail-Closed Architecture):
1. Stage 1 - Reality Lock & Git Worktree Sandbox:
   - Isolated git worktrees per task (`sentinel_init_task`).
   - Empty allow-list blocking & default scope budget (3 files / 80 changed lines).
   - Transactional sandbox writes (`sentinel_write_file`) with automatic rollback on violation.
   - Headless Playwright + Pytest Reality Verifier (`sentinel_verify_browser` & `sentinel_verify_cmd`)
     trapping console.error, pageerror, HTTP >= 400 network responses, and DOM selector assertions.
   - Hard-gated merge (`sentinel_merge_task`) bound to the exact verified git tree/commit hash.

2. Stage 2 - SQLite Project Brain & Failure Loop Blocker:
   - Zero-dependency SQLite3 database (`.sentinel/brain.db`) with WAL concurrency.
   - Architectural Decision Records (`decisions`) with forbidden regex/token scanning on diffs.
   - Failure Intelligence (`failed_attempts`) with normalized diff signature & SequenceMatcher
     similarity blocking (>= 0.88 similarity to a prior failed attempt is hard-blocked).
"""

import ast
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "ERROR: 'mcp' package not installed. Run: pip install 'mcp[cli]' playwright",
        file=sys.stderr,
    )
    sys.exit(1)

# Initialize FastMCP Server
mcp = FastMCP("The-Sentinels-v1.0")

# Default strict governance budgets
DEFAULT_MAX_FILES = 3
DEFAULT_MAX_CHANGED_LINES = 80
FAILURE_SIMILARITY_THRESHOLD = 0.88


# ============================================================================
# CORE UTILITIES & GIT / WORKTREE GOVERNANCE
# ============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_git(args: List[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git"] + args
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Git command failed ({' '.join(cmd)} in {cwd}):\n"
            f"STDOUT: {result.stdout.strip()}\nSTDERR: {result.stderr.strip()}"
        )
    return result


def get_repo_root() -> Path:
    env_root = os.environ.get("SENTINEL_REPO_ROOT")
    start_dir = Path(env_root).resolve() if env_root else Path.cwd().resolve()
    res = run_git(["rev-parse", "--show-toplevel"], cwd=start_dir, check=False)
    if res.returncode != 0:
        raise RuntimeError(
            f"Directory {start_dir} is not inside a valid Git repository. "
            "Initialize git or set SENTINEL_REPO_ROOT."
        )
    return Path(res.stdout.strip()).resolve()


def get_sentinel_dir(repo_root: Path) -> Path:
    sentinel_dir = repo_root / ".sentinel"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    (sentinel_dir / "worktrees").mkdir(parents=True, exist_ok=True)
    (sentinel_dir / "evidence").mkdir(parents=True, exist_ok=True)

    # Ensure .sentinel/ is ignored by git so local DB/worktrees never pollute commits
    gitignore_file = sentinel_dir / ".gitignore"
    if not gitignore_file.exists():
        gitignore_file.write_text("*\n", encoding="utf-8")
    return sentinel_dir


def compute_worktree_state_hash(worktree_path: Path) -> str:
    """
    Computes a deterministic SHA-256 fingerprint of HEAD + all tracked/untracked diffs
    inside the sandbox worktree. Used to bind verification evidence to the exact code state.
    """
    head_res = run_git(["rev-parse", "HEAD"], cwd=worktree_path, check=False)
    head_sha = head_res.stdout.strip() if head_res.returncode == 0 else "NO_HEAD"

    diff_res = run_git(["diff", "HEAD"], cwd=worktree_path, check=False)
    status_res = run_git(["status", "--porcelain"], cwd=worktree_path, check=False)

    hasher = hashlib.sha256()
    hasher.update(f"HEAD:{head_sha}\n".encode("utf-8"))
    hasher.update(f"STATUS:{status_res.stdout}\n".encode("utf-8"))
    hasher.update(f"DIFF:{diff_res.stdout}\n".encode("utf-8"))
    return hasher.hexdigest()


def compute_diff_stats(worktree_path: Path, base_commit: str) -> Tuple[List[str], int, str]:
    """
    Returns (changed_files_list, total_changed_lines, full_unified_diff)
    comparing current worktree state against base_commit.
    """
    # Stage intent-to-add for untracked files inside worktree so diff sees them
    status_res = run_git(["status", "--porcelain"], cwd=worktree_path, check=False)
    for line in status_res.stdout.splitlines():
        if line.startswith("?? "):
            untracked_rel = line[3:].strip()
            run_git(["add", "-N", untracked_rel], cwd=worktree_path, check=False)

    name_res = run_git(["diff", "--name-only", base_commit], cwd=worktree_path, check=False)
    changed_files = [f.strip() for f in name_res.stdout.splitlines() if f.strip()]

    numstat_res = run_git(["diff", "--numstat", base_commit], cwd=worktree_path, check=False)
    total_lines = 0
    for line in numstat_res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            added = int(parts[0]) if parts[0].isdigit() else 0
            deleted = int(parts[1]) if parts[1].isdigit() else 0
            total_lines += added + deleted

    full_diff_res = run_git(["diff", "--unified=0", base_commit], cwd=worktree_path, check=False)
    return changed_files, total_lines, full_diff_res.stdout


def normalize_diff_for_fingerprint(unified_diff: str) -> str:
    """
    Strips line numbers and file headers from unified diff so semantic change patterns
    can be compared reliably against historical failed attempts.
    """
    meaningful_lines = []
    for line in unified_diff.splitlines():
        if line.startswith(("+++", "---", "@@", "diff --git", "index ")):
            continue
        if line.startswith(("+", "-")):
            meaningful_lines.append(re.sub(r"\s+", " ", line.strip()))
    return "\n".join(meaningful_lines)


def check_ast_syntax(file_path: str, content: str) -> Optional[str]:
    """
    Validates Python syntax via native AST before allowing a write to disk.
    """
    if file_path.endswith(".py"):
        try:
            ast.parse(content, filename=file_path)
        except SyntaxError as exc:
            return f"Python AST SyntaxError at line {exc.lineno}, col {exc.offset}: {exc.msg}"
    return None


# ============================================================================
# STAGE 2: SQLITE PROJECT BRAIN & FAILURE INTELLIGENCE STORE
# ============================================================================

class SentinelBrain:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS decisions (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    forbidden_pattern TEXT,
                    active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tasks (
                    run_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    intent_layer TEXT NOT NULL,
                    allowed_globs_json TEXT NOT NULL,
                    max_files INTEGER NOT NULL,
                    max_changed_lines INTEGER NOT NULL,
                    base_branch TEXT NOT NULL,
                    base_commit TEXT NOT NULL,
                    worktree_path TEXT NOT NULL,
                    branch_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS verifications (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    verification_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    worktree_state_hash TEXT NOT NULL,
                    passed INTEGER NOT NULL,
                    http_status INTEGER,
                    console_errors INTEGER NOT NULL,
                    page_errors INTEGER NOT NULL,
                    network_failures INTEGER NOT NULL,
                    dom_pass INTEGER NOT NULL,
                    screenshot_path TEXT,
                    screenshot_sha256 TEXT,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES tasks(run_id)
                );

                CREATE TABLE IF NOT EXISTS failed_attempts (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    files_json TEXT NOT NULL,
                    normalized_diff TEXT NOT NULL,
                    diff_sha256 TEXT NOT NULL,
                    error_summary TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS violations (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def add_decision(
        self, category: str, rule: str, reason: str, forbidden_pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        decision_id = f"adr-{uuid.uuid4().hex[:8]}"
        if forbidden_pattern:
            try:
                re.compile(forbidden_pattern)
            except re.error as exc:
                raise ValueError(f"Invalid forbidden_pattern regex: {exc}")

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO decisions (id, category, rule, reason, forbidden_pattern, active, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (decision_id, category, rule, reason, forbidden_pattern, utc_now()),
            )
        return {
            "id": decision_id,
            "category": category,
            "rule": rule,
            "reason": reason,
            "forbidden_pattern": forbidden_pattern,
        }

    def list_active_decisions(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, category, rule, reason, forbidden_pattern, created_at FROM decisions WHERE active = 1 ORDER BY created_at ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def record_violation(
        self, run_id: str, category: str, message: str, metadata: Dict[str, Any]
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO violations (id, run_id, category, message, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"viol-{uuid.uuid4().hex[:10]}",
                    run_id,
                    category,
                    message,
                    json.dumps(metadata),
                    utc_now(),
                ),
            )

    def record_failed_attempt(
        self,
        run_id: str,
        objective: str,
        files: List[str],
        normalized_diff: str,
        error_summary: str,
    ) -> Optional[str]:
        if not normalized_diff.strip():
            return None
        diff_sha = hashlib.sha256(normalized_diff.encode("utf-8")).hexdigest()
        fail_id = f"fail-{uuid.uuid4().hex[:8]}"
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO failed_attempts (id, run_id, objective, files_json, normalized_diff, diff_sha256, error_summary, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fail_id,
                    run_id,
                    objective,
                    json.dumps(files),
                    normalized_diff,
                    diff_sha,
                    error_summary,
                    utc_now(),
                ),
            )
        return fail_id

    def check_against_failed_attempts(
        self, candidate_normalized_diff: str
    ) -> Optional[Dict[str, Any]]:
        """
        Compares candidate diff against all stored failed_attempts using exact SHA256
        or SequenceMatcher ratio >= FAILURE_SIMILARITY_THRESHOLD.
        """
        if not candidate_normalized_diff.strip():
            return None

        candidate_sha = hashlib.sha256(candidate_normalized_diff.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, run_id, objective, files_json, normalized_diff, diff_sha256, error_summary, created_at FROM failed_attempts ORDER BY created_at DESC LIMIT 100"
            ).fetchall()

        for row in rows:
            if row["diff_sha256"] == candidate_sha:
                return {
                    "match_type": "EXACT_HASH",
                    "similarity": 1.0,
                    "failed_attempt_id": row["id"],
                    "prior_run_id": row["run_id"],
                    "prior_error": row["error_summary"],
                    "files": json.loads(row["files_json"]),
                }
            ratio = difflib.SequenceMatcher(
                None, candidate_normalized_diff, row["normalized_diff"]
            ).ratio()
            if ratio >= FAILURE_SIMILARITY_THRESHOLD:
                return {
                    "match_type": "SEMANTIC_SIMILARITY",
                    "similarity": round(ratio, 4),
                    "failed_attempt_id": row["id"],
                    "prior_run_id": row["run_id"],
                    "prior_error": row["error_summary"],
                    "files": json.loads(row["files_json"]),
                }
        return None

    def get_task(self, run_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE run_id = ?", (run_id,)).fetchone()
            if not row:
                raise ValueError(f"Unknown run_id '{run_id}'. Call sentinel_init_task first.")
            return dict(row)


def get_brain() -> Tuple[Path, Path, SentinelBrain]:
    repo_root = get_repo_root()
    sentinel_dir = get_sentinel_dir(repo_root)
    brain = SentinelBrain(sentinel_dir / "brain.db")
    return repo_root, sentinel_dir, brain


# ============================================================================
# MCP TOOLS: STAGE 1 (WORKTREE + REALITY GATE) & STAGE 2 (PROJECT BRAIN)
# ============================================================================

@mcp.tool()
def sentinel_add_decision(
    category: str,
    rule: str,
    reason: str,
    forbidden_pattern: Optional[str] = None,
) -> str:
    """
    Stage 2 Project Brain: Lock an Architectural Decision Record (ADR) into SQLite.
    If `forbidden_pattern` (regex) is supplied, any proposed code write matching that
    pattern in added lines will be automatically blocked by `sentinel_write_file`.
    """
    _, _, brain = get_brain()
    record = brain.add_decision(
        category=category.strip(),
        rule=rule.strip(),
        reason=reason.strip(),
        forbidden_pattern=forbidden_pattern.strip() if forbidden_pattern else None,
    )
    return json.dumps({"status": "DECISION_LOCKED", "decision": record}, indent=2)


@mcp.tool()
def sentinel_init_task(
    objective: str,
    allowed_globs: List[str],
    intent_layer: str = "general",
    max_files: int = DEFAULT_MAX_FILES,
    max_changed_lines: int = DEFAULT_MAX_CHANGED_LINES,
) -> str:
    """
    Stage 1 + 2 Task Initializer:
    - Enforces Fail-Closed Empty Allow-List Blocking (`allowed_globs` must be non-empty).
    - Sets strict scope budget (default: max 3 files, max 80 changed lines).
    - Creates an isolated Git Worktree inside `.sentinel/worktrees/<run_id>`.
    - Retrieves active Project Brain ADRs and recent Failure Intelligence for context grounding.
    """
    if not objective or not objective.strip():
        return json.dumps(
            {"allowed": False, "error": "FAIL_CLOSED: 'objective' cannot be empty."}, indent=2
        )

    cleaned_globs = [g.strip() for g in allowed_globs if g and g.strip()]
    if not cleaned_globs:
        return json.dumps(
            {
                "allowed": False,
                "error": "FAIL_CLOSED: 'allowed_globs' cannot be empty. Provide explicit file paths or globs (e.g. ['src/ui/*.tsx']).",
            },
            indent=2,
        )

    repo_root, sentinel_dir, brain = get_brain()

    # Ensure repository has at least one commit so git worktree can branch
    head_check = run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root, check=False)
    if head_check.returncode != 0:
        return json.dumps(
            {
                "allowed": False,
                "error": "Git repository has no commits yet. Make an initial commit before starting a Sentinel task.",
            },
            indent=2,
        )

    base_commit = head_check.stdout.strip()
    branch_res = run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root, check=False)
    base_branch = branch_res.stdout.strip() if branch_res.returncode == 0 else "HEAD"

    run_id = f"run-{ datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') }-{uuid.uuid4().hex[:6]}"
    branch_name = f"sentinel/{run_id}"
    worktree_path = sentinel_dir / "worktrees" / run_id

    # Create isolated git worktree
    run_git(
        ["worktree", "add", "-b", branch_name, str(worktree_path), base_commit],
        cwd=repo_root,
        check=True,
    )

    now = utc_now()
    with brain._connect() as conn:
        conn.execute(
            """
            INSERT INTO tasks (
                run_id, objective, intent_layer, allowed_globs_json,
                max_files, max_changed_lines, base_branch, base_commit,
                worktree_path, branch_name, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                run_id,
                objective.strip(),
                intent_layer.strip(),
                json.dumps(cleaned_globs),
                int(max_files),
                int(max_changed_lines),
                base_branch,
                base_commit,
                str(worktree_path),
                branch_name,
                now,
                now,
            ),
        )

        recent_failures = [
            dict(r)
            for r in conn.execute(
                "SELECT id, objective, files_json, error_summary, created_at FROM failed_attempts ORDER BY created_at DESC LIMIT 5"
            ).fetchall()
        ]

    decisions = brain.list_active_decisions()

    return json.dumps(
        {
            "allowed": True,
            "run_id": run_id,
            "sandbox_worktree": str(worktree_path),
            "base_branch": base_branch,
            "base_commit": base_commit,
            "scope_contract": {
                "intent_layer": intent_layer,
                "allowed_globs": cleaned_globs,
                "max_files": max_files,
                "max_changed_lines": max_changed_lines,
            },
            "project_brain_decisions": decisions,
            "recent_failed_attempts": recent_failures,
        },
        indent=2,
    )


@mcp.tool()
def sentinel_write_file(run_id: str, relative_path: str, content: str) -> str:
    """
    Stage 1 + 2 Transactional Sandbox File Writer:
    1. Rejects path traversal or writes outside the sandbox worktree.
    2. Enforces the task's `allowed_globs` contract.
    3. Validates Python AST syntax prior to commit.
    4. Checks added lines against Project Brain ADR `forbidden_pattern` rules.
    5. Performs a transactional write inside the worktree and calculates cumulative diff stats:
       - If `max_files` or `max_changed_lines` budget is exceeded -> AUTOMATIC ROLLBACK.
       - If the normalized diff matches a prior `failed_attempts` entry -> AUTOMATIC ROLLBACK.
    """
    _, _, brain = get_brain()
    task = brain.get_task(run_id)

    if task["status"] != "ACTIVE":
        return json.dumps(
            {
                "allowed": False,
                "error": f"Task {run_id} is in status '{task['status']}' and cannot accept writes.",
            },
            indent=2,
        )

    worktree_path = Path(task["worktree_path"]).resolve()
    if not worktree_path.exists():
        return json.dumps(
            {"allowed": False, "error": f"Sandbox worktree missing at {worktree_path}."},
            indent=2,
        )

    # 1. Path sanitization & sandbox boundary check
    clean_rel = relative_path.strip().lstrip("/").replace("\\", "/")
    if not clean_rel or ".." in Path(clean_rel).parts or clean_rel.startswith(".git"):
        brain.record_violation(
            run_id, "PATH_BOUNDARY", f"Illegal relative path: {relative_path}", {"path": relative_path}
        )
        return json.dumps(
            {"allowed": False, "error": f"BLOCKED: Illegal sandbox path '{relative_path}'."},
            indent=2,
        )

    target_file = (worktree_path / clean_rel).resolve()
    if not str(target_file).startswith(str(worktree_path)):
        brain.record_violation(
            run_id, "SANDBOX_ESCAPE", f"Path escaped worktree: {relative_path}", {}
        )
        return json.dumps(
            {"allowed": False, "error": "BLOCKED: Path escapes sandbox worktree."}, indent=2
        )

    # 2. Enforce Explicit Allow-List Globs
    allowed_globs: List[str] = json.loads(task["allowed_globs_json"])
    if not any(fnmatch.fnmatch(clean_rel, pat) for pat in allowed_globs):
        brain.record_violation(
            run_id,
            "SCOPE_ALLOWLIST_VIOLATION",
            f"File '{clean_rel}' not matched by allowed_globs {allowed_globs}",
            {"file": clean_rel, "allowed_globs": allowed_globs},
        )
        return json.dumps(
            {
                "allowed": False,
                "violation": "SCOPE_ALLOWLIST_VIOLATION",
                "error": f"BLOCKED: '{clean_rel}' is outside allowed scope globs: {allowed_globs}",
            },
            indent=2,
        )

    # 3. Native AST Syntax Validation
    ast_err = check_ast_syntax(clean_rel, content)
    if ast_err:
        brain.record_violation(
            run_id, "AST_SYNTAX_ERROR", ast_err, {"file": clean_rel}
        )
        return json.dumps(
            {"allowed": False, "violation": "AST_SYNTAX_ERROR", "error": ast_err}, indent=2
        )

    # 4. Snapshot previous state for Transactional Rollback
    file_existed = target_file.exists()
    previous_bytes = target_file.read_bytes() if file_existed else None

    def rollback_write() -> None:
        if file_existed and previous_bytes is not None:
            target_file.write_bytes(previous_bytes)
        elif target_file.exists():
            target_file.unlink()
            run_git(["reset", "HEAD", "--", clean_rel], cwd=worktree_path, check=False)

    # Apply tentative write inside sandbox worktree
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(content, encoding="utf-8")

    changed_files, total_changed_lines, unified_diff = compute_diff_stats(
        worktree_path, task["base_commit"]
    )

    # 5. Check Project Brain ADR Forbidden Patterns against added diff lines
    decisions = brain.list_active_decisions()
    added_lines_text = "\n".join(
        line[1:]
        for line in unified_diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    for adr in decisions:
        pattern = adr.get("forbidden_pattern")
        if pattern and re.search(pattern, added_lines_text):
            rollback_write()
            msg = (
                f"ADR Violation [{adr['id']} - {adr['category']}]: "
                f"Rule '{adr['rule']}' triggered by forbidden pattern '{pattern}'."
            )
            brain.record_violation(run_id, "ADR_VIOLATION", msg, {"adr": adr, "file": clean_rel})
            return json.dumps(
                {
                    "allowed": False,
                    "rolled_back": True,
                    "violation": "PROJECT_BRAIN_ADR_CONFLICT",
                    "error": msg,
                },
                indent=2,
            )

    # 6. Check Scope Budget (max_files & max_changed_lines)
    if len(changed_files) > task["max_files"] or total_changed_lines > task["max_changed_lines"]:
        rollback_write()
        msg = (
            f"Scope budget exceeded: {len(changed_files)}/{task['max_files']} files, "
            f"{total_changed_lines}/{task['max_changed_lines']} changed lines."
        )
        brain.record_violation(
            run_id,
            "SCOPE_BUDGET_EXCEEDED",
            msg,
            {
                "changed_files": changed_files,
                "total_changed_lines": total_changed_lines,
                "max_files": task["max_files"],
                "max_changed_lines": task["max_changed_lines"],
            },
        )
        return json.dumps(
            {
                "allowed": False,
                "rolled_back": True,
                "violation": "SCOPE_BUDGET_EXCEEDED",
                "error": msg,
                "changed_files": changed_files,
                "total_changed_lines": total_changed_lines,
            },
            indent=2,
        )

    # 7. Check Stage 2 Failure Intelligence (Loop Blocker)
    norm_diff = normalize_diff_for_fingerprint(unified_diff)
    failure_match = brain.check_against_failed_attempts(norm_diff)
    if failure_match:
        rollback_write()
        msg = (
            f"Repeated Failure Pattern Blocked ({failure_match['match_type']}, "
            f"similarity={failure_match['similarity']}): Matches failed attempt "
            f"{failure_match['failed_attempt_id']} from {failure_match['prior_run_id']}. "
            f"Prior error: {failure_match['prior_error']}"
        )
        brain.record_violation(run_id, "REPEATED_FAILURE_PATTERN", msg, failure_match)
        return json.dumps(
            {
                "allowed": False,
                "rolled_back": True,
                "violation": "REPEATED_FAILURE_PATTERN",
                "error": msg,
                "failure_match": failure_match,
            },
            indent=2,
        )

    state_hash = compute_worktree_state_hash(worktree_path)
    return json.dumps(
        {
            "allowed": True,
            "rolled_back": False,
            "run_id": run_id,
            "written_file": clean_rel,
            "worktree_state_hash": state_hash,
            "budget_usage": {
                "files_changed": len(changed_files),
                "max_files": task["max_files"],
                "changed_lines": total_changed_lines,
                "max_changed_lines": task["max_changed_lines"],
                "modified_files": changed_files,
            },
        },
        indent=2,
    )


@mcp.tool()
def sentinel_verify_browser(
    run_id: str,
    url: str,
    required_selectors: Optional[List[str]] = None,
    expected_title_substring: Optional[str] = None,
    wait_ms: int = 1000,
) -> str:
    """
    Stage 1 Reality Verifier (Headless Playwright Gate):
    - Visits `url` (supports http://, https://, or relative sandbox file path rendered via file://).
    - Traps `console.error`, uncaught `pageerror`, and HTTP >= 400 network responses.
    - Verifies all `required_selectors` exist and are visible in the DOM.
    - Captures full-page PNG evidence + SHA-256 screenshot hash inside `.sentinel/evidence/`.
    - Records verification tied to the exact `worktree_state_hash`.
    - If verification FAILS, automatically logs the current diff into `failed_attempts`
      so the agent is blocked from repeating the same broken fix.
    """
    _, sentinel_dir, brain = get_brain()
    task = brain.get_task(run_id)
    worktree_path = Path(task["worktree_path"]).resolve()

    # Resolve local sandbox file paths to file:// URLs automatically
    target_url = url.strip()
    if not target_url.startswith(("http://", "https://", "file://")):
        candidate_file = (worktree_path / target_url.lstrip("/")).resolve()
        if candidate_file.exists():
            target_url = candidate_file.as_uri()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return json.dumps(
            {
                "passed": False,
                "error": "Playwright is not installed. Run: pip install playwright && playwright install chromium",
            },
            indent=2,
        )

    console_errors: List[str] = []
    page_errors: List[str] = []
    network_failures: List[str] = []
    missing_selectors: List[str] = []
    http_status: Optional[int] = None
    page_title = ""

    verification_id = f"ver-{uuid.uuid4().hex[:8]}"
    screenshot_path = sentinel_dir / "evidence" / f"{run_id}_{verification_id}.png"
    screenshot_sha256 = ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            page = context.new_page()

            page.on(
                "console",
                lambda msg: console_errors.append(msg.text)
                if msg.type == "error"
                else None,
            )
            page.on("pageerror", lambda exc: page_errors.append(str(exc)))
            page.on(
                "response",
                lambda resp: network_failures.append(f"{resp.status} {resp.url}")
                if resp.status >= 400
                else None,
            )
            page.on(
                "requestfailed",
                lambda req: network_failures.append(
                    f"FAILED {req.url} ({req.failure})"
                ),
            )

            response = page.goto(target_url, wait_until="networkidle", timeout=15000)
            if response is not None:
                http_status = response.status
            elif target_url.startswith("file://"):
                http_status = 200

            if wait_ms > 0:
                page.wait_for_timeout(wait_ms)

            page_title = page.title()

            if expected_title_substring and expected_title_substring not in page_title:
                missing_selectors.append(
                    f"Title mismatch: expected substring '{expected_title_substring}', got '{page_title}'"
                )

            for selector in required_selectors or []:
                loc = page.locator(selector).first
                if loc.count() == 0 or not loc.is_visible():
                    missing_selectors.append(selector)

            page.screenshot(path=str(screenshot_path), full_page=True)
            screenshot_sha256 = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()
            browser.close()
    except Exception as exc:
        page_errors.append(f"Playwright execution error: {exc}")

    http_ok = http_status is not None and 200 <= http_status < 400
    dom_pass = len(missing_selectors) == 0
    passed = (
        http_ok
        and dom_pass
        and len(console_errors) == 0
        and len(page_errors) == 0
        and len(network_failures) == 0
    )

    state_hash = compute_worktree_state_hash(worktree_path)
    evidence = {
        "verification_id": verification_id,
        "url": target_url,
        "title": page_title,
        "http_status": http_status,
        "dom_pass": dom_pass,
        "missing_selectors": missing_selectors,
        "console_errors": console_errors,
        "page_errors": page_errors,
        "network_failures": network_failures,
        "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "screenshot_sha256": screenshot_sha256,
        "worktree_state_hash": state_hash,
    }

    with brain._connect() as conn:
        conn.execute(
            """
            INSERT INTO verifications (
                id, run_id, verification_type, target, worktree_state_hash,
                passed, http_status, console_errors, page_errors,
                network_failures, dom_pass, screenshot_path, screenshot_sha256,
                evidence_json, created_at
            ) VALUES (?, ?, 'PLAYWRIGHT_BROWSER', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verification_id,
                run_id,
                target_url,
                state_hash,
                1 if passed else 0,
                http_status,
                len(console_errors),
                len(page_errors),
                len(network_failures),
                1 if dom_pass else 0,
                str(screenshot_path) if screenshot_path.exists() else None,
                screenshot_sha256,
                json.dumps(evidence),
                utc_now(),
            ),
        )

    # Automatically log failed diffs into Stage 2 Failure Intelligence
    logged_failure_id = None
    if not passed:
        changed_files, _, unified_diff = compute_diff_stats(
            worktree_path, task["base_commit"]
        )
        norm_diff = normalize_diff_for_fingerprint(unified_diff)
        err_summary = (
            f"Browser verification failed on {target_url}: "
            f"http={http_status}, console_errors={console_errors}, "
            f"page_errors={page_errors}, missing_selectors={missing_selectors}"
        )
        logged_failure_id = brain.record_failed_attempt(
            run_id=run_id,
            objective=task["objective"],
            files=changed_files,
            normalized_diff=norm_diff,
            error_summary=err_summary,
        )

    return json.dumps(
        {
            "passed": passed,
            "status": "VERIFIED_PASS" if passed else "UNVERIFIED_FAIL",
            "logged_failed_attempt_id": logged_failure_id,
            "evidence": evidence,
        },
        indent=2,
    )


@mcp.tool()
def sentinel_verify_cmd(
    run_id: str,
    test_command: List[str],
    timeout_seconds: int = 60,
) -> str:
    """
    Stage 1 Reality Verifier (CLI / Pytest / Unit Test Gate):
    Executes a deterministic test command (e.g. ['pytest', '-q']) inside the isolated
    git worktree and records verification tied to `worktree_state_hash`.
    """
    _, _, brain = get_brain()
    task = brain.get_task(run_id)
    worktree_path = Path(task["worktree_path"]).resolve()

    if not test_command:
        return json.dumps({"passed": False, "error": "test_command cannot be empty."}, indent=2)

    # Disallow shell injection tokens
    forbidden_tokens = {";", "&&", "||", "|", "`", "$(", ">"}
    if any(tok in arg for arg in test_command for tok in forbidden_tokens):
        return json.dumps(
            {
                "passed": False,
                "error": "BLOCKED: Shell chaining tokens are forbidden in sentinel_verify_cmd.",
            },
            indent=2,
        )

    verification_id = f"ver-{uuid.uuid4().hex[:8]}"
    try:
        proc = subprocess.run(
            test_command,
            cwd=str(worktree_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        passed = proc.returncode == 0
        stdout_tail = proc.stdout[-2000:]
        stderr_tail = proc.stderr[-2000:]
        exit_code = proc.returncode
    except Exception as exc:
        passed = False
        stdout_tail = ""
        stderr_tail = str(exc)
        exit_code = -1

    state_hash = compute_worktree_state_hash(worktree_path)
    evidence = {
        "verification_id": verification_id,
        "command": test_command,
        "exit_code": exit_code,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "worktree_state_hash": state_hash,
    }

    with brain._connect() as conn:
        conn.execute(
            """
            INSERT INTO verifications (
                id, run_id, verification_type, target, worktree_state_hash,
                passed, http_status, console_errors, page_errors,
                network_failures, dom_pass, screenshot_path, screenshot_sha256,
                evidence_json, created_at
            ) VALUES (?, ?, 'TEST_CMD', ?, ?, ?, ?, 0, 0, 0, ?, NULL, NULL, ?, ?)
            """,
            (
                verification_id,
                run_id,
                " ".join(test_command),
                state_hash,
                1 if passed else 0,
                exit_code,
                1 if passed else 0,
                json.dumps(evidence),
                utc_now(),
            ),
        )

    logged_failure_id = None
    if not passed:
        changed_files, _, unified_diff = compute_diff_stats(
            worktree_path, task["base_commit"]
        )
        norm_diff = normalize_diff_for_fingerprint(unified_diff)
        logged_failure_id = brain.record_failed_attempt(
            run_id=run_id,
            objective=task["objective"],
            files=changed_files,
            normalized_diff=norm_diff,
            error_summary=f"Command {test_command} failed (exit {exit_code}): {stderr_tail or stdout_tail}",
        )

    return json.dumps(
        {
            "passed": passed,
            "status": "VERIFIED_PASS" if passed else "UNVERIFIED_FAIL",
            "logged_failed_attempt_id": logged_failure_id,
            "evidence": evidence,
        },
        indent=2,
    )


@mcp.tool()
def sentinel_merge_task(
    run_id: str,
    commit_message: Optional[str] = None,
    cleanup_worktree: bool = True,
) -> str:
    """
    Stage 1 Hard Merge Gate:
    - Recomputes the current `worktree_state_hash`.
    - Queries SQLite `verifications` to confirm a `passed = 1` verification exists for
      THIS exact `worktree_state_hash` (if the agent modified a single character after
      running verification, the hash changes and the merge is BLOCKED).
    - Re-verifies Scope Budget (`max_files` & `max_changed_lines`).
    - Commits inside the sandbox worktree, merges into the base branch, and cleans up the worktree.
    """
    repo_root, _, brain = get_brain()
    task = brain.get_task(run_id)

    if task["status"] != "ACTIVE":
        return json.dumps(
            {"merged": False, "error": f"Task {run_id} is already in status '{task['status']}'."},
            indent=2,
        )

    worktree_path = Path(task["worktree_path"]).resolve()
    current_state_hash = compute_worktree_state_hash(worktree_path)

    with brain._connect() as conn:
        ver_row = conn.execute(
            """
            SELECT * FROM verifications
            WHERE run_id = ? AND worktree_state_hash = ? AND passed = 1
            ORDER BY created_at DESC LIMIT 1
            """,
            (run_id, current_state_hash),
        ).fetchone()

    if not ver_row:
        changed_files, _, unified_diff = compute_diff_stats(
            worktree_path, task["base_commit"]
        )
        norm_diff = normalize_diff_for_fingerprint(unified_diff)
        fail_id = brain.record_failed_attempt(
            run_id=run_id,
            objective=task["objective"],
            files=changed_files,
            normalized_diff=norm_diff,
            error_summary="Attempted merge without passing verification for current worktree state hash.",
        )
        brain.record_violation(
            run_id,
            "UNVERIFIED_MERGE_ATTEMPT",
            "Agent called sentinel_merge_task without a passing verification matching current worktree_state_hash.",
            {"worktree_state_hash": current_state_hash, "failed_attempt_id": fail_id},
        )
        return json.dumps(
            {
                "merged": False,
                "status": "BLOCKED_UNVERIFIED",
                "error": (
                    "HARD GATE BLOCKED: No passing verification exists for the current worktree state hash "
                    f"({current_state_hash[:12]}...). Run sentinel_verify_browser or sentinel_verify_cmd first."
                ),
                "logged_failed_attempt_id": fail_id,
            },
            indent=2,
        )

    changed_files, total_changed_lines, _ = compute_diff_stats(
        worktree_path, task["base_commit"]
    )
    if not changed_files:
        return json.dumps(
            {"merged": False, "error": "No changed files in worktree to merge."}, indent=2
        )

    if len(changed_files) > task["max_files"] or total_changed_lines > task["max_changed_lines"]:
        return json.dumps(
            {
                "merged": False,
                "error": "Scope budget exceeded at merge check.",
                "changed_files": changed_files,
                "total_changed_lines": total_changed_lines,
            },
            indent=2,
        )

    # Commit inside sandbox worktree
    run_git(["add", "-A"], cwd=worktree_path, check=True)
    msg = commit_message or f"Sentinel verified merge ({run_id}): {task['objective']}"
    run_git(["commit", "-m", msg], cwd=worktree_path, check=True)
    commit_sha = run_git(["rev-parse", "HEAD"], cwd=worktree_path, check=True).stdout.strip()

    # Merge branch into base repo
    run_git(["merge", "--no-ff", task["branch_name"], "-m", f"Merge {task['branch_name']}"], cwd=repo_root, check=True)

    if cleanup_worktree:
        run_git(["worktree", "remove", "--force", str(worktree_path)], cwd=repo_root, check=False)
        run_git(["branch", "-d", task["branch_name"]], cwd=repo_root, check=False)

    with brain._connect() as conn:
        conn.execute(
            "UPDATE tasks SET status = 'MERGED', updated_at = ? WHERE run_id = ?",
            (utc_now(), run_id),
        )

    return json.dumps(
        {
            "merged": True,
            "status": "MERGED",
            "run_id": run_id,
            "commit_sha": commit_sha,
            "verified_by": ver_row["id"],
            "verification_type": ver_row["verification_type"],
            "changed_files": changed_files,
            "total_changed_lines": total_changed_lines,
        },
        indent=2,
    )


@mcp.tool()
def sentinel_status(run_id: Optional[str] = None) -> str:
    """
    Returns full telemetry from `.sentinel/brain.db`: active decisions, tasks,
    verifications, failed attempts, and policy violations.
    """
    _, sentinel_dir, brain = get_brain()
    with brain._connect() as conn:
        decisions = brain.list_active_decisions()
        if run_id:
            tasks = [
                dict(r)
                for r in conn.execute("SELECT * FROM tasks WHERE run_id = ?", (run_id,)).fetchall()
            ]
            verifications = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, verification_type, target, passed, http_status, console_errors, page_errors, network_failures, dom_pass, created_at FROM verifications WHERE run_id = ? ORDER BY created_at DESC",
                    (run_id,),
                ).fetchall()
            ]
            violations = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM violations WHERE run_id = ? ORDER BY created_at DESC",
                    (run_id,),
                ).fetchall()
            ]
        else:
            tasks = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM tasks ORDER BY created_at DESC LIMIT 10"
                ).fetchall()
            ]
            verifications = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, run_id, verification_type, target, passed, http_status, console_errors, page_errors, network_failures, dom_pass, created_at FROM verifications ORDER BY created_at DESC LIMIT 10"
                ).fetchall()
            ]
            violations = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM violations ORDER BY created_at DESC LIMIT 10"
                ).fetchall()
            ]

        failed_attempts = [
            dict(r)
            for r in conn.execute(
                "SELECT id, run_id, objective, files_json, error_summary, created_at FROM failed_attempts ORDER BY created_at DESC LIMIT 10"
            ).fetchall()
        ]

    return json.dumps(
        {
            "database": str(sentinel_dir / "brain.db"),
            "decisions_count": len(decisions),
            "decisions": decisions,
            "tasks": tasks,
            "verifications": verifications,
            "failed_attempts": failed_attempts,
            "violations": violations,
        },
        indent=2,
    )


# ============================================================================
# BUILT-IN SELF-TEST SUITE (--self-test)
# ============================================================================

def run_self_test() -> int:
    """
    Executes an end-to-end deterministic verification of Stage 1 + Stage 2
    inside a temporary git repository so you can verify all gates immediately.
    """
    print("=== Running The-Sentinels-v1.0 Stage 1 + Stage 2 Self-Test ===")
    tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel_selftest_")).resolve()
    os.environ["SENTINEL_REPO_ROOT"] = str(tmp_dir)

    try:
        run_git(["init", "-b", "main"], cwd=tmp_dir)
        run_git(["config", "user.email", "sentinel@local.test"], cwd=tmp_dir)
        run_git(["config", "user.name", "Sentinel Test"], cwd=tmp_dir)

        (tmp_dir / "src").mkdir()
        (tmp_dir / "src" / "app.py").write_text("def greet():\n    return 'hello'\n", encoding="utf-8")
        (tmp_dir / "src" / "index.html").write_text(
            "<!DOCTYPE html><html><head><title>Sentinel App</title></head>"
            "<body><button id='cta-btn'>Launch</button></body></html>",
            encoding="utf-8",
        )
        run_git(["add", "-A"], cwd=tmp_dir)
        run_git(["commit", "-m", "Initial commit"], cwd=tmp_dir)

        # 1. Test Empty Allow-List Blocking
        res_empty = json.loads(sentinel_init_task("Fix UI", allowed_globs=[]))
        assert res_empty["allowed"] is False, "Empty allow-list must fail-closed!"
        print("[PASS] Gate 1: Empty allow-list blocked.")

        # 2. Lock an ADR Decision in Project Brain
        adr_res = json.loads(
            sentinel_add_decision(
                category="security",
                rule="Never use eval() in Python files",
                reason="Prevent arbitrary code execution",
                forbidden_pattern=r"\beval\s*\(",
            )
        )
        assert adr_res["status"] == "DECISION_LOCKED"
        print("[PASS] Gate 2: Project Brain ADR locked in SQLite.")

        # 3. Initialize a governed task (default 3 files / 80 lines budget)
        init_res = json.loads(
            sentinel_init_task(
                objective="Update greeting and verify HTML button",
                allowed_globs=["src/*.py", "src/*.html"],
                intent_layer="ui_and_app",
            )
        )
        assert init_res["allowed"] is True
        run_id = init_res["run_id"]
        print(f"[PASS] Gate 3: Isolated Git Worktree created ({run_id}).")

        # 4. Test Out-of-Scope File Write Blocking
        out_scope = json.loads(
            sentinel_write_file(run_id, "README.md", "# Unauthorized change\n")
        )
        assert out_scope["allowed"] is False
        assert out_scope["violation"] == "SCOPE_ALLOWLIST_VIOLATION"
        print("[PASS] Gate 4: Out-of-scope file write blocked.")

        # 5. Test ADR Forbidden Pattern Rollback
        adr_viol = json.loads(
            sentinel_write_file(
                run_id, "src/app.py", "def greet():\n    return eval('1+1')\n"
            )
        )
        assert adr_viol["allowed"] is False
        assert adr_viol["rolled_back"] is True
        assert adr_viol["violation"] == "PROJECT_BRAIN_ADR_CONFLICT"
        print("[PASS] Gate 5: Project Brain ADR conflict blocked and rolled back.")

        # 6. Write valid change inside budget
        valid_write = json.loads(
            sentinel_write_file(
                run_id, "src/app.py", "def greet():\n    return 'hello sentinel'\n"
            )
        )
        assert valid_write["allowed"] is True
        print("[PASS] Gate 6: Valid sandbox write accepted within scope budget.")

        # 7. Test Unverified Merge Blocking (Hard Gate)
        unverified_merge = json.loads(sentinel_merge_task(run_id))
        assert unverified_merge["merged"] is False
        assert unverified_merge["status"] == "BLOCKED_UNVERIFIED"
        print("[PASS] Gate 7: Unverified merge blocked and logged to failed_attempts.")

        # 8. Test Repeated Failure Pattern Blocker
        repeat_write = json.loads(
            sentinel_write_file(
                run_id, "src/app.py", "def greet():\n    return 'hello sentinel'\n"
            )
        )
        assert repeat_write["allowed"] is False
        assert repeat_write["violation"] == "REPEATED_FAILURE_PATTERN"
        print("[PASS] Gate 8: Repeated failure diff pattern blocked by Failure Intelligence.")

        # 9. Write a fresh valid implementation, verify with sentinel_verify_cmd, and merge
        fresh_write = json.loads(
            sentinel_write_file(
                run_id,
                "src/app.py",
                "def greet():\n    return 'verified sentinel v1'\n\nif __name__ == '__main__':\n    assert greet() == 'verified sentinel v1'\n",
            )
        )
        assert fresh_write["allowed"] is True

        ver_cmd = json.loads(
            sentinel_verify_cmd(run_id, [sys.executable, "src/app.py"])
        )
        assert ver_cmd["passed"] is True
        print("[PASS] Gate 9: Reality verification passed and bound to worktree_state_hash.")

        merge_res = json.loads(sentinel_merge_task(run_id))
        assert merge_res["merged"] is True
        assert (tmp_dir / "src" / "app.py").read_text(encoding="utf-8").startswith(
            "def greet():\n    return 'verified sentinel v1'"
        )
        print("[PASS] Gate 10: Verified worktree merged cleanly into main branch.")
        print("\nALL 10 SENTINEL STAGE 1 + STAGE 2 GATES PASSED.")
        return 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# STAGE 3: FAIL-CLOSED PATH/DIFF GUARD + STRUCTURAL CHECKS (client boundary)
# Governs configured client tools, not every possible way to modify files.
# ============================================================================

def stage3_check_path(
    relative_path: str, allowed_globs: List[str], protected_globs: List[str]
) -> Dict[str, Any]:
    """Deterministic path guard. Fail closed on traversal, protected, or unclassified."""
    clean = (relative_path or "").strip().lstrip("/").replace("\\", "/")
    if not clean or ".." in Path(clean).parts or clean.startswith(".git"):
        return {"allowed": False, "violation": "PATH_TRAVERSAL", "error": f"BLOCKED: illegal path '{relative_path}'."}
    for pat in protected_globs or []:
        if fnmatch.fnmatch(clean, pat):
            return {"allowed": False, "violation": "PROTECTED_PATH", "error": f"BLOCKED: '{clean}' matches protected glob '{pat}'."}
    # Unclassifiable change fails closed: bare name with no extension and no directory
    if "/" not in clean and "." not in Path(clean).name:
        return {"allowed": False, "violation": "UNCLASSIFIED_PATH", "error": f"BLOCKED: unclassifiable path '{clean}' fails closed."}
    if not any(fnmatch.fnmatch(clean, pat) for pat in (allowed_globs or [])):
        return {"allowed": False, "violation": "SCOPE_ALLOWLIST_VIOLATION", "error": f"BLOCKED: '{clean}' outside allowed globs {allowed_globs}."}
    return {"allowed": True, "path": clean}


def stage3_check_diff(
    changed_files: List[str], total_changed_lines: int, max_files: int, max_changed_lines: int
) -> Dict[str, Any]:
    """Budget guard over the complete change set, including deletes/renames."""
    files = list(changed_files or [])
    if len(files) > int(max_files) or int(total_changed_lines) > int(max_changed_lines):
        return {
            "allowed": False,
            "violation": "SCOPE_BUDGET_EXCEEDED",
            "error": f"BLOCKED: {len(files)}/{max_files} files, {total_changed_lines}/{max_changed_lines} lines (max_files/max_changed_lines exceeded).",
        }
    return {"allowed": True, "files": files, "lines": int(total_changed_lines)}


def _py_signatures(source: str) -> Dict[str, tuple]:
    tree = ast.parse(source)
    sigs: Dict[str, tuple] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            args = tuple(a.arg for a in node.args.args)
            sigs[node.name] = args
    return sigs


def stage3_check_py_signature(file_path: str, old_content: str, new_content: str) -> Dict[str, Any]:
    """Language-aware check (Python only): public function signatures must not change."""
    if not file_path.endswith(".py"):
        return {"allowed": True, "skipped": "non-python enforced at path/diff level"}
    try:
        old_sigs = _py_signatures(old_content or "")
        new_sigs = _py_signatures(new_content or "")
    except SyntaxError as exc:
        return {"allowed": False, "violation": "AST_SYNTAX_ERROR", "error": f"BLOCKED: {exc}"}
    for name, old_args in old_sigs.items():
        if name in new_sigs and new_sigs[name] != old_args:
            return {
                "allowed": False,
                "violation": "SIGNATURE_CHANGED",
                "error": f"BLOCKED: public function '{name}{old_args}' signature changed to '{new_sigs[name]}' without authorization.",
            }
    return {"allowed": True}


@mcp.tool()
def sentinel_guard_check(
    run_id: str,
    changed_files: List[str],
    total_changed_lines: int,
    protected_globs: Optional[List[str]] = None,
) -> str:
    """Stage 3 deterministic guard: allow-list + protected + budget over full change set."""
    _, _, brain = get_brain()
    task = brain.get_task(run_id)
    allowed_globs: List[str] = json.loads(task["allowed_globs_json"])
    for f in changed_files or []:
        pr = stage3_check_path(f, allowed_globs, protected_globs or [])
        if not pr["allowed"]:
            brain.record_violation(run_id, pr.get("violation", "GUARD"), pr["error"], {"file": f})
            return json.dumps({"allowed": False, **pr}, indent=2)
    dr = stage3_check_diff(changed_files or [], total_changed_lines, task["max_files"], task["max_changed_lines"])
    if not dr["allowed"]:
        brain.record_violation(run_id, "SCOPE_BUDGET_EXCEEDED", dr["error"], dr)
        return json.dumps({"allowed": False, **dr}, indent=2)
    return json.dumps({"allowed": True, "run_id": run_id, "files": changed_files}, indent=2)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(run_self_test())
    mcp.run()
