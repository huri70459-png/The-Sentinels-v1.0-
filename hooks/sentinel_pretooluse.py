#!/usr/bin/env python3
"""Sentinel PreToolUse hook adapter (Claude Code + Cursor).
Reads hook JSON from stdin, exits 0 to allow, 2 to block with message on stderr.
Reviewed: no shell execution, only path matching. Runs with user permissions.

Env:
  SENTINEL_WORKTREE  absolute path of the active task worktree (required)
  SENTINEL_ALLOWED   comma-separated allow globs, e.g. "src/*.py,src/*.html" (required)
"""
import fnmatch
import json
import sys
from os import environ
from pathlib import Path


def _load_input():
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def _deny(msg):
    print(f"Sentinel BLOCKED: {msg}", file=sys.stderr)
    return 2


def main():
    data = _load_input()
    if not isinstance(data, dict) or not data:
        return _deny("malformed hook input fails closed.")
    tool = str(data.get("tool_name") or data.get("tool") or "")
    inp = data.get("tool_input") or data.get("input") or {}
    candidate = str(
        inp.get("file_path") or inp.get("path") or inp.get("file") or inp.get("command") or ""
    )
    worktree = environ.get("SENTINEL_WORKTREE", "").strip()
    allowed_raw = environ.get("SENTINEL_ALLOWED", "").strip()
    if not worktree or not allowed_raw:
        return _deny("no active Sentinel task (SENTINEL_WORKTREE/SENTINEL_ALLOWED unset).")
    allowed = [g.strip() for g in allowed_raw.split(",") if g.strip()]
    # Shell commands: deny any that reference absolute paths outside the worktree
    if tool.lower() in ("bash", "shell", "exec") and candidate:
        if candidate.startswith("/") or (len(candidate) > 2 and candidate[1] == ":"):
            if not candidate.startswith(worktree):
                return _deny(f"shell path outside worktree: {candidate}")
        return 0
    if tool.lower() in ("write", "edit", "create", "apply_patch", "multiedit"):
        p = candidate.strip().lstrip("/").replace("\\", "/")
        if not p or ".." in Path(p).parts:
            return _deny(f"illegal path '{candidate}'.")
        if not any(fnmatch.fnmatch(p, g) for g in allowed):
            return _deny(f"'{p}' outside allowed {allowed}.")
        return 0
    # Unknown write mechanisms deny by default; read-only tools allow
    if tool.lower() in ("read", "glob", "grep", "ls", "log"):
        return 0
    return _deny(f"unrecognized write mechanism '{tool}' fails closed.")


if __name__ == "__main__":
    sys.exit(main())
