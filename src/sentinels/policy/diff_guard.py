"""Diff budget guard over the complete change set, including deletes/renames."""
from typing import Any, Dict, List


def check_diff(
    changed_files: List[str], total_changed_lines: int, max_files: int, max_changed_lines: int
) -> Dict[str, Any]:
    files = list(changed_files or [])
    if len(files) > int(max_files) or int(total_changed_lines) > int(max_changed_lines):
        return {
            "allowed": False,
            "violation": "SCOPE_BUDGET_EXCEEDED",
            "error": f"BLOCKED: {len(files)}/{max_files} files, {total_changed_lines}/{max_changed_lines} lines (max_files/max_changed_lines exceeded).",
        }
    return {"allowed": True, "files": files, "lines": int(total_changed_lines)}
