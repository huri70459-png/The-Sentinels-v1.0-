"""Path scope guard: allow-list + protected globs, fail closed."""
import fnmatch
from pathlib import Path
from typing import Any, Dict, List


def check_path(
    relative_path: str, allowed_globs: List[str], protected_globs: List[str]
) -> Dict[str, Any]:
    clean = (relative_path or "").strip().lstrip("/").replace("\\", "/")
    if not clean or ".." in Path(clean).parts or clean.startswith(".git"):
        return {"allowed": False, "violation": "PATH_TRAVERSAL", "error": f"BLOCKED: illegal path '{relative_path}'."}
    for pat in protected_globs or []:
        if fnmatch.fnmatch(clean, pat):
            return {"allowed": False, "violation": "PROTECTED_PATH", "error": f"BLOCKED: '{clean}' matches protected glob '{pat}'."}
    if "/" not in clean and "." not in Path(clean).name:
        return {"allowed": False, "violation": "UNCLASSIFIED_PATH", "error": f"BLOCKED: unclassifiable path '{clean}' fails closed."}
    if not any(fnmatch.fnmatch(clean, pat) for pat in (allowed_globs or [])):
        return {"allowed": False, "violation": "SCOPE_ALLOWLIST_VIOLATION", "error": f"BLOCKED: '{clean}' outside allowed globs {allowed_globs}."}
    return {"allowed": True, "path": clean}
