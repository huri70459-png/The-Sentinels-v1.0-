"""Structural guard, Python only: public function signatures must not change."""
import ast
from typing import Any, Dict


def _signatures(source: str) -> Dict[str, tuple]:
    tree = ast.parse(source)
    sigs: Dict[str, tuple] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            sigs[node.name] = tuple(a.arg for a in node.args.args)
    return sigs


def check_py_signature(file_path: str, old_content: str, new_content: str) -> Dict[str, Any]:
    if not file_path.endswith(".py"):
        return {"allowed": True, "skipped": "non-python enforced at path/diff level"}
    try:
        old_sigs = _signatures(old_content or "")
        new_sigs = _signatures(new_content or "")
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
