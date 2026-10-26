"""Slice 1 RED tests: policy guards as importable services (src layout)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentinels.policy.path_guard import check_path
from sentinels.policy.diff_guard import check_diff
from sentinels.policy.signature_guard import check_py_signature


def test_permitted_write_allowed():
    assert check_path("src/app.py", ["src/*.py"], [])["allowed"] is True


def test_forbidden_path_blocked():
    assert check_path("README.md", ["src/*.py"], [])["allowed"] is False


def test_protected_glob_untouched():
    r = check_path("src/secret.py", ["src/*.py"], ["src/secret.py"])
    assert r["allowed"] is False and r["violation"] == "PROTECTED_PATH"


def test_unclassified_type_fails_closed():
    assert check_path("blobfish", ["*"], [])["allowed"] is False


def test_diff_budget_enforced():
    r = check_diff(["a.py", "b.py", "c.py", "d.py"], 10, 3, 80)
    assert r["allowed"] is False and "max_files" in r["error"]


def test_diff_deletes_counted():
    assert check_diff(["src/app.py"], 90, 3, 80)["allowed"] is False


def test_py_signature_change_blocked():
    old = "def greet(name):\n    return name\n"
    new = "def greet(name, extra):\n    return name\n"
    r = check_py_signature("src/app.py", old, new)
    assert r["allowed"] is False and r["violation"] == "SIGNATURE_CHANGED"


def test_non_python_skipped_at_structural_level():
    r = check_py_signature("web/app.ts", "a", "b")
    assert r["allowed"] is True and r.get("skipped") is not None
