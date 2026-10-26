"""Stage 3 RED tests: fail-closed path/diff guard + hook boundary."""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# These imports MUST fail until Stage 3 is implemented (RED phase)
from sentinel_mcp import (
    stage3_check_path,
    stage3_check_diff,
    stage3_check_py_signature,
)


def test_permitted_write_allowed():
    r = stage3_check_path("src/app.py", ["src/*.py"], [])
    assert r["allowed"] is True


def test_forbidden_path_blocked():
    r = stage3_check_path("README.md", ["src/*.py"], [])
    assert r["allowed"] is False


def test_protected_glob_untouched():
    r = stage3_check_path("src/secret.py", ["src/*.py"], ["src/secret.py"])
    assert r["allowed"] is False
    assert r["violation"] == "PROTECTED_PATH"


def test_unclassified_type_fails_closed():
    r = stage3_check_path("blobfish", ["*"], [])
    # no extension / unclassifiable must fail closed when strict
    assert r["allowed"] is False


def test_diff_budget_enforced():
    files = ["a.py", "b.py", "c.py", "d.py"]
    r = stage3_check_diff(files, 10, 3, 80)
    assert r["allowed"] is False
    assert "max_files" in r["error"]


def test_diff_deletes_counted():
    # deletes/renames must be included: 90 deleted lines exceeds 80 budget
    r = stage3_check_diff(["src/app.py"], 90, 3, 80)
    assert r["allowed"] is False


def test_py_signature_change_blocked():
    old = "def greet(name):\n    return name\n"
    new = "def greet(name, extra):\n    return name\n"
    r = stage3_check_py_signature("src/app.py", old, new)
    assert r["allowed"] is False
    assert r["violation"] == "SIGNATURE_CHANGED"
