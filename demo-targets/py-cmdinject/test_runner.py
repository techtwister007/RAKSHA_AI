"""The app's own regression suite: normal behaviour that must survive the fix."""
import sys; sys.path.insert(0, ".")
from app.runner import run_user_command


def test_runs_a_plain_name():
    assert run_user_command("status") == ["handling", "status"]


def test_runs_another_plain_name():
    assert run_user_command("report") == ["handling", "report"]
