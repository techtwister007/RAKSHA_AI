"""Pure patch-generator checks for the C and Python template fixes (fast, always run)."""
import pathlib

from raksha.adapters.c_asan import bounds_check_patch
from raksha.adapters.python_sink import shell_false_patch

ROOT = pathlib.Path(__file__).parents[1] / "demo-targets"


def test_c_bounds_check_patch():
    cp = bounds_check_patch((ROOT / "c-overflow" / "src" / "parser.c").read_text())
    assert "--- a/src/parser.c" in cp and "sizeof(buf)" in cp and cp.count("\n") > 3


def test_python_shell_false_patch():
    pp = shell_false_patch((ROOT / "py-cmdinject" / "app" / "runner.py").read_text())
    assert "shell=False" in pp and '["echo"' in pp
