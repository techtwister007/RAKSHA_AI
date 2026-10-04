"""Python adapter — configures the generic CommandTarget for a Python project.

The deep lane for Python: run inputs through a replay driver that observes a dangerous sink
(shell=True with tainted input) and reports it in PySecSan's format, which RAKSHA's PySecSanOracle
parses. "Compiling" for Python is a parse/import check. The fix lane for the demo target swaps the
shell string for an argument list with shell=False (template); the gate proves it like any other.
"""

from __future__ import annotations

import difflib
from pathlib import Path

from ..gate.target import CommandTarget


def python_target(root: str | Path, *, driver: str = "fuzz_cmd.py",
                  test_file: str = "test_runner.py", timeout: float = 120.0) -> CommandTarget:
    return CommandTarget(
        source_root=Path(root).resolve(),
        # "COMPILES" for Python: the package imports cleanly.
        build_cmd="python3 -c \"import py_compile,glob,sys; "
                  "[py_compile.compile(f,doraise=True) for f in glob.glob('app/*.py')]\"",
        run_cmd=f"python3 {driver} {{input}}",
        test_cmd=f"python3 -m pytest -q {test_file}",
        coverage_cmd=f"python3 {driver} {{input}} --coverage",
        refuzz_cmd=(
            "i=0; for p in 'a; id' 'b | cat /etc/hostname' 'c && echo x' 'd `whoami`' 'e > /tmp/z'; do "
            "i=$((i+1)); printf '%s' \"$p\" > rf_$i; "
            "python3 " + driver + " rf_$i > err_$i 2>&1; "
            "if [ $? -ne 0 ]; then cp err_$i {out}/crash_$i; fi; done"
        ),
        apply_patch_cmd="git apply -p1 {patch}",
        timeout=timeout,
    )


def shell_false_patch(runner_src: str) -> str:
    """Template-lane fix: replace the shell string + shell=True with an arg list + shell=False."""
    before = runner_src
    vuln = ('    cmd = "echo handling " + name                 '
            '# BUG: input interpolated into a shell line\n'
            '    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.split()\n')
    fix = ('    cmd = ["echo", "handling", name]               '
           '# FIX: argument list, no shell\n'
           '    return subprocess.run(cmd, shell=False, capture_output=True, text=True).stdout.split()\n')
    if vuln not in before:
        raise ValueError("vulnerable sink lines not found in runner.py")
    after = before.replace(vuln, fix)
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/app/runner.py", tofile="b/app/runner.py"))
