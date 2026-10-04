"""A dependency-free dynamic sink sanitizer for the synthesized Python harness.

Python has no ASan, so a command injection does not crash — it quietly runs. A fuzzer that only
watches for exceptions never sees it. PySecSan solves this by hooking the dangerous sinks; this is a
small, honest version of the same idea for when PySecSan is not installed on the sealed node: it
wraps the shell / eval / deserialization sinks so that a call carrying injected shell metacharacters
is REPORTED (in PySecSan's own output format, which the oracle already parses) and BLOCKED rather
than executed. Blocking matters: we are feeding adversarial input, and we will not actually run
`rm -rf` to prove it was reachable.

It flags only a sink reached with a metacharacter, so a benign input (no metacharacters) passes
untouched — which is exactly what the harness quality gate needs. Installed by the synthesized
harness before the target is imported; no effect on any other process.
"""

from __future__ import annotations

import builtins
import os
import subprocess
import sys
import traceback

#: Shell metacharacters that turn a string argument into additional commands.
_SHELL_META = (";", "|", "&", "$", "`", "\n", ">", "<", "(", ")", "{", "}", "&&", "||")


def _looks_injected(command: str) -> bool:
    return isinstance(command, str) and any(m in command for m in _SHELL_META)


def _report(detector: str, sink: str, cwe_hint: str) -> None:
    # PySecSan detector format — the PySecSanOracle parses this to the right CWE and sink. The
    # caller frame (the target line that reached the sink) is printed as a CPython traceback frame so
    # the oracle localises the fix site to the target's own code, not to this guard.
    caller = ""
    for frame, lineno in traceback.walk_stack(sys._getframe().f_back):
        name = frame.f_code.co_filename
        if name.endswith("raksha_sinkguard.py") or name.endswith("raksha_harness.py"):
            continue
        caller = f'  File "{name}", line {lineno}, in {frame.f_code.co_name}\n'
        break
    sys.stderr.write(f"=== BUG DETECTED: PySecSan: {detector} ===\n"
                     f"PySecSan: {detector} detected in {sink}\n"
                     f"Traceback (most recent call last):\n{caller}")
    sys.stderr.flush()
    raise SystemExit(99)                      # non-zero: the harness reports a crash; nothing executed


def install() -> None:
    """Wrap the dangerous sinks in-process. Idempotent."""
    if getattr(install, "_done", False):
        return
    install._done = True  # type: ignore[attr-defined]

    _run, _call, _check, _popen = (subprocess.run, subprocess.call,
                                    subprocess.check_output, subprocess.Popen)

    def _guard_shell(args, kwargs, sink):
        cmd = args[0] if args else kwargs.get("args")
        if kwargs.get("shell") and _looks_injected(cmd if isinstance(cmd, str) else " ".join(cmd or [])):
            _report("command injection", sink, "CWE-78")

    def run(*a, **k):
        _guard_shell(a, k, "subprocess.run"); return _run(*a, **k)

    def call(*a, **k):
        _guard_shell(a, k, "subprocess.call"); return _call(*a, **k)

    def check_output(*a, **k):
        _guard_shell(a, k, "subprocess.check_output"); return _check(*a, **k)

    class Popen(_popen):  # type: ignore[misc,valid-type]
        def __init__(self, *a, **k):
            _guard_shell(a, k, "subprocess.Popen"); super().__init__(*a, **k)

    subprocess.run, subprocess.call, subprocess.check_output, subprocess.Popen = (
        run, call, check_output, Popen)

    _system, _popen_os = os.system, os.popen

    def system(cmd):
        if _looks_injected(cmd):
            _report("command injection", "os.system", "CWE-78")
        return _system(cmd)

    def popen_os(cmd, *a, **k):
        if _looks_injected(cmd):
            _report("command injection", "os.popen", "CWE-78")
        return _popen_os(cmd, *a, **k)

    os.system, os.popen = system, popen_os

    _eval = builtins.eval

    def guard_eval(expr, *a, **k):
        if isinstance(expr, str) and any(t in expr for t in ("__", "import", "os.", "subprocess")):
            _report("code injection", "eval", "CWE-94")
        return _eval(expr, *a, **k)

    builtins.eval = guard_eval  # type: ignore[assignment]
