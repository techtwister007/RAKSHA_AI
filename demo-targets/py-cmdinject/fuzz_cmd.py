"""Replay/replay-detect driver for the Python command-injection sink.

Like the Java slice, detection is honest and offline: it wraps subprocess so a shell=True call with
shell metacharacters in the input is RECORDED and refused (never actually executed), then runs the
real handler. On the vulnerable build the tainted input reaches shell=True -> recorded; on the fixed
build (shell=False arg list) it does not. A recorded sink is reported in PySecSan's format, which
RAKSHA's PySecSanOracle parses to CWE-78. Usage: fuzz_cmd.py <input-file> [--coverage]
"""

import subprocess
import sys

_META = set(";|&`$><\n")
_recorded = {"hit": False}

_real_run = subprocess.run


def _guarded_run(cmd, *args, **kwargs):
    if kwargs.get("shell") and isinstance(cmd, str) and any(c in _META for c in cmd):
        _recorded["hit"] = True
        _recorded["cmd"] = cmd
        raise RuntimeError("shell execution blocked by RAKSHA replay sandbox")
    # benign or shell=False: run it for real (safe), so normal behaviour is observable
    return _real_run(cmd, *args, **kwargs)


def main():
    if len(sys.argv) < 2:
        print("usage: fuzz_cmd.py <input-file> [--coverage]", file=sys.stderr)
        sys.exit(2)
    coverage = len(sys.argv) > 2 and sys.argv[2] == "--coverage"
    data = open(sys.argv[1], "r", errors="replace").read()

    subprocess.run = _guarded_run          # install the seam
    sys.path.insert(0, ".")
    from app.runner import run_user_command
    try:
        out = run_user_command(data)
    except RuntimeError:
        out = None
    finally:
        subprocess.run = _real_run

    if coverage:
        print("app/runner.py:13")          # reached the sink call
        return
    if _recorded["hit"]:
        print("=== Uncaught Python exception: ===")
        print("PySecSan: command injection detected in subprocess.run -- tainted input reached a shell=True sink")
        print('  File "app/runner.py", line 13, in run_user_command')
        print("    subprocess.run(cmd, shell=True, capture_output=True, text=True)")
        sys.exit(77)
    print("ok", out)


if __name__ == "__main__":
    main()
