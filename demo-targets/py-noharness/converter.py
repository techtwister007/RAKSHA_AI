"""A unit-conversion helper exposed to operators. No fuzz harness ships with it.

`convert` passes the user's unit string into a shell pipeline (shell=True) — a command injection.
RAKSHA must synthesize a harness, find it, fix it and prove the fix.
"""
import subprocess


def convert(spec: str) -> str:
    # spec like "10 m to ft"; delegated to a units(1)-style helper via the shell. The bug.
    out = subprocess.run("units " + spec, shell=True, capture_output=True, text=True)
    return out.stdout
