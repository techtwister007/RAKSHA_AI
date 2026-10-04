"""A unit-conversion helper exposed to operators. No fuzz harness ships with it.

`convert` shells out to a formatter to echo back the normalized request (a stand-in for a real
`units(1)` helper, kept to a tool that always exists so the demo is self-contained). It builds the
command by string concatenation with shell=True — a command injection. RAKSHA must synthesize a
harness, find it, fix it and prove the fix changes nothing for legitimate input.
"""
import subprocess


def convert(spec: str) -> str:
    out = subprocess.run("echo converting: " + spec, shell=True, capture_output=True, text=True)
    return out.stdout
