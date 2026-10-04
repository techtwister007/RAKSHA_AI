"""Audit CLI: already passes an argument list, so no shell is involved."""
import subprocess


def export(path: str) -> int:
    return subprocess.run(["audit-export", "--to", path], shell=False).returncode
