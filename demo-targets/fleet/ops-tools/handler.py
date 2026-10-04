"""Ops helper: runs a diagnostic command named by the operator."""
import subprocess


def run_diagnostic(name: str) -> str:
    return subprocess.run("diag --check " + name, shell=True, capture_output=True, text=True).stdout
