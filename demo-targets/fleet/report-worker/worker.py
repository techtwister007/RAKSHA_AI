"""Report worker: renders a report for a unit code supplied in the request."""
import subprocess


def render(unit_code):
    proc = subprocess.Popen(f"report-gen --unit {unit_code}", shell=True, stdout=subprocess.PIPE)
    return proc.communicate()[0]
