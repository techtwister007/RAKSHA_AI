"""Generic, bug-class-keyed repair templates — the zero-inference floor of the repair ladder.

A template here is not a per-target hand-fix; it is the standard safe rewrite for a class of bug,
applied at the fix site the oracle localised. It produces a real unified diff (via difflib, so the
hunk line numbers always match) and NOTHING here decides the fix is correct — the five-check gate
does. A template that does not apply, or whose fix the gate rejects, simply yields the next lane.

These cover the autofuzz demo shapes offline (no model): an unbounded C copy into a fixed buffer,
and a Python shell/eval sink reached with input. The model lane (repair.py) generalises beyond them
when an endpoint is configured; these are the floor that always runs.
"""

from __future__ import annotations

import base64
import difflib
import re
from pathlib import Path

from .finding import Finding


def _diff(before: str, after: str, path: str) -> str | None:
    if before == after:
        return None
    return "".join(difflib.unified_diff(before.splitlines(keepends=True),
                                        after.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def _read_fix_site(finding: Finding, root: Path) -> tuple[str, str] | None:
    """(relative path, source text) for the finding's fix site, or None if unreadable."""
    if not finding.fix_site_set:
        return None
    rel = finding.fix_site_set[0].uri
    p = (root / rel)
    if not p.is_file():
        # the oracle path may be relative to a subdir; try to find it by basename under root
        matches = [q for q in root.rglob(Path(rel).name) if q.is_file()]
        if not matches:
            return None
        p, rel = matches[0], str(matches[0].relative_to(root))
    try:
        return rel, p.read_text()
    except OSError:
        return None


# ---- C / C++: bound an unchecked copy into a fixed-size buffer ---------------------------------

_C_COPY = re.compile(r"\b(memcpy|memmove)\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*(?P<src>[^,]+?)\s*,\s*(?P<n>[^;]+?)\)\s*;")
_C_STRCPY = re.compile(r"\bstrcpy\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*(?P<src>[^)]+?)\)\s*;")


def c_bound_copy(finding: Finding, root: Path) -> str | None:
    """Clamp a memcpy/strcpy at the fix site to the destination buffer's own size.

    `memcpy(dst, src, n)` -> `memcpy(dst, src, (n) < sizeof(dst) ? (n) : sizeof(dst))`. When dst is a
    fixed-size array this is provably safe; when it is a pointer `sizeof` is wrong and the gate's
    differential / coverage checks reject the candidate — so proposing it is safe, accepting it is
    the gate's call.
    """
    got = _read_fix_site(finding, root)
    if got is None:
        return None
    rel, text = got
    lines = text.splitlines(keepends=True)
    idx = (finding.fix_site_set[0].start_line or 1) - 1
    window = range(max(0, idx - 2), min(len(lines), idx + 3))   # the oracle line, give or take
    after = list(lines)
    changed = False
    for i in window:
        line = lines[i]
        m = _C_COPY.search(line)
        if m:
            n, dst = m.group("n").strip(), m.group("dst")
            bounded = (f"{m.group(1)}({dst}, {m.group('src').strip()}, "
                       f"({n}) < sizeof({dst}) ? ({n}) : sizeof({dst}));")
            after[i] = line[:m.start()] + bounded + line[m.end():]
            changed = True
            break
        ms = _C_STRCPY.search(line)
        if ms:
            dst, src = ms.group("dst"), ms.group("src").strip()
            bounded = f"strncpy({dst}, {src}, sizeof({dst}) - 1); {dst}[sizeof({dst}) - 1] = 0;"
            after[i] = line[:ms.start()] + bounded + line[ms.end():]
            changed = True
            break
    return _diff(text, "".join(after), rel) if changed else None


# ---- Python: make a shell / eval sink safe ----------------------------------------------------

_PY_SHELL = re.compile(r"(?P<pre>subprocess\.(?:run|call|check_output|Popen)\s*\(\s*)(?P<cmd>[^,]+?)\s*,\s*shell\s*=\s*True")


def py_shell_safe(finding: Finding, root: Path) -> str | None:
    """Turn `subprocess.run(cmd, shell=True)` at the fix site into a no-shell argv split.

    `shell=True` with a built string is the injection; splitting the command with shlex and dropping
    the shell removes the metacharacter channel while preserving the intended argv.
    """
    got = _read_fix_site(finding, root)
    if got is None:
        return None
    rel, text = got
    lines = text.splitlines(keepends=True)
    idx = (finding.fix_site_set[0].start_line or 1) - 1
    after = list(lines)
    changed = False
    for i in range(max(0, idx - 2), min(len(lines), idx + 3)):
        m = _PY_SHELL.search(lines[i])
        if m:
            repl = f"{m.group('pre')}shlex.split({m.group('cmd').strip()})"
            after[i] = lines[i][:m.start()] + repl + lines[i][m.end():]
            changed = True
            break
    if not changed:
        return None
    if not re.search(r"^\s*import shlex\b", text, re.M):
        after.insert(_import_insertion_point(after), "import shlex\n")
    body = "".join(after)
    return _diff(text, body, rel)


def _import_insertion_point(lines: list[str]) -> int:
    """After the last top-level import (or the module docstring / shebang when there is none)."""
    last = -1
    for i, ln in enumerate(lines):
        if re.match(r"^(import|from)\s+\w", ln):
            last = i
    if last >= 0:
        return last + 1
    i = 0
    if lines and lines[0].startswith("#!"):
        i = 1
    if i < len(lines) and lines[i].lstrip().startswith(('"""', "\'\'\'")):
        q = lines[i].lstrip()[:3]
        if lines[i].rstrip().endswith(q) and len(lines[i].strip()) > 3:
            return i + 1
        for j in range(i + 1, len(lines)):
            if q in lines[j]:
                return j + 1
    return i


# ---- Go: bound a slice / index to the backing length --------------------------------------------

_GO_SLICE = re.compile(r"(?P<arr>[A-Za-z_]\w*)\[\s*(?P<lo>[^\]:]*?):\s*(?P<hi>[^\]]+?)\s*\]")


def go_bound_slice(finding: Finding, root: Path) -> str | None:
    """Clamp a slice high bound to the backing array's length: `a[lo:hi]` -> `a[lo:min(hi, len(a))]`.

    Go 1.21+ has a builtin `min`. A slice-bounds panic is an unchecked high index; clamping it to
    len removes the panic while preserving behaviour for in-range inputs — the gate confirms that.
    """
    got = _read_fix_site(finding, root)
    if got is None:
        return None
    rel, text = got
    lines = text.splitlines(keepends=True)
    idx = (finding.fix_site_set[0].start_line or 1) - 1
    after = list(lines)
    changed = False
    for i in range(max(0, idx - 2), min(len(lines), idx + 3)):
        m = _GO_SLICE.search(lines[i])
        if not m:
            continue
        arr, lo, hi = m.group("arr"), m.group("lo").strip(), m.group("hi").strip()
        if f"len({arr})" in hi or "min(" in hi:
            continue                              # already bounded
        bounded = f"{arr}[{lo}:min({hi}, len({arr}))]"
        after[i] = lines[i][:m.start()] + bounded + lines[i][m.end():]
        changed = True
        break
    return _diff(text, "".join(after), rel) if changed else None


def generic_templates(finding: Finding, root: Path):
    """The template functions worth trying for this finding, in order, as zero-arg closures."""
    cwe = finding.bug_class
    out = []
    if finding.language == "c/c++" and cwe in ("CWE-121", "CWE-122", "CWE-787", "CWE-125", "CWE-787", "CWE-120"):
        out.append(lambda: c_bound_copy(finding, root))
    if finding.language == "python" and cwe in ("CWE-78", "CWE-77"):
        out.append(lambda: py_shell_safe(finding, root))
    if finding.language == "go" and cwe in ("CWE-125", "CWE-787", "CWE-129"):
        out.append(lambda: go_bound_slice(finding, root))
    return out


# ---- deterministic regression tests (zero inference) -------------------------------------------
# A regression test the TEMPLATE lane can offer, so "fail-before / pass-after" is available offline
# with no model. The gate verifies it exactly like a model-written one (verify_regression_test), so
# a generated test that does NOT exercise the bug is rejected and never shipped — the generator
# earns nothing by itself. The test SOURCE is run by the target's `added_test_cmd`; for the
# synthesized autofuzz targets that is `sh {test}` (C) or `python3 {test}` (Python).

_C_REGRESSION_CLASSES = ("CWE-121", "CWE-122", "CWE-787", "CWE-125", "CWE-120")
_PY_REGRESSION_CLASSES = ("CWE-78", "CWE-77")


def _c_overflow_regression(reproducer: bytes) -> str:
    """A shell test: feed the reproducer to the synthesized harness and assert NO sanitizer abort.

    Fails on the vulnerable build (the harness aborts under ASan, non-zero exit); passes on the
    patched build (the harness exits clean). Reproducer bytes travel base64-encoded so arbitrary
    binary input survives the shell.
    """
    b64 = base64.b64encode(reproducer).decode("ascii")
    return (
        "#!/bin/sh\n"
        "# RAKSHA generated regression test (C overflow): the reproducer must not abort.\n"
        f"printf '%s' '{b64}' | base64 -d > .raksha_regress_in 2>/dev/null\n"
        "./raksha_harness .raksha_regress_in > .raksha_regress_out 2>&1\n"
        "rc=$?\n"
        'if [ "$rc" -ne 0 ]; then echo "REGRESS-FAIL: harness aborted (rc=$rc)"; exit 1; fi\n'
        "if grep -Eq 'AddressSanitizer|ERROR: |runtime error:|SUMMARY: ' .raksha_regress_out; then "
        'echo "REGRESS-FAIL: sanitizer reported an abort"; exit 1; fi\n'
        'echo "REGRESS-PASS: reproducer no longer aborts"; exit 0\n'
    )


def _py_injection_regression() -> str:
    """A Python test: drive the harness with a shell-metacharacter payload and assert the injected
    command never runs (no marker file appears) and the sink guard did not fire.

    Fails on the vulnerable build (the metacharacter reaches `shell=True`, the guard aborts
    non-zero); passes on the patched build (no-shell argv — the metacharacter is inert)."""
    return (
        "# RAKSHA generated regression test (Python shell injection): the sink must stay unreached.\n"
        "import os, subprocess, sys\n"
        "marker = '.raksha_injection_marker'\n"
        "try:\n"
        "    os.remove(marker)\n"
        "except OSError:\n"
        "    pass\n"
        "payload = b'x; touch ' + marker.encode()\n"
        "with open('.raksha_regress_in', 'wb') as fh:\n"
        "    fh.write(payload)\n"
        "proc = subprocess.run(['python3', 'raksha_harness.py', '.raksha_regress_in'],\n"
        "                      capture_output=True)\n"
        "fired = os.path.exists(marker) or b'PySecSan' in proc.stderr or proc.returncode != 0\n"
        "try:\n"
        "    os.remove(marker)\n"
        "except OSError:\n"
        "    pass\n"
        "sys.exit(1 if fired else 0)\n"
    )


def template_regression_test(finding: Finding, reproducer: bytes | None) -> str | None:
    """A deterministic regression test for the covered bug classes, or None. Zero inference."""
    cwe = finding.bug_class
    if finding.language == "c/c++" and cwe in _C_REGRESSION_CLASSES and reproducer is not None:
        return _c_overflow_regression(reproducer)
    if finding.language == "python" and cwe in _PY_REGRESSION_CLASSES:
        return _py_injection_regression()
    return None
