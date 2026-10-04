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
            repl = f"{m.group('pre')}__import__('shlex').split({m.group('cmd').strip()})"
            after[i] = lines[i][:m.start()] + repl + lines[i][m.end():]
            changed = True
            break
    if not changed:
        return None
    body = "".join(after)
    return _diff(text, body, rel)


def generic_templates(finding: Finding, root: Path):
    """The template functions worth trying for this finding, in order, as zero-arg closures."""
    cwe = finding.bug_class
    out = []
    if finding.language == "c/c++" and cwe in ("CWE-121", "CWE-122", "CWE-787", "CWE-125", "CWE-787", "CWE-120"):
        out.append(lambda: c_bound_copy(finding, root))
    if finding.language == "python" and cwe in ("CWE-78", "CWE-77"):
        out.append(lambda: py_shell_safe(finding, root))
    return out
