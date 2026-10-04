"""B7 — contract-violation demotion: a direct-call crash on a stated precondition stays SUSPECTED.

A synthesized harness calls an entry point directly, with any bytes. That can break a precondition
the function states and that every real caller honours — `parse(buf)` documented "buf must be
non-empty", called only by code that checks first. The crash is real but is the *harness's* misuse,
not a reachable defect. Reporting it would be a false positive the jury would catch.

The rule is deliberately narrow, so a genuine bug is never hidden by it. A crash is held at
SUSPECTED (never dropped, never reported as verified) only when BOTH hold:

1. **The function states a precondition** — a doc/comment line (`precondition`, `requires`,
   `must be`, `must not`, `caller must`, `@pre`, `# Panics`, `@throws IllegalArgumentException`) or
   an explicit guard at the top of the body (`assert`, `assert!`, `Objects.requireNonNull`,
   `Preconditions.check*`). The matched text is returned as the reason.
2. **No input-facing path reaches it** — no structural source→sink path is in this function, and
   no caller elsewhere in the tree is input-facing (a `main`, a handler/route, or a body that reads
   stdin / argv / a request / a socket / a file). An entry point with *no callers at all* is the
   public API itself, so it counts as input-facing: a library's exported parse() is attack surface.

Text-only and deterministic: the tree is read, nothing is executed. Either condition failing means no
demotion, so the default is always "report what replays".
"""

from __future__ import annotations

import re
from pathlib import Path

_SKIP = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}
_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".py", ".go", ".rs", ".java", ".js", ".ts"}
_MAX = 1_000_000

_PRECONDITION = re.compile(
    r"(precondition|\brequires?\b|\bmust (?:be|not|have|contain)\b|caller must|@pre\b|# Panics|"
    r"@throws\s+IllegalArgumentException|undefined (?:behaviou?r )?if)", re.IGNORECASE)
_GUARD = re.compile(
    r"^\s*(assert\b|assert!\s*\(|debug_assert!\s*\(|Objects\.requireNonNull|Preconditions\.check)",
    re.MULTILINE)
_INPUT_API = re.compile(
    r"(sys\.stdin|sys\.argv|input\(|request\.|\bargv\b|os\.Args|System\.in|getParameter|"
    r"\brecv\(|\bread\(\s*0\b|fread\(|fgets\(|Files\.read|req\.(?:body|query|params)|process\.argv|"
    r"std::env::args|io::stdin|http\.Request|ReadAll\()")
_INPUT_FN = re.compile(r"^(main|handle\w*|\w*handler|serve\w*|route\w*|on_?\w*request)$", re.IGNORECASE)


def _files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return [p for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in _SUFFIXES and p.stat().st_size <= _MAX
            and not any(part in _SKIP for part in p.parts)]


def _def_span(lines: list[str], symbol: str) -> tuple[int, int] | None:
    """(start, end) line indexes of `symbol`'s definition: start at the def line, end at the next
    blank-line-separated top-level def or 60 lines on. Heuristic by design — it only scopes a search."""
    rx = re.compile(rf"(\bdef\s+{re.escape(symbol)}\s*\(|\bfn\s+{re.escape(symbol)}\b|"
                    rf"\bfunc\s+(?:\([^)]*\)\s*)?{re.escape(symbol)}\s*\(|"
                    rf"\b{re.escape(symbol)}\s*\([^;]*\)\s*(?:throws[^{{]*)?\{{?\s*$|"
                    rf"function\s+{re.escape(symbol)}\s*\()")
    for i, line in enumerate(lines):
        if rx.search(line) and not line.strip().endswith(";"):
            return i, min(len(lines), i + 60)
    return None


def stated_precondition(text: str, symbol: str) -> str | None:
    """The precondition the function states (doc comment above, or a guard in its first lines)."""
    lines = text.splitlines()
    span = _def_span(lines, symbol)
    if span is None:
        return None
    start, _ = span
    # the doc/comment block directly above (C/Java/Go/Rust) ...
    above: list[str] = []
    j = start - 1
    while j >= 0 and (lines[j].strip().startswith(("//", "/*", "*", "#", "///", "@")) or not lines[j].strip()):
        if lines[j].strip():
            above.append(lines[j].strip())
        j -= 1
        if len(above) > 30:
            break
    # ... and the Python docstring / first body lines below
    below = lines[start + 1: start + 12]
    for line in reversed(above):
        m = _PRECONDITION.search(line)
        if m:
            return line.lstrip("/*# ").strip()
    doc = "\n".join(below)
    if '"""' in doc or "'''" in doc:
        for line in below:
            if _PRECONDITION.search(line):
                return line.strip().strip('"\'').strip()
            if line.strip().endswith(('"""', "'''")) and line.strip() not in ('"""', "'''"):
                break
    m = _GUARD.search(doc)
    if m:
        return below[doc[: m.start()].count("\n")].strip()
    return None


def _callers(root: Path, symbol: str) -> list[tuple[str, str, str]]:
    """(file, enclosing function name, enclosing body text) for each call of `symbol` outside its def."""
    call = re.compile(rf"(?<![\w.]){re.escape(symbol)}\s*\(|\.{re.escape(symbol)}\s*\(")
    fn_head = re.compile(r"(?:\bdef\s+(\w+)|\bfn\s+(\w+)|\bfunc\s+(?:\([^)]*\)\s*)?(\w+)|"
                         r"function\s+(\w+)|^\s*(?:[\w<>\[\]*&]+\s+)+\**(\w+)\s*\([^;]*$)")
    out: list[tuple[str, str, str]] = []
    for p in _files(root):
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        current, cur_start = "<module>", 0
        for i, line in enumerate(lines):
            h = fn_head.search(line)
            if h:
                current, cur_start = next(g for g in h.groups() if g), i
            if current == symbol:
                continue
            if call.search(line) and not re.search(rf"\b(def|fn|func|function)\s+{re.escape(symbol)}\b", line):
                body = "\n".join(lines[cur_start: i + 1])
                out.append((str(p), current, body))
    return out


def input_facing(root: str | Path, symbol: str, *, structural_functions: set[str] | None = None) -> bool:
    """True when some input-facing path reaches `symbol` (or it has no callers — it IS the API)."""
    if structural_functions and symbol in structural_functions:
        return True
    callers = _callers(Path(root), symbol)
    if not callers:
        return True
    return any(_INPUT_FN.match(fn) or _INPUT_API.search(body) for _, fn, body in callers)


def demotion_reason(root: str | Path, source_file: str | Path, symbol: str, *,
                    structural_functions: set[str] | None = None) -> str | None:
    """Why a direct-call crash on `symbol` should stay SUSPECTED, or None (report as usual)."""
    path = Path(source_file)
    if not path.is_absolute():
        path = Path(root) / path
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    pre = stated_precondition(text, symbol)
    if pre is None:
        return None
    if input_facing(root, symbol, structural_functions=structural_functions):
        return None
    return (f"contract: {symbol} states a precondition ({pre!r}) and no input-facing caller reaches "
            f"it — the crash is the harness breaking the contract, held at SUSPECTED")
