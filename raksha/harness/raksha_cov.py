"""B4 — real line coverage for the synthesized Python and Node harnesses (stdlib only).

Copied next to the harness in the work dir and run by the gate's coverage command; prints one
`relative/path:line` per executed line of the TARGET's own files (never the harness, never
anything outside the work dir), which is what COVERAGE_HELD reads.

    python3 raksha_cov.py py raksha_harness.py <input>   # sys.settrace over the harness run
    python3 raksha_cov.py v8 <NODE_V8_COVERAGE dir>      # V8 block ranges -> executed lines

Python: a line tracer records (file, line) for frames whose file sits under the cwd; the harness
runs with its own argv; output is flushed even when the sink guard ends the process via os._exit.
Node: V8's block coverage gives byte ranges with execution counts; ranges are painted outer to
inner (inner blocks override), and a line counts as executed when any non-blank character on it
ran. Both are measurements, not heuristics: a line that did not run is not printed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

_EXCLUDE: set[str] = set()   # filled at start: the harness file named on the command line
_SKIP_DIRS = {"node_modules", ".git", "__pycache__"}
_TOKEN = ""   # B8: the per-run token in RAKSHA's own file names; set from the harness name


def _token_of(name: str) -> str:
    stem = Path(name).stem
    return stem.split("_", 1)[1] if stem[:2] in ("h_", "j_") and "_" in stem else ""


def _rel(path: str, cwd: str) -> str | None:
    if not path or path.startswith("<") or not os.path.isfile(path):
        return None                    # <frozen ...>, <string>: not a file of the target
    try:
        ap = os.path.realpath(path)
    except (OSError, ValueError):
        return None
    if not ap.startswith(cwd + os.sep):
        return None
    rel = ap[len(cwd) + 1:]
    parts = rel.split(os.sep)
    if parts[-1] in _EXCLUDE or any(p in _SKIP_DIRS for p in parts) \
            or parts[-1] == os.path.basename(__file__) or (_TOKEN and _TOKEN in parts[-1]):
        return None
    return rel


def _emit(lines: set[tuple[str, int]]) -> None:
    out = "".join(f"{f}:{n}\n" for f, n in sorted(lines))
    os.write(1, out.encode())


def run_python(harness: str, argv: list[str]) -> None:
    import runpy
    import threading
    cwd = os.path.realpath(os.getcwd())
    seen: set[tuple[str, int]] = set()
    cache: dict[str, str | None] = {}

    def tracer(frame, event, arg):
        fn = frame.f_code.co_filename
        rel = cache.get(fn, ...)
        if rel is ...:
            rel = cache[fn] = _rel(fn, cwd)
        if rel is None:
            return None            # do not trace into frames outside the target
        if event in ("line", "call") and frame.f_lineno > 0:
            seen.add((rel, frame.f_lineno))
        return tracer

    real_exit = os._exit

    def flushing_exit(code):        # the sink guard aborts with os._exit: report what ran first
        sys.settrace(None)
        _emit(seen)
        real_exit(code)

    os._exit = flushing_exit
    sys.argv = [harness, *argv]
    sys.path.insert(0, cwd)
    sys.settrace(tracer)
    threading.settrace(tracer)
    devnull = open(os.devnull, "w")
    sys.stdout = devnull
    try:
        runpy.run_path(harness, run_name="__main__")
    except BaseException:  # noqa: BLE001 — a crash is fine; coverage is what ran before it
        pass
    finally:
        sys.settrace(None)
        sys.stdout = sys.__stdout__
    _emit(seen)


def v8_lines(cov_dir: str, cwd: str) -> set[tuple[str, int]]:
    out: set[tuple[str, int]] = set()
    for p in sorted(Path(cov_dir).glob("*.json")):
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        for script in data.get("result", []):
            url = script.get("url", "")
            if not url.startswith("file://"):
                continue
            path = unquote(urlparse(url).path)
            rel = _rel(path, cwd)
            if rel is None:
                continue
            try:
                src = Path(path).read_text(errors="replace")
            except OSError:
                continue
            counts = [0] * len(src)
            ranges = [r for fn in script.get("functions", []) for r in fn.get("ranges", [])]
            ranges.sort(key=lambda r: (r["startOffset"], -r["endOffset"]))
            for r in ranges:
                a, b = max(0, r["startOffset"]), min(len(src), r["endOffset"])
                c = r["count"]
                for i in range(a, b):
                    counts[i] = c
            line, ran = 1, False
            for i, ch in enumerate(src):
                if ch == "\n":
                    if ran:
                        out.add((rel, line))
                    line, ran = line + 1, False
                elif not ch.isspace() and counts[i] > 0:
                    ran = True
            if ran:
                out.add((rel, line))
    return out


def main(argv: list[str]) -> int:
    global _TOKEN
    if len(argv) >= 2 and argv[0] == "py":
        _TOKEN = _token_of(argv[1])
        _EXCLUDE.add(os.path.basename(argv[1]))
        run_python(argv[1], argv[2:])
        return 0
    if len(argv) in (2, 3) and argv[0] == "v8":
        _TOKEN = _token_of(argv[2]) if len(argv) == 3 else ""
        if len(argv) == 3:
            _EXCLUDE.add(os.path.basename(argv[2]))
        _emit(v8_lines(argv[1], os.path.realpath(os.getcwd())))
        return 0
    sys.stderr.write("usage: py <harness> <input> | v8 <dir> [guard]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
