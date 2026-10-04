"""Go oracle — native `go test -fuzz` and runtime panics.

Go is memory-safe, so its "sanitizer" is the runtime itself: an out-of-bounds index, a nil
dereference, a divide-by-zero or (under -race) a data race panics with a typed message and a stack.
Native `go test -fuzz` is the engine — it writes a failing input to testdata and prints the panic —
so the Go lane needs no mutation fuzzer of its own; this oracle turns that panic into the unified
finding record, localised to the target's own code (runtime / testing / reflect frames skipped).

Format verification status: **VERIFIED** for `panic: runtime error: <kind>` and the tab-indented
`\t<file>.go:<line> +0x..` frames the Go runtime prints, and for the `WARNING: DATA RACE` report.
"""

from __future__ import annotations

import re

from .. import names as _names
from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

_PANIC = re.compile(r"panic:\s*(?:runtime error:\s*)?(?P<msg>.+)")
_RACE = re.compile(r"WARNING: DATA RACE")
_FRAME = re.compile(r"^\s+(?P<file>[^\s:]+\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-fA-F]+)?\s*$")
_FUNC = re.compile(r"^(?P<fn>[\w./\-]+(?:\.[\w.*()]+)+)\(")

#: Go runtime panic text -> CWE. Longest match first, like the other oracles.
_GO_CWE = {
    "index out of range": "CWE-125",
    "slice bounds out of range": "CWE-125",
    "invalid memory address or nil pointer dereference": "CWE-476",
    "integer divide by zero": "CWE-369",
    "makeslice: len out of range": "CWE-789",
    "makeslice: cap out of range": "CWE-789",
    "out of memory": "CWE-789",
    "stack overflow": "CWE-674",
    "close of closed channel": "CWE-362",
    "close of nil channel": "CWE-476",
    "send on closed channel": "CWE-362",
    "assignment to entry in nil map": "CWE-476",
    "data race": "CWE-362",
}

#: Frames that are never the bug's own code.
_NOT_TARGET = ("/src/runtime/", "/src/testing/", "/src/reflect/", "runtime.", "testing.",
               "reflect.", "raksha_fuzz_test.go", _names.GO_FILE)


def _cwe(msg: str) -> str:
    low = msg.lower()
    for key in sorted(_GO_CWE, key=len, reverse=True):
        if key in low:
            return _GO_CWE[key]
    return "CWE-noinfo"


class GoOracle(Oracle):
    name = "go"
    language = "go"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        race = _RACE.search(raw)
        panic = _PANIC.search(raw)
        if not race and not panic:
            return []
        msg = "data race" if race and not panic else panic.group("msg").strip()
        bug_class = _cwe(msg)
        frames = self._frames(raw)
        severity = "high" if bug_class in ("CWE-125", "CWE-787", "CWE-362") else "medium"
        finding = Finding(
            oracle=f"{self.name}:panic", bug_class=bug_class, language=self.language,
            target=target, message=f"Go runtime: {msg}", severity=severity, frames=frames,
            abort_signature=abort_signature(bug_class, frames), raw_excerpt=excerpt(raw))
        seed_fix_site(finding, frames)
        return [finding]

    @staticmethod
    def _frames(raw: str) -> list[Frame]:
        lines = raw.splitlines()
        frames: list[Frame] = []
        for i, line in enumerate(lines):
            m = _FRAME.match(line)
            if not m:
                continue
            uri = m.group("file")
            if any(marker in uri for marker in _NOT_TARGET):
                continue
            fn = ""
            fm = _FUNC.match(lines[i - 1].strip()) if i else None
            if fm:
                fn = fm.group("fn").rsplit("/", 1)[-1]
            frames.append(Frame(symbol=fn or uri.rsplit("/", 1)[-1], uri=uri, line=int(m.group("line"))))
        return frames
