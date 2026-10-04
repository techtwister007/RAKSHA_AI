"""Rust oracle — runtime panics from `cargo test` (stable, no cargo-fuzz / nightly).

Rust is memory-safe in safe code, so — like Go — its "sanitizer" is the runtime itself: an
out-of-bounds slice/index, an arithmetic overflow (under `overflow-checks`), a divide-by-zero or an
`unwrap()` on `None`/`Err` all abort the thread with a typed `panicked at ...` message and (when a
backtrace is printed) a stack. The Rust deep lane synthesizes a `cargo test` harness that calls the
entry point, finds a panicking input by mutation, and this oracle turns the panic into the unified
finding record, localised to the crate's own code (std / core / rustc / the synthesized harness
frames skipped).

Both panic-message layouts are handled:

    * old (pre-1.65):  ``thread 'main' panicked at 'MSG', src/lib.rs:12:9``
    * new (1.65+):     ``thread 'main' (TID) panicked at src/lib.rs:12:9:\nMSG``

Format verification status: **VERIFIED** against rustc 1.97 (`thread '<name>' (<tid>) panicked at
<file>:<line>:<col>:` with the message on the following line, and the ``   N: sym`` / ``   at
<file>.rs:<line>:<col>`` backtrace frames libtest prints). The older single-line form is matched by
a second pattern so output captured from earlier toolchains still parses.
"""

from __future__ import annotations

import re

from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

# New form: location on the `panicked at` line, message on the next line. The thread-id `(NNN)` is
# optional (added in newer libtest). The file is lazy up to the `:line:col:` suffix.
_PANIC_NEW = re.compile(
    r"panicked at\s+(?P<file>[^\s][^\n]*?):(?P<line>\d+):(?P<col>\d+):\s*\n\s*(?P<msg>[^\n]+)")
# Old form: message quoted inline, then the location.
_PANIC_OLD = re.compile(
    r"panicked at\s+'(?P<msg>.*?)',\s+(?P<file>[^\s][^\n]*?):(?P<line>\d+):(?P<col>\d+)")

# Backtrace frames libtest prints: `   5: symbol` then `             at ./path.rs:line:col`.
_BT_SYM = re.compile(r"^\s*\d+:\s+(?P<sym>\S.*)$")
_BT_AT = re.compile(r"^\s*at\s+(?P<file>\S.*?\.rs):(?P<line>\d+)(?::(?P<col>\d+))?\s*$")

#: Frames that are never the crate's own code (std/core/alloc, the compiler's sysroot, the
#: synthesized harness, and anything under a cargo registry checkout).
_NOT_TARGET = ("/rustc/", "/library/", "library/std", "library/core", "library/alloc",
               "raksha_fuzz.rs", "/.cargo/", "/registry/")

#: Rust panic text -> CWE. Longest / most specific key first (resolved by sorting on length), like
#: the other oracles. A slice/index range panic is an out-of-bounds *read* of the backing buffer
#: (CWE-125); safe Rust cannot turn it into an out-of-bounds write, so CWE-787 is reserved for the
#: rare report that names a write.
_RUST_CWE = {
    "range end index": "CWE-125",
    "range start index": "CWE-125",
    "out of range for slice": "CWE-125",
    "index out of bounds": "CWE-125",
    "slice index starts at": "CWE-125",
    "slice index": "CWE-125",
    "attempt to add with overflow": "CWE-190",
    "attempt to subtract with overflow": "CWE-190",
    "attempt to multiply with overflow": "CWE-190",
    "attempt to negate with overflow": "CWE-190",
    "attempt to shift left with overflow": "CWE-190",
    "attempt to shift right with overflow": "CWE-190",
    "attempt to compute the remainder with overflow": "CWE-190",
    "with overflow": "CWE-190",
    "attempt to divide by zero": "CWE-369",
    "divide by zero": "CWE-369",
    "attempt to calculate the remainder with a divisor of zero": "CWE-369",
    "called `option::unwrap()` on a `none`": "CWE-476",
    "called `result::unwrap()` on an `err`": "CWE-476",
    "called `result::expect()`": "CWE-476",
    "called `option::expect()`": "CWE-476",
    "unwrap()` on a `none": "CWE-476",
    "unwrap()` on an `err": "CWE-476",
    "unwrap() on": "CWE-476",
}

#: CWEs whose panic is a memory-unsafety class rather than a logic abort — reported high.
_HIGH = ("CWE-125", "CWE-787")


def _cwe(msg: str) -> str:
    low = msg.lower()
    for key in sorted(_RUST_CWE, key=len, reverse=True):
        if key in low:
            return _RUST_CWE[key]
    return "CWE-noinfo"


def _norm(path: str) -> str:
    """Drop a leading `./` so a backtrace path (`./src/lib.rs`) and a panic-line path (`src/lib.rs`)
    name the same file relative to the crate root."""
    return path[2:] if path.startswith("./") else path


class RustPanicOracle(Oracle):
    name = "rust-panic"
    language = "rust"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        m = _PANIC_NEW.search(raw) or _PANIC_OLD.search(raw)
        if not m:
            return []
        msg = m.group("msg").strip()
        pfile = _norm(m.group("file"))
        pline, pcol = int(m.group("line")), int(m.group("col"))
        bug_class = _cwe(msg)
        frames = self._frames(raw, pfile, pline, pcol)
        severity = "high" if bug_class in _HIGH else "medium"
        finding = Finding(
            oracle="rust:panic", bug_class=bug_class, language=self.language,
            target=target, message=f"Rust panic: {msg}", severity=severity, frames=frames,
            abort_signature=abort_signature(bug_class, frames), raw_excerpt=excerpt(raw))
        seed_fix_site(finding, frames)
        return [finding]

    @staticmethod
    def _frames(raw: str, pfile: str, pline: int, pcol: int) -> list[Frame]:
        """The crash site (the `panicked at` location) first, then any target-owned backtrace
        frames. std/core/rustc/harness frames are dropped so the finding's identity and fix site are
        the crate's own code, never the runtime or the synthesized test."""
        bt = RustPanicOracle._backtrace_frames(raw)
        base = pfile.rsplit("/", 1)[-1]
        sym = next((s for (s, f, l, _c) in bt
                    if l == pline and f.rsplit("/", 1)[-1] == base), None)
        frames = [Frame(symbol=sym or base, uri=pfile, line=pline, column=pcol)]
        for (s, f, l, c) in bt:
            if (_norm(f), l) == (pfile, pline):
                continue                      # already represented by the crash-site frame
            frames.append(Frame(symbol=s, uri=_norm(f), line=l, column=c))
        return frames

    @staticmethod
    def _backtrace_frames(raw: str) -> list[tuple[str, str, int, int | None]]:
        lines = raw.splitlines()
        out: list[tuple[str, str, int, int | None]] = []
        for i, line in enumerate(lines):
            ms = _BT_SYM.match(line)
            if not ms or i + 1 >= len(lines):
                continue
            mat = _BT_AT.match(lines[i + 1])
            if not mat:
                continue
            uri = mat.group("file")
            if any(marker in uri for marker in _NOT_TARGET):
                continue
            col = int(mat.group("col")) if mat.group("col") else None
            out.append((ms.group("sym").strip(), uri, int(mat.group("line")), col))
        return out
