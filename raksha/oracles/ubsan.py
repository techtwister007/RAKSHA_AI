"""UndefinedBehaviorSanitizer and LeakSanitizer oracles — C/C++ native targets.

Two dedicated oracles for the two LLVM sanitizers whose reports are *not* the
``==pid==ERROR: AddressSanitizer: <kind>`` banner the AsanOracle keys on:

* ``UbsanOracle`` reads a UBSan diagnostic line of the shape
  ``<file>:<line>:<col>: runtime error: <message>`` (what ``-fsanitize=undefined``
  prints, with or without a following ``#N`` stack trace) and maps the message to a
  CWE that already lives in ``cwe.py``'s UBSan section.
* ``LeakOracle`` reads a LeakSanitizer ``detected memory leaks`` report — its
  ``Direct leak of N byte(s) ... allocated from:`` block and the allocation stack —
  and maps it to CWE-401 (missing release of memory).

Both follow ``AsanOracle``'s contract exactly: they emit SUSPECTED findings only, obey
the one-claim rule (the *first* diagnostic / the *first* leak becomes the single record,
so a ``-fsanitize-recover`` run that prints several lines, or a report that lists several
leaks, still yields one finding), and drop sanitizer-runtime and libc frames when picking
the fix site so the located frame is target code, not ``malloc`` or ``__ubsan_handle_*``.

Heuristic, stated plainly: the UBSan message-to-kind table is substring matching against
the stable LLVM wording ("signed integer overflow", "shift exponent is ...", "division by
zero", etc.). A wording LLVM changes, or one not in the table, degrades to the generic
"undefined-behaviour" kind (CWE-noinfo) rather than losing the finding.

Format verification status: **VERIFIED** against the LLVM runtime-error line layout and
the LeakSanitizer ``Direct leak``/``allocated from:`` block, both stable across LLVM and
gcc (libubsan / liblsan) versions.

Note: ``AsanOracle`` also recognises a UBSan ``runtime error:`` line and the LeakSanitizer
banner (ASan runs LSan at exit by default). These oracles are the dedicated,
flavour-specific readers; when both are registered in ``ALL_ORACLES`` a UBSan or LSan
report is co-claimed, exactly as a Go data race is co-claimed by ``GoOracle`` and
``TsanOracle``.
"""

from __future__ import annotations

import re

from ..cwe import cwe_for_sanitizer
from ..finding import RUNTIME_FRAME_PREFIXES, Finding, Frame
from .base import Oracle, _is_tool_frame, abort_signature, excerpt, seed_fix_site

# A UBSan diagnostic line. The leading location must be a native source file so a log line
# like "app.py:12:3: runtime error: retrying" is never mistaken for undefined behaviour.
_UBSAN = re.compile(
    r"(?P<uri>[^\s:]+\.(?:c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx|m|mm|cu|rs|ino))"
    r":(?P<line>\d+):(?P<col>\d+):\s*runtime error:\s*(?P<desc>.+)"
)
# LeakSanitizer's banner, standalone (-fsanitize=leak) or at ASan exit.
_LEAK_BANNER = re.compile(r"==\d+==\s*ERROR:\s*LeakSanitizer:\s*detected memory leaks")
# "Direct leak of 128 byte(s) in 1 object(s) allocated from:" (Indirect leaks are consequences).
_LEAK_DIRECT = re.compile(r"(?P<kind>Direct|Indirect) leak of (?P<bytes>\d+) byte\(s\) in (?P<objs>\d+) object")
# A sanitizer-style frame: "#0 0xADDR in symbol file:line:col" (column optional).
_FRAME = re.compile(
    r"^\s*#(?P<depth>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<symbol>[^\s]+)"
    r"(?:\s+(?P<uri>[^\s:]+):(?P<line>\d+)(?::(?P<col>\d+))?)?"
)

#: UBSan message substrings -> the sanitizer kind cwe.py already maps. Longest first so
#: "unsigned integer overflow" is not shadowed by a shorter sibling.
_UBSAN_KIND = {
    "signed integer overflow": "signed-integer-overflow",
    "unsigned integer overflow": "unsigned-integer-overflow",
    "shift exponent": "shift-exponent",
    "division by zero": "division-by-zero",
    "load of null pointer": "null-pointer-dereference",
    "member access within null pointer": "null-pointer-dereference",
    "null pointer": "null-pointer-dereference",
    "out of bounds for type": "index-out-of-bounds",
    "index out of bounds": "index-out-of-bounds",
    "misaligned address": "misaligned-pointer",
    "outside the range of representable values": "float-cast-overflow",
}

CWE_MEMORY_LEAK = "CWE-401"

#: Sanitizer-runtime and libc source markers the shared ``_is_tool_frame`` does not list. The
#: allocation stack's innermost frame is the interceptor (``#0 ... in malloc .../libsanitizer/...``):
#: keeping it would localise a leak to ``malloc`` instead of the caller that forgot to free.
_RUNTIME_URI = ("libsanitizer", "lsan_interceptors", "asan_interceptors", "interception",
                "sysdeps/", "libc-start", "/csu/")


class UbsanOracle(Oracle):
    name = "ubsan"
    language = "c/c++"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        match = _UBSAN.search(raw)              # first diagnostic only: the one-claim rule
        if not match:
            return []
        desc = match.group("desc").strip()
        kind = next(
            (v for k, v in sorted(_UBSAN_KIND.items(), key=lambda kv: len(kv[0]), reverse=True)
             if k in desc.lower()),
            "undefined-behaviour",
        )
        bug_class = cwe_for_sanitizer(kind)
        frames = _frames(raw) or [
            Frame(symbol="<ubsan>", uri=match.group("uri"),
                  line=int(match.group("line")), column=int(match.group("col")))
        ]
        finding = Finding(
            oracle=f"{self.name}:UndefinedBehaviorSanitizer",
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=f"UndefinedBehaviorSanitizer: {desc}",
            severity="medium",
            frames=frames,
            abort_signature=abort_signature(bug_class, frames),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(finding, frames)
        return [finding]


class LeakOracle(Oracle):
    name = "lsan"
    language = "c/c++"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        if not _LEAK_BANNER.search(raw):
            return []
        direct = _LEAK_DIRECT.search(raw)       # first leak only: the one-claim rule
        leaked = direct.group("bytes") if direct else None
        # The allocation stack follows the "allocated from:" line; take the frames after the
        # first leak header so the fix site is the allocation site, not an unrelated frame.
        body = raw[direct.end():] if direct else raw
        frames = _frames(body)
        detail = f"detected memory leaks ({leaked} byte(s))" if leaked else "detected memory leaks"
        finding = Finding(
            oracle=f"{self.name}:LeakSanitizer",
            bug_class=CWE_MEMORY_LEAK,
            language=self.language,
            target=target,
            message=f"LeakSanitizer: {detail}",
            severity="medium",
            frames=frames,
            abort_signature=abort_signature(CWE_MEMORY_LEAK, frames),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(finding, frames)
        return [finding]


def _frames(raw: str) -> list[Frame]:
    """Sanitizer-style frames, dropping the sanitizer runtime and libc interceptor frames.

    ``malloc``/``__ubsan_handle_*``/``__interceptor_*`` and the libsanitizer sources are the
    tool's own frames: keeping them would localise a leak to ``malloc`` instead of the caller
    that forgot to free, so they are filtered the same way ``base._is_tool_frame`` filters
    everywhere else in the pipeline.
    """
    frames: list[Frame] = []
    for line in raw.splitlines():
        m = _FRAME.match(line)
        if not m:
            continue
        frame = Frame(
            symbol=m.group("symbol"),
            uri=m.group("uri"),
            line=int(m.group("line")) if m.group("line") else None,
            column=int(m.group("col")) if m.group("col") else None,
        )
        if _is_runtime_frame(frame):
            continue
        frames.append(frame)
    return frames


def _is_runtime_frame(frame: Frame) -> bool:
    """A sanitizer-runtime, allocator-interceptor or libc-start frame — never the bug's code."""
    if _is_tool_frame(frame):
        return True
    if frame.symbol.startswith(RUNTIME_FRAME_PREFIXES):
        return True
    uri = (frame.uri or "").lower()
    # the allocator interceptor (#0 malloc) lives in the sanitizer runtime, caught by uri; a target
    # function merely named `malloc` in real source is left alone.
    return any(mk in uri for mk in _RUNTIME_URI)
