"""ASan / UBSan / MSan oracle — C/C++ and other native targets.

Format verification status: **VERIFIED**. The LLVM sanitizer report layout
(`==pid==ERROR: AddressSanitizer: <kind>`, `#N 0xaddr in symbol file:line:col`,
`SUMMARY: ...`) is stable across LLVM versions and is what AFL++/libFuzzer surface.
"""

from __future__ import annotations

import re

from ..cwe import cwe_for_sanitizer
from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

_ERROR = re.compile(
    r"==\d+==\s*ERROR:\s*(?P<tool>AddressSanitizer|MemorySanitizer|LeakSanitizer"
    r"|ThreadSanitizer|UndefinedBehaviorSanitizer):\s*(?P<kind>[\w\-]+)"
)
# UBSan reports inline rather than with a ==pid==ERROR banner.
_UBSAN = re.compile(
    r"(?P<uri>[^\s:]+):(?P<line>\d+):(?P<col>\d+):\s*runtime error:\s*(?P<desc>.+)"
)
_FRAME = re.compile(
    r"^\s*#(?P<depth>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<symbol>[^\s]+)"
    r"(?:\s+(?P<uri>[^\s:]+):(?P<line>\d+)(?::(?P<col>\d+))?)?"
)
_SUMMARY = re.compile(r"SUMMARY:\s*\w+:\s*(?P<kind>[\w\-]+)")

# Kinds where the abort is a dangerous *write* or lifetime error — treat as high.
_HIGH_SEVERITY = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "double-free",
    "use-after-poison",
}

_UBSAN_KIND = {
    "signed integer overflow": "signed-integer-overflow",
    "shift exponent": "shift-exponent",
    "division by zero": "division-by-zero",
    "null pointer": "null-pointer-dereference",
    "load of null pointer": "null-pointer-dereference",
}


class AsanOracle(Oracle):
    name = "asan"
    language = "c/c++"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        match = _ERROR.search(raw)
        if match:
            return self._parse_sanitizer_report(raw, match, target=target)
        ub = _UBSAN.search(raw)
        if ub:
            return self._parse_ubsan(raw, ub, target=target)
        return []

    # ------------------------------------------------------------------

    def _parse_sanitizer_report(self, raw: str, match: re.Match[str], *, target: str) -> list[Finding]:
        kind = match.group("kind")
        tool = match.group("tool")
        frames = self._frames(raw)

        # The SUMMARY line is more specific than the banner for some kinds, so resolve the kind
        # FIRST, then derive bug class and severity from the resolved kind — otherwise a banner
        # that reads generic/medium but summarises to a high-severity write/lifetime kind would
        # keep the wrong severity and emit SARIF level="warning" for a dangerous bug.
        summary = _SUMMARY.search(raw)
        if summary and summary.group("kind") != kind:
            kind = summary.group("kind")
        bug_class = cwe_for_sanitizer(kind)
        severity = "high" if kind in _HIGH_SEVERITY else "medium"

        finding = Finding(
            oracle=f"{self.name}:{tool}",
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=f"{tool}: {kind}",
            severity=severity,
            frames=frames,
            abort_signature=abort_signature(bug_class, frames),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(finding, frames)
        return [finding]

    def _parse_ubsan(self, raw: str, match: re.Match[str], *, target: str) -> list[Finding]:
        desc = match.group("desc").strip()
        kind = next(
            (v for k, v in _UBSAN_KIND.items() if k in desc.lower()),
            "undefined-behaviour",
        )
        frames = self._frames(raw) or [
            Frame(
                symbol="<ubsan>",
                uri=match.group("uri"),
                line=int(match.group("line")),
                column=int(match.group("col")),
            )
        ]
        bug_class = cwe_for_sanitizer(kind)
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

    @staticmethod
    def _frames(raw: str) -> list[Frame]:
        frames: list[Frame] = []
        for line in raw.splitlines():
            m = _FRAME.match(line)
            if not m:
                continue
            frames.append(
                Frame(
                    symbol=m.group("symbol"),
                    uri=m.group("uri"),
                    line=int(m.group("line")) if m.group("line") else None,
                    column=int(m.group("col")) if m.group("col") else None,
                )
            )
        return frames
