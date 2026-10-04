"""The oracle plugin interface.

An oracle's single job: turn one language's bug evidence into the unified finding
record. Everything below this layer is language-agnostic — that is the whole point of
the layer, and the reason adding a language is a day's work rather than a rewrite.

Contract, and it matters:

    An oracle returns findings in SUSPECTED. Never CONFIRMED.

Parsing tool output proves a bug *was observed once*, which is not the same as having a
reproducer that replays. The pipeline attaches the reproducer and replays it; only then
may `confirm()` be called. An oracle that returned CONFIRMED records would quietly
destroy the precision guarantee, so it is simply not the oracle's call to make.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod

from ..finding import RUNTIME_FRAME_PREFIXES, Finding, FixSite, Frame


class Oracle(ABC):
    """Base class for every language's oracle."""

    name: str
    language: str

    @abstractmethod
    def parse(self, raw: str, *, target: str) -> list[Finding]:
        """Turn raw tool output into SUSPECTED findings. Returns [] if nothing fired."""

    def detects(self, raw: str) -> bool:
        """Cheap check for whether this oracle has anything to say about `raw`."""
        return bool(self.parse(raw, target="<probe>"))


def abort_signature(bug_class: str, frames: list[Frame], depth: int = 3) -> str:
    """A stable signature for the abort, used for dedup and for before/after comparison.

    Deliberately ignores addresses, PIDs and build paths — all of which change between
    runs and would make two sightings of one bug look like two bugs. Runtime and fuzzer frames
    are skipped: two command injections in different callers both pass through
    ProcessBuilder.start, and must not share a signature.
    """
    own = [f for f in frames if not f.symbol.startswith(RUNTIME_FRAME_PREFIXES)
           and not _is_tool_frame(f)] or frames
    top = [f.normalised() for f in own[:depth]]
    return hashlib.sha256("|".join([bug_class, *top]).encode()).hexdigest()[:16]


def first_owned_frame(frames: list[Frame], target_root: str | None = None) -> Frame | None:
    """The topmost frame that belongs to the target rather than to a tool or runtime.

    Localisation proper is ripwire's job (crash site -> fix site). This is the cheap
    fallback so a finding always carries at least one candidate location.
    """
    for f in frames:
        if not f.uri:
            continue
        if _is_tool_frame(f):
            continue
        if target_root and target_root not in f.uri:
            continue
        return f
    return next((f for f in frames if f.uri), None)


_TOOL_MARKERS = (
    "/usr/lib/",
    "/usr/include/",
    "compiler-rt",
    "sanitizer_common",
    "libfuzzer",
    "/jazzer/",
    "com/code_intelligence/jazzer",
    "com.code_intelligence.jazzer",
    "atheris",
    "pysecsan",
    "site-packages",
    "__libc_start_main",
)


def _is_tool_frame(frame: Frame) -> bool:
    haystack = f"{frame.uri or ''} {frame.symbol}".lower()
    return any(marker.lower() in haystack for marker in _TOOL_MARKERS)


def seed_fix_site(finding: Finding, frames: list[Frame]) -> None:
    """Attach a cheap fallback candidate location so no finding is unlocalised.

    Real localisation (crash site -> fix site, ranked, in target-owned code) is
    ripwire's job in Phase 2. This guarantees `fix_site_set` is never empty, which the
    repair lanes rely on.
    """
    frame = first_owned_frame(frames)
    if frame and frame.uri:
        finding.add_fix_site(
            FixSite(
                uri=frame.uri,
                rank=0,
                start_line=frame.line,
                symbol=frame.symbol,
                rationale="topmost target-owned frame in the abort trace",
            )
        )


def excerpt(raw: str, limit: int = 1200) -> str:
    """Keep a bounded slice of raw tool output for the evidence bundle."""
    return raw[:limit]
