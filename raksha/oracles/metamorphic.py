"""Metamorphic oracle — a violated invariant between two related inputs, not a crash.

Most oracles need the program to *misbehave observably* (crash, abort at a sink, hang). A
metamorphic oracle needs neither: it derives a second input from a first by a transformation
that *should not change the answer*, runs both, and reports a finding when the two answers
disagree. The evidence is the pair of inputs, carried in the reproducer, and replaying the
pair re-demonstrates the disagreement.

The shipped relation library, keyed by what the entry point is:

* ``PaddingInvariance`` — ``f(x) == f(x + trailing_padding)`` for a parser that should ignore
  harmless trailing bytes. A parser that treats padded and unpadded input differently is
  improper input handling, CWE-20.
* ``RoundTrip`` — ``decode(encode(x)) == x`` when both exist. CWE-noinfo (the class depends on
  what the mismatch corrupts).
* ``Idempotence`` — ``normalize(normalize(x)) == normalize(x)``. CWE-noinfo.

``check_relations(run_one, seed_corpus, relations) -> Finding | None`` runs each relation
against each seed input in order and returns a finding for the first violation, or ``None`` if
every relation holds on the whole corpus. ``MetamorphicOracle`` is the plugin wrapper; it
claims only the ``=== RAKSHA METAMORPHIC ===`` signal text, so it never fires on another
oracle's output.

Heuristic, stated plainly: a relation only proves a defect if the invariant genuinely must
hold for a correct program. The library ships relations that are true by construction for the
entry-point kind they are keyed to; choosing an inappropriate relation is a caller error, not
something this module can detect.
"""

from __future__ import annotations

import re
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Iterable

from ..finding import DETERMINISTIC_MATCH, Finding, Frame, Reproducer
from .base import Oracle, abort_signature, excerpt, seed_fix_site

CWE_IMPROPER_INPUT = "CWE-20"
CWE_NOINFO = "CWE-noinfo"


def _as_bytes(value: object) -> bytes:
    """Coerce an input or output to bytes for the carried pair (bytes pass through)."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    return repr(value).encode("utf-8", "surrogatepass")


@dataclass(frozen=True)
class Violation:
    """A failed relation: the relation's name and class, and the pair that disagreed."""

    relation: str
    cwe: str
    input_a: bytes
    input_b: bytes
    detail: str


class Relation(ABC):
    """A metamorphic relation: derive a second input, and compare the two answers."""

    name: str
    cwe: str

    @abstractmethod
    def check(self, run_one: Callable[[object], object], x: object) -> Violation | None:
        """Return a ``Violation`` if the relation fails on ``x``, else ``None``."""


class PaddingInvariance(Relation):
    """``f(x) == f(x + trailing_padding)`` — trailing padding must not change the parse."""

    name = "padding-invariance"

    def __init__(self, padding: bytes = b"\n", cwe: str = CWE_IMPROPER_INPUT) -> None:
        self.padding = padding
        self.cwe = cwe

    def check(self, run_one: Callable[[object], object], x: object) -> Violation | None:
        if not isinstance(x, (bytes, bytearray)):   # relation applies to byte inputs only
            return None
        a = bytes(x)
        b = a + self.padding
        out_a, out_b = run_one(a), run_one(b)
        if out_a != out_b:
            return Violation(self.name, self.cwe, _as_bytes(a), _as_bytes(b),
                             f"f(x)={out_a!r} != f(x+{self.padding!r})={out_b!r}")
        return None


class RoundTrip(Relation):
    """``decode(encode(x)) == x`` — an encode/decode pair must be lossless."""

    name = "round-trip"

    def __init__(self, encode: Callable[[object], object], decode: Callable[[object], object],
                 cwe: str = CWE_NOINFO) -> None:
        self.encode = encode
        self.decode = decode
        self.cwe = cwe

    def check(self, run_one: Callable[[object], object], x: object) -> Violation | None:
        encoded = self.encode(x)
        decoded = self.decode(encoded)
        if decoded != x:
            return Violation(self.name, self.cwe, _as_bytes(x), _as_bytes(encoded),
                             f"decode(encode(x))={decoded!r} != x={x!r}")
        return None


class Idempotence(Relation):
    """``normalize(normalize(x)) == normalize(x)`` — a second pass must change nothing."""

    name = "idempotence"

    def __init__(self, normalize: Callable[[object], object] | None = None,
                 cwe: str = CWE_NOINFO) -> None:
        self.normalize = normalize
        self.cwe = cwe

    def check(self, run_one: Callable[[object], object], x: object) -> Violation | None:
        fn = self.normalize or run_one
        once = fn(x)
        twice = fn(once)
        if twice != once:
            return Violation(self.name, self.cwe, _as_bytes(x), _as_bytes(once),
                             f"normalize(normalize(x))={twice!r} != normalize(x)={once!r}")
        return None


# ---- carried pair --------------------------------------------------------------------------


def encode_pair(a: bytes, b: bytes) -> bytes:
    """Length-prefix the two inputs into one blob carried as the reproducer's bytes."""
    return struct.pack(">I", len(a)) + a + struct.pack(">I", len(b)) + b


def decode_pair(blob: bytes) -> tuple[bytes, bytes]:
    """Recover ``(input_a, input_b)`` from an ``encode_pair`` blob."""
    (la,) = struct.unpack(">I", blob[:4])
    a = blob[4:4 + la]
    off = 4 + la
    (lb,) = struct.unpack(">I", blob[off:off + 4])
    b = blob[off + 4:off + 4 + lb]
    return a, b


def pair_from_finding(finding: Finding) -> tuple[bytes, bytes] | None:
    """The ``(input_a, input_b)`` pair a metamorphic finding carries, or ``None``."""
    repro = finding.reproducer
    if repro is None or repro.data is None:
        return None
    return decode_pair(repro.data)


def _finding_for(violation: Violation, *, target: str, language: str,
                 entry_point: Frame | None) -> Finding:
    frames = [entry_point] if entry_point else []
    pair = encode_pair(violation.input_a, violation.input_b)
    finding = Finding(
        oracle=f"metamorphic:{violation.relation}",
        bug_class=violation.cwe,
        language=language,
        target=target,
        message=f"metamorphic: {violation.relation} violated — {violation.detail}",
        severity="medium",
        frames=frames,
        abort_signature=abort_signature(f"{violation.cwe}:{violation.relation}", frames),
        raw_excerpt=excerpt(violation.detail),
    )
    # The evidence is the input PAIR: both are carried in the reproducer so replaying it
    # re-runs the two related inputs and re-shows the disagreement. A metamorphic re-check is
    # deterministic, so the reproducer is a deterministic match, not a crash replay.
    finding.attach_reproducer(Reproducer.from_bytes(
        pair, ["raksha-metamorphic-replay", violation.relation],
        kind=DETERMINISTIC_MATCH,
        detail=f"pair for {violation.relation}: a={violation.input_a!r} b={violation.input_b!r}",
    ))
    seed_fix_site(finding, frames)
    return finding


def check_relations(
    run_one: Callable[[object], object],
    seed_corpus: Iterable[object],
    relations: Iterable[Relation],
    *,
    target: str = "<target>",
    language: str = "python",
    entry_point: Frame | None = None,
) -> Finding | None:
    """Run every relation against every seed input and return the first violation as a finding.

    Deterministic: the corpus and the relations are iterated in order, so the same corpus always
    yields the same first violation. Returns ``None`` when every relation holds on the whole
    corpus — a correct program produces no finding.
    """
    corpus = list(seed_corpus)
    relations = list(relations)
    for x in corpus:
        for relation in relations:
            violation = relation.check(run_one, x)
            if violation is not None:
                return _finding_for(violation, target=target, language=language,
                                    entry_point=entry_point)
    return None


# ---- the plugin wrapper ------------------------------------------------------------------------

_META_BANNER = re.compile(r"===\s*RAKSHA METAMORPHIC\s*===")
_META_RELATION = re.compile(r"relation:\s*(?P<v>[\w-]+)")
_META_CWE = re.compile(r"cwe:\s*(?P<v>CWE-[\w]+)")
_META_DETAIL = re.compile(r"detail:\s*(?P<v>.+)")


class MetamorphicOracle(Oracle):
    name = "metamorphic"
    language = "any"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        if not _META_BANNER.search(raw):
            return []
        relation = (m.group("v") if (m := _META_RELATION.search(raw)) else "relation")
        cwe = (m.group("v") if (m := _META_CWE.search(raw)) else CWE_NOINFO)
        detail = (m.group("v").strip() if (m := _META_DETAIL.search(raw)) else "invariant violated")
        finding = Finding(
            oracle=f"metamorphic:{relation}",
            bug_class=cwe,
            language="any",
            target=target,
            message=f"metamorphic: {relation} violated — {detail}",
            severity="medium",
            frames=[],
            abort_signature=abort_signature(f"{cwe}:{relation}", []),
            raw_excerpt=excerpt(raw),
        )
        return [finding]
