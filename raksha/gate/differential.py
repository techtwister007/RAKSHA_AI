"""The differential-corpus check and the machinery that keeps it honest on real services.

The check itself is simple: every non-crashing corpus input must produce the same output before
and after the patch. What makes it usable on a real service is the pre-flight — a target whose
output carries timestamps, UUIDs or hash-ordered keys would otherwise fail its own patch.

So: a canonicaliser strips the noise that is noise by construction (timestamps, UUIDs, hex
addresses, temp paths, durations), and a determinism pre-flight runs each input several times on
the UNPATCHED build. An input whose canonical output still varies is quarantined — excluded from
the comparison and listed by name in the bundle, never silently dropped. The quarantine count is a
number we show.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .target import BuildResult, Target

_DEFAULT_PATTERNS: tuple[tuple[str, str], ...] = (
    # ISO-8601 timestamps, with or without fraction / zone
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TS>"),
    # UUIDs
    (r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>"),
    # hex addresses and long hex tokens (pointers, hashes)
    (r"\b0x[0-9a-fA-F]{4,}\b", "<ADDR>"),
    (r"\b[0-9a-fA-F]{32,}\b", "<HEX>"),
    # temp paths
    (r"/tmp/[\w.\-/]+", "<TMP>"),
    # durations: "took 12ms", "in 0.34s", "elapsed=1.2 s"
    (r"\b\d+(?:\.\d+)?\s?(?:ms|µs|us|ns|s|sec|seconds)\b", "<DUR>"),
    # PIDs / thread ids in the common forms
    (r"\b(?:pid|tid|thread)[=: ]\s?\d+\b", "<PID>"),
)


@dataclass
class Canonicaliser:
    """Normalise output that differs for reasons that are not behaviour."""

    patterns: tuple[tuple[str, str], ...] = _DEFAULT_PATTERNS
    extra: tuple[tuple[str, str], ...] = ()
    sort_lines: bool = False  # for outputs whose line order is hash-dependent

    def __post_init__(self) -> None:
        self._compiled = [(re.compile(p), r) for p, r in (*self.patterns, *self.extra)]

    def canon(self, data: bytes) -> bytes:
        text = data.decode("utf-8", "replace")
        for rx, repl in self._compiled:
            text = rx.sub(repl, text)
        if self.sort_lines:
            text = "\n".join(sorted(text.splitlines()))
        return text.encode("utf-8")


@dataclass(frozen=True)
class Quarantined:
    index: int
    reason: str


@dataclass
class PreflightResult:
    stable: list[int] = field(default_factory=list)
    quarantined: list[Quarantined] = field(default_factory=list)
    crashing: list[int] = field(default_factory=list)  # inputs that abort on the baseline: not comparable


def preflight(
    target: Target,
    baseline: BuildResult,
    corpus: list[bytes],
    *,
    runs: int = 3,
    canon: Canonicaliser | None = None,
) -> PreflightResult:
    """Run each input `runs` times on the unpatched build; quarantine anything that varies."""
    canon = canon or Canonicaliser()
    result = PreflightResult()
    for i, data in enumerate(corpus):
        outputs = []
        aborted = False
        for _ in range(runs):
            r = target.run(baseline, data)
            if r.timed_out or r.exit_code != 0:
                aborted = True
                break
            outputs.append(canon.canon(r.stdout))
        if aborted:
            result.crashing.append(i)
            continue
        if len(set(outputs)) == 1:
            result.stable.append(i)
        else:
            result.quarantined.append(Quarantined(i, "output varies across identical runs"))
    return result


@dataclass(frozen=True)
class Mismatch:
    index: int
    before: bytes
    after: bytes


def differential(
    target: Target,
    before: BuildResult,
    after: BuildResult,
    corpus: list[bytes],
    stable: list[int],
    *,
    canon: Canonicaliser | None = None,
) -> list[Mismatch]:
    """For every stable input, canonical output before must equal canonical output after."""
    canon = canon or Canonicaliser()
    mismatches: list[Mismatch] = []
    for i in stable:
        a = target.run(before, corpus[i])
        b = target.run(after, corpus[i])
        ca, cb = canon.canon(a.stdout), canon.canon(b.stdout)
        if ca != cb or a.exit_code != b.exit_code:
            mismatches.append(Mismatch(i, ca, cb))
    return mismatches
