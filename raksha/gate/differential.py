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
from typing import Callable

from .target import BuildResult, Target

#: Only what is noise BY CONSTRUCTION. Every mask hides real output from the comparison, so an
#: over-broad one lets a bad patch through; genuine non-determinism beyond these is caught by the
#: pre-flight and quarantined by name instead.
_DEFAULT_PATTERNS: tuple[tuple[str, str], ...] = (
    # ISO-8601 timestamps, with or without fraction / zone
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TS>"),
    # UUIDs (random by design)
    (r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>"),
    # pointers: 0x + at least 8 hex digits (a short 0x1234 is a value, not an address)
    (r"\b0x[0-9a-fA-F]{8,}\b", "<ADDR>"),
    # JVM identity hash in a default toString: Object@1b6d3586
    (r"(?<=@)[0-9a-f]{6,8}\b", "<IDHASH>"),
    # names minted by mkdtemp/tempfile — only the random component, the rest of the path is kept
    (r"/tmp/(?:tmp[A-Za-z0-9_]{6,}|raksha-[A-Za-z0-9_\-]+)", "/tmp/<TMP>"),
    # a duration only where a timing word introduces it: "took 12ms", "elapsed=1.2 s", "in 0.34s"
    (r"(?i)\b(took|elapsed|duration|latency|time|in)([=: ]\s*)\d+(?:\.\d+)?\s?(?:ms|µs|us|ns|s|sec|secs|seconds)\b",
     "\\1\\2<DUR>"),
    # process / thread ids in their keyed forms
    (r"\b(?:pid|tid|thread-id)[=: ]\s?\d+\b", "<PID>"),
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


#: Crash output from a program with no sanitizer attached. Without these, an input that genuinely
#: crashes on the baseline would be treated as ordinary behaviour — and a correct patch that fixes
#: that crash would then be rejected for "changing" it.
_CRASH_BANNER = re.compile(
    r"Traceback \(most recent call last\)|Exception in thread \"|Segmentation fault|core dumped"
    r"|^panic: |thread '[^']*' panicked at|Fatal Python error|terminate called after throwing"
    r"|SIGSEGV|SIGABRT|SIGBUS|SIGILL|SIGFPE",
    re.MULTILINE,
)


def _aborted(r, is_abort) -> bool:
    """A run aborted if it timed out, died on a signal, printed a crash banner, or an oracle fired.
    A plain non-zero exit (a validation reject, a usage error) is NOT an abort — it is behaviour."""
    signalled = r.exit_code < 0 or 128 < r.exit_code < 160   # subprocess: -N; via a shell: 128+N
    return bool(r.timed_out or signalled or _CRASH_BANNER.search(r.text) or is_abort(r.text))


@dataclass(frozen=True)
class Quarantined:
    index: int
    reason: str


@dataclass
class PreflightResult:
    stable: list[int] = field(default_factory=list)
    quarantined: list[Quarantined] = field(default_factory=list)
    crashing: list[int] = field(default_factory=list)  # inputs that ABORT on the baseline: not comparable


def preflight(
    target: Target,
    baseline: BuildResult,
    corpus: list[bytes],
    *,
    runs: int = 3,
    canon: Canonicaliser | None = None,
    is_abort: Callable[[str], bool] | None = None,
) -> PreflightResult:
    """Run each input `runs` times on the unpatched build; quarantine anything that varies.

    An input is "crashing" (dropped from the comparison) only when it genuinely ABORTS on the
    baseline — a timeout, or output an oracle recognises as a crash. A plain deterministic
    non-zero exit (a validation reject, a usage error) is NOT an abort: it is comparable
    behaviour, so it stays in the differential set with its exit code as part of its signature.
    Treating every non-zero exit as "crashing" used to silently narrow the check to exit-0
    inputs, letting a patch change every error path unnoticed.
    """
    canon = canon or Canonicaliser()
    is_abort = is_abort or (lambda _text: False)
    result = PreflightResult()
    for i, data in enumerate(corpus):
        signatures = []
        aborted = False
        for _ in range(runs):
            r = target.run(baseline, data)
            if _aborted(r, is_abort):
                aborted = True
                break
            # The signature is output AND exit code, so an error-path input with a stable
            # non-zero exit is comparable and a patch that changes it will be caught.
            signatures.append((canon.canon(r.stdout), r.exit_code))
        if aborted:
            result.crashing.append(i)
            continue
        if len(set(signatures)) == 1:
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
