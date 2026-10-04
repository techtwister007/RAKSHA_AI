"""B2 — deterministic input minimisation (delta-debugging / ddmin).

A fuzzing campaign confirms a bug with whatever crashing input it stumbled on -- often large and
full of bytes irrelevant to the crash. A minimal reproducer is smaller to store, faster to replay,
and far easier for a human (or the repair lanes) to read as "this is what triggers it". This module
shrinks a crashing input to a locally minimal one while a caller-supplied predicate stays true.

Algorithm
---------
Classic Zeller ddmin. The input is split into ``n`` contiguous chunks (starting at ``n=2``); at each
granularity we try, in a fixed order:

  1. **reduce to a subset** -- does a single chunk, alone, still satisfy the predicate? If so, keep
     it and reset to the coarsest granularity.
  2. **reduce to a complement** -- does the input with one chunk removed still satisfy it? If so,
     keep that and drop the granularity by one.
  3. otherwise **refine** -- double ``n`` (capped at the input length) and try again.

When ``n`` reaches the input length and no single-byte removal preserves the predicate, the result
is *1-minimal*: removing any one byte breaks it. That is the "locally minimal" guarantee.

Guarantees
----------
* **Never returns a non-crashing input.** The result is only ever the original input or a candidate
  for which ``still_crashes`` was observed True; every reduction is re-checked before it is kept,
  so the returned bytes always satisfy the predicate (when the original did).
* **Deterministic & stable.** No randomness; chunks are split and visited in a fixed order and
  predicate results are memoised, so the same ``(data, predicate)`` always yields the same output.
* **Terminates.** Every kept reduction strictly shortens the input, and ``max_rounds`` caps the
  outer passes as a belt-and-braces guard against a pathological predicate.
* **stdlib only, offline.**
"""

from __future__ import annotations

from typing import Callable

#: Default cap on outer-loop passes. ddmin terminates on its own (each reduction strictly shrinks
#: the input); this is a safety net so a non-monotone predicate can never loop forever. Generous
#: enough that it is never hit for a well-behaved predicate.
DEFAULT_MAX_ROUNDS = 10_000


def _split(data: bytes, n: int) -> list[bytes]:
    """Split ``data`` into ``n`` contiguous, near-equal chunks (deterministic)."""
    length = len(data)
    n = min(n, length) or 1
    # distribute the remainder across the first chunks so sizes differ by at most one.
    base, extra = divmod(length, n)
    chunks: list[bytes] = []
    start = 0
    for i in range(n):
        size = base + (1 if i < extra else 0)
        chunks.append(data[start:start + size])
        start += size
    return chunks


def minimise(
    data: bytes,
    still_crashes: Callable[[bytes], bool],
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
) -> bytes:
    """Shrink ``data`` to a locally minimal input for which ``still_crashes`` holds.

    ``still_crashes(candidate) -> bool`` is the predicate to preserve (typically: replaying
    ``candidate`` fires the oracle). It must be deterministic for the result to be stable.

    Returns the smallest input ddmin reaches that still satisfies the predicate. If the original
    ``data`` does not satisfy the predicate, it is returned unchanged (there is nothing to minimise
    and we never fabricate a crashing input) -- so a caller that has already confirmed the crash is
    guaranteed a predicate-true result.
    """
    cache: dict[bytes, bool] = {}

    def test(candidate: bytes) -> bool:
        cached = cache.get(candidate)
        if cached is None:
            cached = bool(still_crashes(candidate))
            cache[candidate] = cached
        return cached

    # Contract guard: only minimise something that actually crashes. If it does not, hand it back
    # untouched rather than returning a reduction that does not satisfy the predicate.
    if not test(data):
        return data

    n = 2
    rounds = 0
    while len(data) >= 2 and rounds < max_rounds:
        rounds += 1
        chunks = _split(data, n)
        progressed = False

        # 1. reduce to a subset: a single chunk alone still crashes.
        for chunk in chunks:
            if chunk and chunk != data and test(chunk):
                data = chunk
                n = 2
                progressed = True
                break
        if progressed:
            continue

        # 2. reduce to a complement: dropping one chunk still crashes.
        for i in range(len(chunks)):
            complement = b"".join(chunks[:i] + chunks[i + 1:])
            if complement and complement != data and test(complement):
                data = complement
                n = max(n - 1, 2)
                progressed = True
                break
        if progressed:
            continue

        # 3. refine: finer granularity, or stop when we are already at per-byte chunks.
        if n >= len(data):
            break
        n = min(len(data), n * 2)

    return data
