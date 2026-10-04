"""A small, deterministic, dependency-free mutation fuzzer.

Autofuzz's job is to need no hand-written harness AND no fuzzing engine installed on the sealed node.
libFuzzer/AFL need a compiler-rt runtime that is often absent (it is here); this gives the find loop
a floor that always runs: mutate an input, feed it to the synthesized harness, keep whatever makes
the oracle fire. It is coverage-blind — a real campaign with AFL++/libFuzzer is far stronger and
plugs in behind the same `Fuzzer` interface when the toolchain is present — but it is enough to turn
a synthesized harness into real crashing inputs on the bugs the demo and the ARVO-class targets hold.

Deterministic: every run with the same seed and corpus produces the same inputs, so a finding is
reproducible and the numbers are stable. That is the property a fuzzing engine deliberately lacks and
that the gate's differential check needs.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable

#: Tokens worth trying verbatim: the shapes that trip real parsers. Extended from the seed corpus.
_DICTIONARY = [
    b"", b"\x00", b"\xff", b"\x00\x00\x00\x00", b"\xff" * 8, b"A" * 64, b"%s%s%s%n", b"../" * 8,
    b"${jndi:ldap://x/a}", b"'; DROP TABLE t;--", b"\x7fELF", b"{}", b"[]", b"-1", b"2147483648",
    b"99999999999999999999", b"\n" * 16, b"\t", b"%00", b"&&id", b"`id`",
]


@dataclass
class FuzzResult:
    crashes: list[bytes] = field(default_factory=list)   # distinct inputs that fired the oracle
    executions: int = 0
    first_crash_execs: int | None = None                 # execs until the first crash (a speed signal)
    stopped_early: bool = False                          # the plateau rule returned the budget early

    @property
    def found(self) -> bool:
        return bool(self.crashes)


def _mutate(rng: random.Random, data: bytes) -> bytes:
    """One mutation, chosen at random from the moves a byte-level fuzzer uses."""
    if not data:
        return rng.choice(_DICTIONARY) or b"\x00"
    b = bytearray(data)
    move = rng.randrange(7)
    if move == 0:                                   # flip a bit
        i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
    elif move == 1:                                 # set a random byte
        b[rng.randrange(len(b))] = rng.randrange(256)
    elif move == 2:                                 # insert a run (grow — this is what overflows buffers)
        b[rng.randrange(len(b) + 1):0] = bytes([rng.randrange(256)]) * rng.randrange(1, 64)
    elif move == 3:                                 # delete a span
        i = rng.randrange(len(b)); del b[i:i + rng.randrange(1, 8)]
    elif move == 4:                                 # splice in a dictionary token
        tok = rng.choice(_DICTIONARY)
        i = rng.randrange(len(b) + 1); b[i:i] = tok
    elif move == 5:                                 # repeat the whole input (overflow via length)
        b = bytearray(bytes(b) * rng.randrange(2, 6))
    else:                                           # interesting integer at a boundary
        for v in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\x80\x00\x00\x00"):
            if rng.random() < 0.5:
                i = rng.randrange(len(b)); b[i:i + len(v)] = v
                break
    return bytes(b[:1 << 20])                        # cap at 1 MiB so one input can't exhaust memory


@dataclass
class Fuzzer:
    """Feed mutated inputs to `run_one` until it fires the oracle or the budget is spent.

    `run_one(data) -> bool` returns True when the input made the oracle fire (a crash). The caller
    supplies it; it is the one thing that knows how to execute the synthesized harness.
    """

    run_one: Callable[[bytes], bool]
    seed_corpus: list[bytes] = field(default_factory=list)
    max_execs: int = 20000
    max_crashes: int = 5
    seed: int = 1337
    #: Stop early once this many consecutive executions add neither a crash nor a new corpus input.
    #: This is the "marginal information" stopping rule: when fresh execs stop teaching the campaign
    #: anything, the next ones are unlikely to either, so we return the budget to the orchestrator.
    #: None disables it (run the full budget). It makes the stop principled rather than a fixed clock.
    max_execs_without_progress: int | None = 4000
    #: Optional external coverage-guided engine (AFL++/libFuzzer) when its runtime is present. A
    #: callable (run_one, seed_corpus, max_execs, seed) -> FuzzResult. None uses this stdlib engine,
    #: which always runs; a real engine plugs in here without changing any caller.
    engine: Callable | None = None

    def run(self) -> FuzzResult:
        if self.engine is not None:
            # A real coverage-guided engine (AFL++/libFuzzer) when its runtime is carried. It owns
            # the loop and the stopping; we just hand it the same contract and return its result.
            return self.engine(self.run_one, list(self.seed_corpus), self.max_execs, self.seed)
        rng = random.Random(self.seed)
        corpus = list(self.seed_corpus) or [b"A", b""]
        result = FuzzResult()
        seen: set[bytes] = set()
        since_progress = 0
        # First try the seed corpus and the dictionary verbatim — the cheapest wins come free.
        for data in [*corpus, *_DICTIONARY]:
            if self._check(data, result, seen):
                corpus.append(data)
            if len(result.crashes) >= self.max_crashes:
                return result
        before = len(corpus)
        while result.executions < self.max_execs and len(result.crashes) < self.max_crashes:
            base = rng.choice(corpus)
            data = _mutate(rng, base)
            grew = self._check(data, result, seen) and len(data) < 4096
            if grew:
                corpus.append(data)                 # keep a crasher as a base for nearby bugs
            # progress = a new crash or a new corpus input since we last checked
            if len(corpus) > before or result.crashes:
                since_progress = 0
                before = len(corpus)
            else:
                since_progress += 1
            if (self.max_execs_without_progress is not None
                    and since_progress >= self.max_execs_without_progress and not result.crashes):
                result.stopped_early = True
                break
        return result

    def _check(self, data: bytes, result: FuzzResult, seen: set[bytes]) -> bool:
        result.executions += 1
        fired = self.run_one(data)
        if fired and data not in seen:
            seen.add(data)
            result.crashes.append(data)
            if result.first_crash_execs is None:
                result.first_crash_execs = result.executions
        return fired
