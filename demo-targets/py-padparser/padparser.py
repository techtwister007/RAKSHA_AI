"""A record parser that violates padding-invariance — the metamorphic demo.

A well-behaved record parser should ignore harmless trailing padding: appending a trailing
newline (or other whitespace) to a record must not change how it parses. ``checksum`` folds
*every* byte into a 16-bit sum, trailing bytes included, so ``checksum(x)`` and
``checksum(x + b"\\n")`` differ. That is a metamorphic relation violation (padding-invariance),
which maps to CWE-20 (improper input validation) — not a crash, a *wrong answer* that the
MetamorphicOracle finds by comparing the outputs of two related inputs.

``checksum_fixed`` is the corrected parser: it strips trailing whitespace first, so padding no
longer changes the result and the relation holds. The oracle must find a violation in the
first and nothing in the second.
"""

from __future__ import annotations

_WHITESPACE = b" \t\r\n\x0b\x0c"


def checksum(data: bytes) -> int:
    """BUG: folds trailing padding into the checksum, so trailing bytes change the output."""
    total = 0
    for b in data:
        total = (total + b) & 0xFFFF
    return total


def checksum_fixed(data: bytes) -> int:
    """Correct parser: ignore trailing whitespace before folding, restoring padding-invariance."""
    total = 0
    for b in data.rstrip(_WHITESPACE):
        total = (total + b) & 0xFFFF
    return total
