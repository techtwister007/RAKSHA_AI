"""Minimal, dependency-free semantic-version comparison for the supply-chain lane.

Good enough for "is X in [introduced, fixed)?" across the ecosystems we parse. Not a full semver
implementation: it compares dotted numeric releases and orders any pre-release / build suffix
*before* the same release without it (so 2.17.1-rc1 < 2.17.1), which is the conservative choice for
a vulnerability check. Non-numeric or unparseable versions compare as equal-unknown and the caller
treats an unknown as "cannot confirm", never as a false positive.
"""

from __future__ import annotations

import re

_SPLIT = re.compile(r"[.\-+]")


def parse(v: str) -> tuple[list[int], bool]:
    """Return (numeric release components, had_suffix). Leading 'v' tolerated."""
    v = v.strip().lstrip("vV")
    had_suffix = False
    nums: list[int] = []
    for part in _SPLIT.split(v):
        if part.isdigit():
            nums.append(int(part))
        elif part:
            had_suffix = True
            break  # stop at the first non-numeric part (pre-release/build)
    return nums, had_suffix


def compare(a: str, b: str) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b. Pre-release suffix sorts before the bare release."""
    na, sa = parse(a)
    nb, sb = parse(b)
    for x, y in zip(na, nb):
        if x != y:
            return -1 if x < y else 1
    if len(na) != len(nb):
        return -1 if len(na) < len(nb) else 1
    if sa != sb:               # same numeric release; suffixed one is earlier
        return -1 if sa else 1
    return 0


def in_range(version: str, introduced: str, fixed: str | None) -> bool:
    """True if introduced <= version < fixed (fixed=None means unbounded above)."""
    if compare(version, introduced) < 0:
        return False
    if fixed is not None and compare(version, fixed) >= 0:
        return False
    return True
