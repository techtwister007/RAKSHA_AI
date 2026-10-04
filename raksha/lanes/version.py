"""Dependency-free version comparison for the supply-chain lane.

Precision is scored, and a range check is only as good as its comparison at the boundary, which is
exactly where real-world version strings get awkward. This handles the shapes the parsed ecosystems
actually publish:

  - trailing zeros are equal:            1.0 == 1.0.0 == 1.0.0.0
  - pre-releases sort before the release, ordered by stage then number:
                                          2.0-alpha1 < 2.0-beta9 < 2.0-rc2 < 2.0
                                          5.4b1 < 5.4 (PEP 440, letters attached) · 1.0.0-alpha.2 < 1.0.0-alpha.10
  - a numeric semver pre-release / Go pseudo-version sorts before its release:
                                          1.2.6-0 < 1.2.6 · 1.7.0-0.2021…-abc < 1.7.0
  - Maven release qualifiers equal the release: 5.3.0.RELEASE == 5.3.0.Final == 5.3.0.GA == 5.3.0
  - post-releases sort after:            1.2.3.post1 > 1.2.3
  - build metadata is ignored:           1.0.0+build.5 == 1.0.0
  - epochs (PEP 440):                    1!1.0 > 2.0

A version with no readable release number compares as unknown; `in_range` returns False for it, so an
unparseable version is never reported (no false positive from a string we cannot read).
"""

from __future__ import annotations

import re

_RELEASE = re.compile(r"^(\d+(?:\.\d+)*)")
_PRE = re.compile(r"^(dev|snapshot|alpha|a|beta|b|milestone|m|preview|pre|rc|cr|c)[.\-_]?(\d*)")
_POST = re.compile(r"^(?:post|rev|r|sp|patch)[.\-_]?(\d*)")
_EQUAL_QUALIFIER = re.compile(r"^(?:release|final|ga)$")
_STAGE = {"dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3,
          "preview": 4, "pre": 4, "rc": 5, "cr": 5, "c": 5}

# suffix ordering keys: (class, rank, number)
#   class 0 = pre-release (sorts before the release), 1 = the release itself, 2 = post-release
_RELEASE_KEY = (1, 0, 0)


def parse(v: str) -> tuple[int, tuple[int, ...], tuple[int, int, int]] | None:
    """(epoch, release numbers with trailing zeros stripped, suffix key), or None if unreadable."""
    s = v.strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    s = s.split("+", 1)[0]                          # build metadata never affects precedence
    epoch = 0
    if "!" in s:
        e, _, s = s.partition("!")
        if not e.isdigit():
            return None
        epoch = int(e)
    m = _RELEASE.match(s)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    rest = s[m.end():].lstrip(".-_").lower()
    return epoch, tuple(nums), _suffix_key(rest)


def _suffix_key(rest: str) -> tuple[int, int, int]:
    if not rest or _EQUAL_QUALIFIER.match(rest):
        return _RELEASE_KEY
    pre = _PRE.match(rest)
    if pre:
        return (0, _STAGE[pre.group(1)], int(pre.group(2) or 0))
    post = _POST.match(rest)
    if post:
        return (2, 0, int(post.group(1) or 0))
    if rest[0].isdigit():
        # a numeric pre-release (semver "1.2.6-0", Go pseudo-version) — before its release
        lead = re.match(r"\d+", rest)
        return (0, -1, int(lead.group(0)) if lead else 0)
    return (0, 6, 0)  # an unrecognised qualifier: treat as a pre-release (semver's default)


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


def compare(a: str, b: str) -> int | None:
    """-1 if a<b, 0 if equal, 1 if a>b; None if either version is unreadable."""
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        return _cmp(pa[0], pb[0])
    na, nb = list(pa[1]), list(pb[1])
    width = max(len(na), len(nb))
    na += [0] * (width - len(na))
    nb += [0] * (width - len(nb))
    if na != nb:
        return _cmp(na, nb)
    return _cmp(pa[2], pb[2])


def in_range(version: str, introduced: str, fixed: str | None) -> bool:
    """True if introduced <= version < fixed (fixed=None means unbounded above).

    An unreadable version is never in range: we only report what we can verify.
    """
    lo = compare(version, introduced)
    if lo is None or lo < 0:
        return False
    if fixed is not None:
        hi = compare(version, fixed)
        if hi is None or hi >= 0:
            return False
    return True


def in_any_range(version: str, ranges: list[dict]) -> dict | None:
    """The first range ({introduced, fixed}) that contains `version`, or None."""
    for r in ranges:
        if in_range(version, r.get("introduced", "0"), r.get("fixed")):
            return r
    return None
