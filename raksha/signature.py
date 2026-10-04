"""The canonical crash signature (W0-2).

Two different notions of "the same bug" already live in `finding.dedup_key`: a deterministic match
is its location, a crash is its stack. That key is tuned for the Normalise stage (collapsing 800
fuzzer inputs into one record) and is exact on the CWE.

The *signature* here answers a different, coarser question that several later stages ask:

    "Is this crash the same defect as that one, for the purpose of deciding whether a patch fixed
     it, whether the red team found a NEW bug, and whether a fleet holds one defect in many files?"

So it groups on the CWE **family** (W0-3), not the exact code — a patch that turns a CWE-121 into a
CWE-122 has not fixed the memory defect — and on the normalised target-owned top frames, with
runtime/fuzzer frames dropped. It is deliberately independent of input bytes and of build paths, so
the same defect reached by two different inputs, on two builds, carries one signature.

The multi-bug gate (A1) uses it as: the fixed signature must be absent on the patched build, and no
signature may appear that was absent on the vulnerable build. The red team uses it to tell a genuine
new win from a re-find. The fleet roll-up (C5) uses it to fold one defect across repositories.
"""

from __future__ import annotations

import hashlib

from .cwe import family
from .finding import RUNTIME_FRAME_PREFIXES, Finding, Frame


def _owned(frames: list[Frame]) -> list[Frame]:
    own = [f for f in frames if not f.symbol.startswith(RUNTIME_FRAME_PREFIXES)]
    return own or list(frames)


def signature(finding: Finding, *, depth: int = 3) -> str:
    """A stable, path-independent, family-level identity for a crash finding.

    `<family-or-cwe>:<hash of the owned top frames>`. The prefix is human-readable so a journal or a
    red-team log shows which defect moved; the hash disambiguates two defects in the same family.
    """
    fam = family(finding.bug_class) or finding.bug_class or "unknown"
    own = _owned(finding.frames)
    # top frame carries its line (one function can hold two distinct defects); the rest are
    # symbol@basename only, so a recompile or a different scratch path does not change the signature.
    parts = []
    if own:
        parts.append(own[0].normalised() + f":{own[0].line or ''}")
        parts += [f.normalised() for f in own[1:depth]]
    digest = hashlib.sha256("|".join([fam, *parts]).encode()).hexdigest()[:12]
    return f"{fam}:{digest}"


def same_defect(a: Finding, b: Finding) -> bool:
    """Whether two crash findings are, to the signature's resolution, the same defect."""
    return signature(a) == signature(b)
