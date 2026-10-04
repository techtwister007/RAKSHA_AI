"""Fleet roll-up (C5): one defect across many repositories, folded into one finding with N sites.

The vaccine sweep searches an estate for *variants* of a proven fix. This is the complementary
book-keeping: when the SAME defect (by canonical crash signature, or the same deterministic match)
appears in several targets — a vendored library copied across services, one bug pattern repeated —
the board should show one defect with its locations, not N identical rows that triple the counts.

It groups, it never merges records destructively: each member finding keeps its own identity and
evidence; the roll-up is a view over them for the operator and the Scorecard.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .finding import DETERMINISTIC_MATCH, Finding, reportable
from .signature import signature


def _key(f: Finding) -> str:
    """How two findings are 'the same defect' for roll-up: a crash by its signature; a deterministic
    match by its advisory/rule and package, independent of which manifest it sits in."""
    if f.reproducer is not None and f.reproducer.kind == DETERMINISTIC_MATCH:
        sym = f.frames[0].symbol if f.frames else ""
        return f"det:{f.bug_class}:{f.abort_signature or ''}:{sym}"
    return f"crash:{signature(f)}"


@dataclass
class FleetGroup:
    key: str
    bug_class: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def locations(self) -> list[str]:
        return sorted({f.target for f in self.findings})

    def as_dict(self) -> dict:
        return {"bug_class": self.bug_class, "count": len(self.findings),
                "targets": self.locations, "finding_ids": [f.id for f in self.findings],
                "message": self.findings[0].message[:140] if self.findings else ""}


def rollup(findings) -> list[dict]:
    """Groups of the same defect spanning TWO OR MORE targets, most-widespread first. A defect in a
    single target is not a fleet issue and is left out of the roll-up."""
    groups: dict[str, FleetGroup] = {}
    for f in reportable(findings):
        k = _key(f)
        g = groups.setdefault(k, FleetGroup(key=k, bug_class=f.bug_class))
        g.findings.append(f)
    spanning = [g for g in groups.values() if len(g.locations) >= 2]
    spanning.sort(key=lambda g: len(g.locations), reverse=True)
    return [g.as_dict() for g in spanning]
