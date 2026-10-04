"""The ranked risk register — "fix these 3 first, ignore these 400".

An operator with 500 systems does not want 500 patches dumped on them; they want priorities. This
ranks reportable findings by severity x reachability x exploitability, each factor derived from the
record rather than guessed:

  severity       — the oracle's own rating (critical/high/medium/low)
  reachability   — a finding with a replaying reproducer is reachable (1.0); a static-only SUSPECTED
                   finding is only possibly reachable (0.4)
  exploitability — an exploit that replays (1.0) outranks a deterministic match such as a dependency
                   CVE (0.7) or a spec-only exposure (0.6); this is why the register ranks
                   exploit-proven findings above match-proven ones

Verified fixes sort to the top within a score band (they are actionable now), and REPORT_ONLY
findings are flagged for human remediation. The score is a priority signal, never a precision claim.
"""

from __future__ import annotations

from dataclasses import dataclass

from .finding import DETERMINISTIC_MATCH, EXPLOIT_REPLAY, Finding, Status, reportable

_SEVERITY = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}


def _reachability(f: Finding) -> float:
    if f.reproducer is not None and f.replay_before is not None and f.replay_before.oracle_fired:
        return 1.0
    return 0.4  # static-only / unproven: possibly reachable


def _exploitability(f: Finding) -> float:
    if f.reproducer is None:
        return 0.5
    if f.reproducer.kind == EXPLOIT_REPLAY:
        return 1.0
    if f.reproducer.kind == DETERMINISTIC_MATCH:
        return 0.7
    return 0.6


@dataclass
class RiskRow:
    finding: Finding
    score: float
    severity: float
    reachability: float
    exploitability: float

    @property
    def actionable(self) -> bool:
        return self.finding.status is Status.VERIFIED

    def as_dict(self) -> dict:
        f = self.finding
        return {
            "id": f.id, "bug_class": f.bug_class, "severity": f.severity, "language": f.language,
            "target": f.target, "status": f.status.value, "score": round(self.score, 2),
            "has_fix": f.status is Status.VERIFIED, "message": f.message[:120],
            "evidence": f.reproducer.kind if f.reproducer else None,
        }


def register(findings) -> list[RiskRow]:
    """All reportable findings, ranked most-urgent first. A verified fix breaks ties upward."""
    rows = []
    for f in reportable(findings):
        sev = _SEVERITY.get(f.severity.lower(), 1.0)
        reach = _reachability(f)
        expl = _exploitability(f)
        rows.append(RiskRow(f, sev * reach * expl, sev, reach, expl))
    rows.sort(key=lambda r: (r.score, r.actionable), reverse=True)
    return rows


def fix_first(findings, n: int = 3) -> list[RiskRow]:
    """The top-n the operator should act on now."""
    return register(findings)[:n]
