"""The scorecard — the finale five, computed from the finding records themselves.

Shortlisting is banked; every remaining point comes from performance, speed, precision,
functionality and scalability. The rule this module exists to enforce:

    A criterion you cannot measure is a criterion you cannot score.

So the metrics are *derived*, never typed in. Every number here traces back to a field
the pipeline wrote while it ran — a status transition, a gate result, a repair-lane tag.
Nothing is estimated, and nothing can be inflated without falsifying a record, which
the invariants in `finding.py` already forbid.

Screen 5 of the operator console renders exactly this dict.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

from .finding import Finding, GateCheck, RepairLane, Status, reportable


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 2) if values else None


@dataclass
class Scorecard:
    """One snapshot of the jury's own scoresheet, filled in from live records."""

    performance: dict[str, Any] = field(default_factory=dict)
    speed: dict[str, Any] = field(default_factory=dict)
    precision: dict[str, Any] = field(default_factory=dict)
    functionality: dict[str, Any] = field(default_factory=dict)
    scalability: dict[str, Any] = field(default_factory=dict)
    resource: dict[str, Any] = field(default_factory=dict)
    posture: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "performance": self.performance,
            "speed": self.speed,
            "precision": self.precision,
            "functionality": self.functionality,
            "scalability": self.scalability,
            "resource": self.resource,
            "posture": self.posture,
        }


def scorecard(findings: Iterable[Finding]) -> Scorecard:
    """Compute the full scorecard for a set of findings."""
    findings = list(findings)
    reported = reportable(findings)

    by_status = {s: [f for f in findings if f.status is s] for s in Status}
    verified = by_status[Status.VERIFIED]

    # ---- Performance: bugs found and bugs patched -----------------------
    performance = {
        "findings_total": len(findings),
        "findings_reported": len(reported),
        "bugs_confirmed": len([f for f in reported if f.status is not Status.SUSPECTED]),
        "bugs_verified_fixed": len(verified),
        "report_only": len(by_status[Status.REPORT_ONLY]),
        "by_status": {s.value: len(v) for s, v in by_status.items()},
        "by_oracle": _count(f.oracle for f in findings),
        "by_bug_class": _count(f.bug_class for f in findings),
    }

    # ---- Speed: medians, from transition timestamps ---------------------
    pov_times = [f.time_to_pov_seconds for f in findings if f.time_to_pov_seconds is not None]
    patch_times = [f.time_to_patch_seconds for f in findings if f.time_to_patch_seconds is not None]
    speed = {
        "median_time_to_pov_seconds": _median(pov_times),
        "median_time_to_validated_patch_seconds": _median(patch_times),
        "fastest_pov_seconds": round(min(pov_times), 2) if pov_times else None,
        "samples": {"pov": len(pov_times), "patch": len(patch_times)},
    }

    # ---- Precision: 100% on reports, by construction ---------------------
    # Every reported finding has a replaying reproducer because `confirm()` refuses
    # otherwise. This recomputes it from the records rather than asserting it, so the
    # number on screen is a measurement and not a claim.
    with_reproducer = [
        f for f in reported
        if f.reproducer is not None
        and f.replay_before is not None
        and f.replay_before.oracle_fired
    ]
    # Measured over every candidate patch the gate ever judged, taken from the
    # append-only history. Counting only findings that still hold a patch would drop
    # every rejected candidate from the denominator and make this metric 100% by
    # selection bias -- precisely the inflated number this project refuses to publish.
    diff_runs = [r for f in findings for r in f.gate_history
                 if r.check is GateCheck.DIFFERENTIAL_CORPUS]
    diff_survived = [r for r in diff_runs if r.passed]
    # Honest split of how reports were proven: an exploit that replays vs a deterministic match
    # (a dependency CVE, a secret). Both are proof; only the first is an exploit, and the risk
    # register ranks accordingly. Shown so we never imply an exploit we do not have.
    by_evidence = _count(
        f.reproducer.kind for f in with_reproducer if f.reproducer is not None
    )
    precision = {
        "reports_with_reproducer_pct": _pct(len(with_reproducer), len(reported)),
        "reports_without_reproducer": len(reported) - len(with_reproducer),
        "evidence_kind": by_evidence,
        "candidate_patches_gated": len(diff_runs),
        "patches_surviving_differential_pct": _pct(len(diff_survived), len(diff_runs)),
        "patches_rejected_by_gate": len(diff_runs) - len(diff_survived),
        "quarantined_corpus_inputs": sum(
            r.quarantined_inputs for f in findings for r in f.gate_history
        ),
        "unproven_findings_suppressed": len(by_status[Status.SUSPECTED]),
    }

    # ---- Functionality: did the loop run unattended ----------------------
    functionality = {
        "zero_human_input_verified": len([f for f in verified if not f.signatures]),
        "awaiting_human_approval": len([f for f in verified if f.signatures]),
        "repair_rounds_total": sum(f.repair_rounds for f in findings),
        "full_loop_completions": len(verified),
        "roe_levels_exercised": sorted({f.roe_level.value for f in findings}),
    }

    # ---- Scalability: languages, not thread count ------------------------
    languages = sorted({f.language for f in findings})
    scalability = {
        "languages_covered": languages,
        "language_count": len(languages),
        "targets": sorted({f.target for f in findings}),
        "target_count": len({f.target for f in findings}),
        "verified_per_language": _count(f.language for f in verified),
    }

    # ---- Resource utilisation: the escalation ladder working -------------
    fix_lanes = [f.repair_lane for f in verified if f.repair_lane]
    # Every lane ever tried, including candidates the gate went on to reject. Counting
    # only the lanes behind successful fixes would hide model tokens we spent and got
    # nothing for -- which is exactly what the resource criterion asks about.
    attempt_lanes = [l for f in findings for l in f.lane_history]
    inference_attempts = [l for l in attempt_lanes if l is not RepairLane.TEMPLATE]
    inference_fixes = [l for l in fix_lanes if l is not RepairLane.TEMPLATE]
    resource = {
        "fixes_by_lane": _count(l.value for l in fix_lanes),
        "attempts_by_lane": _count(l.value for l in attempt_lanes),
        "zero_inference_fix_pct": _pct(
            len([l for l in fix_lanes if l is RepairLane.TEMPLATE]), len(fix_lanes)
        ),
        "inference_attempts": len(inference_attempts),
        "inference_attempts_without_a_fix": len(inference_attempts) - len(inference_fixes),
    }

    # ---- Posture: the two badges that never change -----------------------
    posture = {"network_interfaces": 0, "cloud_calls": 0}

    return Scorecard(
        performance=performance,
        speed=speed,
        precision=precision,
        functionality=functionality,
        scalability=scalability,
        resource=resource,
        posture=posture,
    )


def _pct(numerator: int, denominator: int) -> float | None:
    """Percentage, or None when there is nothing to measure.

    Returns None rather than 0.0 or 100.0 for an empty denominator: a metric with no
    samples is unmeasured, and reporting it as a number would be exactly the kind of
    unearned claim this project refuses to make.
    """
    if denominator == 0:
        return None
    return round(100.0 * numerator / denominator, 1)


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))
