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
from typing import Any, Callable, Iterable

from .finding import EXPLOIT_REPLAY, INFERENCE_LANES, Finding, GateCheck, Status, reportable
from .gpu import VramReading, vram
from . import inference, sandbox

#: Record "languages" that are really lanes, not languages: a secret ("any") or an API spec ("api").
NOT_A_LANGUAGE = frozenset({"any", "api"})

#: Findings produced within this window of the first finding count toward the "fast opening
#: move" metric — the dossier's "time-to-first-finding matters more than depth".
FIRST_WINDOW_SECONDS = 600


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
    #: What this run did NOT establish. A proof of presence is never a proof of absence, so the
    #: scoresheet carries the boundary of the claim next to the claim.
    boundary: dict[str, Any] = field(default_factory=dict)
    #: The layers added for the AI-vs-AI / quantum / concurrency threat horizon: evidence fusion,
    #: the model parliament, the independent red team, attack chains, PQC readiness, mission tiers.
    depth: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "performance": self.performance,
            "speed": self.speed,
            "precision": self.precision,
            "functionality": self.functionality,
            "scalability": self.scalability,
            "resource": self.resource,
            "posture": self.posture,
            "boundary": self.boundary,
            "depth": self.depth,
        }


def live_counters() -> dict[str, int]:
    """Process-wide inference and execution counters, for a session to snapshot at its start."""
    return {**inference.counters(), **sandbox.execution_counts()}


def scorecard(
    findings: Iterable[Finding],
    *,
    vaccine_variants: int | None = None,
    gpu_probe: Callable[[], VramReading | None] = vram,
    started_at=None,
    counter_baseline: dict[str, int] | None = None,
    targets_degraded: int | None = None,
    targets_total: int | None = None,
    attack_graph: dict | None = None,
    pqc: dict | None = None,
) -> Scorecard:
    """Compute the full scorecard for a set of findings.

    `vaccine_variants` is the count of fleet variants found per verified fix by the vaccine
    sweep (held by the session, not the records), surfaced here so Screen 5 shows every ledger
    row. `gpu_probe` reads live VRAM; it returns None off-GPU, and the metric is then honestly
    absent rather than a faked zero. `started_at` is when the run began (so time-to-first-finding is
    wall-clock from the start, build and fuzzing included); `counter_baseline` is the live-counter
    snapshot taken then, so this run reports only its own model calls, tokens and executions.
    """
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

    # ---- Speed: medians + the opening move, from transition timestamps --
    pov_times = [f.time_to_pov_seconds for f in findings if f.time_to_pov_seconds is not None]
    patch_times = [f.time_to_patch_seconds for f in findings if f.time_to_patch_seconds is not None]
    # The dossier's headline speed number: wall-clock from the run's first finding to the first
    # one that became reportable. Taken from created_at (the run's t0) to the earliest CONFIRMED
    # transition among reported findings — derived from the records, not a stopwatch guess.
    t0 = started_at or min((f.created_at for f in findings), default=None)
    first_proven_at = min(
        (f._transition_at(Status.CONFIRMED) for f in reported
         if f._transition_at(Status.CONFIRMED) is not None),
        default=None,
    )
    time_to_first_finding = (
        round((first_proven_at - t0).total_seconds(), 2) if t0 and first_proven_at else None
    )
    proven_in_first_window = (
        len([f for f in reported
             if (f._transition_at(Status.CONFIRMED) or f.created_at) - t0 <= _window()])
        if t0 else 0
    )
    speed = {
        "time_to_first_proven_finding_seconds": time_to_first_finding,
        "median_time_to_pov_seconds": _median(pov_times),
        "median_time_to_validated_patch_seconds": _median(patch_times),
        "fastest_pov_seconds": round(min(pov_times), 2) if pov_times else None,
        "proven_findings_in_first_10min": proven_in_first_window,
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
        # Cross-confirmation: a static SUSPECTED finding promoted because another lane's
        # reproducer landed on the same fix site with the same CWE. Counted from the merge
        # record on the survivor, so the precision ledger row is a measurement.
        "static_findings_promoted": sum(len(f.merged_from) for f in findings),
        "unproven_findings_suppressed": len(by_status[Status.SUSPECTED]),
        # Candidates patch hygiene refused before any gate run (out-of-scope file, oversized, or a
        # new execution/network primitive). Never applied, so never in the gated count above.
        "candidate_patches_rejected_before_gate": sum(len(f.rejected_candidates) for f in findings),
        # A dependency match proves the version is present; the import scan says whether the
        # code reaches it. Shown so a CVE in an unused library is never dressed as an exploit.
        "dependency_reachability": _count(f.reachability for f in findings if f.reachability),
        # Structural (CPG) hypotheses raised; those a dynamic reproducer later confirmed are already
        # in static_findings_promoted. The rest stay SUSPECTED and never become reports.
        "structural_hypotheses": len([f for f in findings if f.oracle.startswith("cpg:")]),
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
    languages = sorted({f.language for f in findings} - NOT_A_LANGUAGE)
    scalability = {
        "languages_covered": languages,
        "language_agnostic_lanes": sorted({f.language for f in findings} & NOT_A_LANGUAGE),
        "language_count": len(languages),
        "targets": sorted({f.target for f in findings}),
        "target_count": len({f.target for f in findings}),
        "verified_per_language": _count(f.language for f in verified),
        # Vaccine sweep: variants of a verified fix found across the asset estate. Held by the
        # session (not a finding field), passed in so the Scorecard shows the ledger row.
        "vaccine_variants_found": vaccine_variants,
    }

    # ---- Resource utilisation: the escalation ladder working -------------
    fix_lanes = [f.repair_lane for f in verified if f.repair_lane]
    # Every lane ever tried, including candidates the gate went on to reject. Counting
    # only the lanes behind successful fixes would hide model tokens we spent and got
    # nothing for -- which is exactly what the resource criterion asks about.
    attempt_lanes = [l for f in findings for l in f.lane_history]
    # Only the LLM lane spends tokens; template / retrieval / mitigation are all zero-inference.
    inference_attempts = [l for l in attempt_lanes if l in INFERENCE_LANES]
    inference_fixes = [l for l in fix_lanes if l in INFERENCE_LANES]
    zero_inference_fixes = [l for l in fix_lanes if l not in INFERENCE_LANES]
    verified_via_model = len([f for f in verified if f.repair_lane in INFERENCE_LANES])
    now = live_counters()
    base = counter_baseline or {}
    run = {k: now[k] - base.get(k, 0) for k in now}
    tokens_total = run["completion_tokens"]
    vram_reading = gpu_probe()
    resource = {
        "fixes_by_lane": _count(l.value for l in fix_lanes),
        "attempts_by_lane": _count(l.value for l in attempt_lanes),
        "zero_inference_fix_pct": _pct(len(zero_inference_fixes), len(fix_lanes)),
        "inference_attempts": len(inference_attempts),
        "inference_attempts_without_a_fix": len(inference_attempts) - len(inference_fixes),
        # Tokens are an actual sum captured from each model response's usage, not an estimate.
        # Per validated patch = total completion tokens / patches the model lane verified.
        "model_completion_tokens": tokens_total,
        "tokens_per_validated_patch": (
            round(tokens_total / verified_via_model, 1) if verified_via_model else None
        ),
        "inference_calls": run["inference_calls"],
        # Live VRAM, or None off-GPU — honestly absent rather than a faked zero.
        "vram": vram_reading.as_dict() if vram_reading else None,
    }

    # ---- Posture: badges backed by live counters, not constants ----------
    # network_interfaces: target code that ran with a network interface. Zero only when every
    # execution of target code went through the network-less sandbox; any run on the host makes the
    # badge read "unenforced" rather than claim an isolation that did not happen. cloud_calls: model
    # calls that left the sealed deployment.
    posture = {
        "network_interfaces": 0 if run["unsandboxed_runs"] == 0 else "unenforced",
        "cloud_calls": run["egress_calls"],
        "sandboxed_runs": run["sandboxed_runs"],
        "unsandboxed_runs": run["unsandboxed_runs"],
    }

    # ---- Boundary: what this run did not establish --------------------------
    exploit_langs = {f.language for f in findings
                     if f.reproducer is not None and f.reproducer.kind == EXPLOIT_REPLAY} - NOT_A_LANGUAGE
    boundary = {
        "claim": "presence of the findings above, each with a replaying reproducer; never absence",
        "unresolved_suspected": len(by_status[Status.SUSPECTED]),
        "proven_but_unfixed": len(by_status[Status.REPORT_ONLY]),
        "languages_exercised_by_exploit": sorted(exploit_langs),
        "languages_build_free_only": sorted(set(languages) - exploit_langs),
        "targets_degraded_to_build_free": targets_degraded,
        "targets_total": targets_total,
        "dependencies_not_imported": len([f for f in findings if f.reachability == "not-imported"]),
        "dependencies_reachability_unknown": len([f for f in findings if f.reachability == "unknown"]),
        "statement": None,
    }
    boundary["statement"] = assurance_statement(boundary, performance)

    # ---- Depth: the assurance layers for the threat horizon ----------------
    ev = [f.evidence_score for f in findings if f.evidence_score]
    confidences = [e["confidence"] for e in ev]
    parl = [f.parliament for f in findings if f.parliament]
    red = [f.red_team for f in findings if f.red_team]
    depth = {
        # evidence fusion
        "findings_with_fused_evidence": len(ev),
        "median_evidence_confidence": _median(confidences),
        "findings_with_2plus_independent_channels": len([e for e in ev if e.get("independent_channels", 0) >= 2]),
        # model parliament / epistemic conflict (offline: disagreement is None, conflict is measured)
        "parliament_quorum": max((p.get("quorum", 0) for p in parl), default=0),
        "findings_flagged_for_investigation": len([p for p in parl if p.get("flag_for_investigation")]),
        "epistemic_conflicts": len([p for p in parl if p.get("epistemic_conflict")]),
        # independent red team against verified patches
        "patches_red_teamed": len(red),
        "patches_red_team_held": len([r for r in red if r.get("held")]),
        "patches_red_team_broke": len([r for r in red if r.get("held") is False]),
        # patch frontier (Pareto choice among passing candidates)
        "patches_with_frontier_alternatives": len([f for f in verified if len(f.frontier) > 1]),
        # crypto / post-quantum readiness
        "crypto_findings": len([f for f in reported if f.oracle.startswith("crypto:")]),
        "pqc_quantum_vulnerable_sites": (pqc or {}).get("quantum_vulnerable_sites"),
        "pqc_blast_radius": (pqc or {}).get("blast_radius"),
        # attack chains (composition into a path to impact)
        "attack_chains": ((attack_graph or {}).get("summary") or {}).get("chains"),
        "viable_attack_chains": ((attack_graph or {}).get("summary") or {}).get("viable_chains"),
        # mission impact tiers exercised (from the asset registry)
        "mission_tiers": _count(f.mission_impact for f in findings if f.mission_impact),
        # concurrency: races found and proven (the TSan oracle)
        "race_findings": len([f for f in findings if f.oracle.startswith("tsan") or f.bug_class == "CWE-362"]),
    }

    return Scorecard(
        performance=performance,
        depth=depth,
        boundary=boundary,
        speed=speed,
        precision=precision,
        functionality=functionality,
        scalability=scalability,
        resource=resource,
        posture=posture,
    )


def assurance_statement(boundary: dict[str, Any], performance: dict[str, Any]) -> str:
    """The sentence a commander reads instead of "SECURE". It states what was proven and names what
    was not analysed, so the decision-maker knows what the machine knows and what it does not."""
    parts = [f"{performance['findings_reported']} finding(s) proven present, "
             f"{performance['bugs_verified_fixed']} fixed and proven; "
             f"{boundary['proven_but_unfixed']} proven and referred unfixed."]
    if boundary["languages_exercised_by_exploit"]:
        parts.append("Exploit-level analysis covered: " + ", ".join(boundary["languages_exercised_by_exploit"]) + ".")
    if boundary["languages_build_free_only"]:
        parts.append("Build-free analysis only (no exploit attempted): "
                     + ", ".join(boundary["languages_build_free_only"]) + ".")
    if boundary["targets_degraded_to_build_free"]:
        parts.append(f"{boundary['targets_degraded_to_build_free']} of {boundary['targets_total']} target(s) "
                     f"did not build and were analysed build-free only.")
    if boundary["unresolved_suspected"]:
        parts.append(f"{boundary['unresolved_suspected']} suspected finding(s) remain unproven and unreported.")
    if boundary["dependencies_not_imported"] or boundary["dependencies_reachability_unknown"]:
        parts.append(f"Of the dependency findings, {boundary['dependencies_not_imported']} are in packages the "
                     f"code does not import and {boundary['dependencies_reachability_unknown']} could not be "
                     f"checked for reachability.")
    parts.append("This run establishes presence, not absence: unexercised code paths, bug classes without an "
                 "oracle here, and the environment around the code are outside the claim.")
    return " ".join(parts)


def _window():
    from datetime import timedelta
    return timedelta(seconds=FIRST_WINDOW_SECONDS)


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
