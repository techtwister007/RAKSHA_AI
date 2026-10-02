"""Tests for the scorecard.

Two things matter here. First, every number must be derived from the records, so that
what the jury sees is a measurement. Second, an unmeasured metric must read as
unmeasured (`None`), never as a flattering zero or a hundred -- volunteering the bound
is the whole posture.
"""

from __future__ import annotations

from raksha.finding import (
    GATE_ORDER,
    Finding,
    Frame,
    GateCheck,
    RepairLane,
    ReplayResult,
    Reproducer,
    Signature,
    utcnow,
)
from raksha.metrics import scorecard


def _finding(language: str, cwe: str, symbol: str, target: str = "demo") -> Finding:
    return Finding(
        oracle=f"{language}-oracle",
        bug_class=cwe,
        language=language,
        target=target,
        message=f"{cwe} in {symbol}",
        frames=[Frame(symbol=symbol, uri=f"src/{symbol}.x", line=10)],
    )


def _prove(f: Finding) -> Finding:
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r.sh"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    return f


def _fix(f: Finding, lane: RepairLane = RepairLane.TEMPLATE) -> Finding:
    f.mark_patched("--- a\n+++ b\n", lane)
    for check in GATE_ORDER:
        f.record_gate(check, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow()))
    f.verify()
    return f


def test_empty_run_reports_unmeasured_not_zero():
    """A run with no findings must not advertise 100% precision."""
    card = scorecard([]).as_dict()
    assert card["performance"]["findings_total"] == 0
    assert card["precision"]["reports_with_reproducer_pct"] is None
    assert card["precision"]["patches_surviving_differential_pct"] is None
    assert card["speed"]["median_time_to_pov_seconds"] is None
    assert card["resource"]["zero_inference_fix_pct"] is None


def test_precision_is_100_percent_on_reports_and_suppressed_count_is_visible():
    """The headline claim, recomputed from records -- plus the honest denominator."""
    proven = _prove(_finding("java", "CWE-917", "AuditLogger"))
    static_only = _finding("python", "CWE-89", "UserDao")   # no reproducer, suppressed

    card = scorecard([proven, static_only]).as_dict()
    assert card["precision"]["reports_with_reproducer_pct"] == 100.0
    assert card["precision"]["reports_without_reproducer"] == 0
    assert card["precision"]["unproven_findings_suppressed"] == 1
    assert card["performance"]["findings_total"] == 2
    assert card["performance"]["findings_reported"] == 1


def test_rejected_patch_shows_up_in_precision_not_hidden():
    """A gate rejection is a number we show, not one we bury."""
    f = _prove(_finding("c/c++", "CWE-122", "parse_header"))
    f.mark_patched("--- a\n+++ b\n", RepairLane.LLM)
    f.record_gate(GateCheck.COMPILES, True)
    f.record_gate(GateCheck.POV_DEAD, True)
    f.record_gate(GateCheck.DIFFERENTIAL_CORPUS, False,
                  detail="4 inputs changed output", quarantined_inputs=3)
    f.gate_failed("differential corpus")

    card = scorecard([f]).as_dict()
    assert card["precision"]["patches_surviving_differential_pct"] == 0.0
    assert card["precision"]["patches_rejected_by_gate"] == 1
    assert card["precision"]["quarantined_corpus_inputs"] == 3


def test_scalability_counts_languages_not_threads():
    findings = [
        _fix(_prove(_finding("java", "CWE-917", "AuditLogger"))),
        _fix(_prove(_finding("c/c++", "CWE-122", "parse_header"))),
        _fix(_prove(_finding("python", "CWE-78", "runner"))),
    ]
    card = scorecard(findings).as_dict()
    assert card["scalability"]["language_count"] == 3
    assert card["scalability"]["languages_covered"] == ["c/c++", "java", "python"]
    assert card["scalability"]["verified_per_language"] == {
        "c/c++": 1, "java": 1, "python": 1
    }


def test_resource_utilisation_tracks_the_zero_inference_share():
    """The escalation ladder only scores if we can show the cheap lane doing work."""
    template = _fix(_prove(_finding("java", "CWE-917", "A")), RepairLane.TEMPLATE)
    llm = _fix(_prove(_finding("java", "CWE-89", "B")), RepairLane.LLM)
    card = scorecard([template, llm]).as_dict()
    assert card["resource"]["zero_inference_fix_pct"] == 50.0
    assert card["resource"]["fixes_by_lane"] == {"LLM": 1, "TEMPLATE": 1}


def test_speed_medians_come_from_transition_timestamps():
    findings = [_fix(_prove(_finding("java", "CWE-917", f"S{i}"))) for i in range(3)]
    card = scorecard(findings).as_dict()
    assert card["speed"]["median_time_to_pov_seconds"] is not None
    assert card["speed"]["median_time_to_validated_patch_seconds"] is not None
    assert card["speed"]["samples"] == {"pov": 3, "patch": 3}


def test_functionality_separates_autonomous_from_awaiting_approval():
    """R3 autonomy and R2 sign-off are different numbers and must not be conflated."""
    autonomous = _fix(_prove(_finding("java", "CWE-917", "A")))
    approved = _fix(_prove(_finding("java", "CWE-89", "B")))
    approved.add_signature(Signature("k1", "Maj A", "sig", utcnow()))

    card = scorecard([autonomous, approved]).as_dict()
    assert card["functionality"]["zero_human_input_verified"] == 1
    assert card["functionality"]["awaiting_human_approval"] == 1
    assert card["functionality"]["full_loop_completions"] == 2


def test_report_only_is_counted_as_a_real_result():
    """No fix validated is still a delivered, honest outcome -- not a zero."""
    f = _prove(_finding("c/c++", "CWE-416", "free_node"))
    f.report_only("3 rounds exhausted, no candidate cleared the gate")
    card = scorecard([f]).as_dict()
    assert card["performance"]["report_only"] == 1
    assert card["performance"]["findings_reported"] == 1
    assert card["precision"]["reports_with_reproducer_pct"] == 100.0


def test_posture_badges_are_always_zero():
    card = scorecard([]).as_dict()
    assert card["posture"] == {"network_interfaces": 0, "cloud_calls": 0}


def test_inference_spent_on_a_rejected_patch_stays_visible():
    """Resource utilisation must count model calls that produced nothing.

    Regression: measuring lanes only over successful fixes let a rejected LLM candidate
    vanish, so a run that burned tokens and then fell back to a template reported
    "100% of fixes cost zero inference" with no hint of the spend.
    """
    f = _prove(_finding("java", "CWE-917", "AuditLogger"))

    f.mark_patched("--- a\n+++ b\n(llm)", RepairLane.LLM)
    f.record_gate(GateCheck.DIFFERENTIAL_CORPUS, False, detail="output changed")
    f.gate_failed("differential corpus")

    _fix(f, RepairLane.TEMPLATE)

    card = scorecard([f]).as_dict()
    assert card["resource"]["zero_inference_fix_pct"] == 100.0      # the fix was free
    assert card["resource"]["attempts_by_lane"] == {"LLM": 1, "TEMPLATE": 1}
    assert card["resource"]["inference_attempts"] == 1              # but we did pay
    assert card["resource"]["inference_attempts_without_a_fix"] == 1
    assert f.lane_history == [RepairLane.LLM, RepairLane.TEMPLATE]


def test_lane_history_rides_along_in_the_proof_block():
    f = _prove(_finding("java", "CWE-89", "UserDao"))
    f.mark_patched("--- a\n+++ b\n", RepairLane.RETRIEVAL)
    f.gate_failed("coverage dropped")
    _fix(f, RepairLane.LLM)
    assert f.proof_block()["repair"]["lane_history"] == ["RETRIEVAL", "LLM"]
