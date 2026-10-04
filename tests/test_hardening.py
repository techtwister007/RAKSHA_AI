"""Regression tests for the end-to-end hardening pass.

Each test pins a gap the audit found: a bypassable invariant, a gate check that failed open, a
differential that dropped error-path inputs, and scoring metrics the ledger promised but the
Scorecard did not emit. They are grouped by the criterion they protect.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from raksha import inference
from raksha.finding import (
    Finding, GateCheck, InvariantViolation, RepairLane, Status, Transition, utcnow,
)
from raksha.gate.differential import Canonicaliser, differential, preflight
from raksha.gate.runner import decide, run_gate
from raksha.gate.target import BuildResult, RunResult
from raksha.metrics import scorecard

from test_gate import FakeTarget, confirmed_finding, corpus


# ---------------------------------------------------------------- precision invariant (H1)

def test_a_forged_birth_state_is_refused():
    """A finding cannot be constructed into a reportable state; it must earn it."""
    for status in (Status.CONFIRMED, Status.VERIFIED, Status.REPORT_ONLY):
        with pytest.raises(InvariantViolation):
            Finding(oracle="o", bug_class="b", language="c", target="t", message="m",
                    _status=status)


def test_a_normal_finding_is_born_suspected():
    f = Finding(oracle="o", bug_class="b", language="c", target="t", message="m")
    assert f.status is Status.SUSPECTED and not f.is_reportable
    assert f.history and f.history[0].to_status is Status.SUSPECTED


def test_a_reconstructed_record_must_match_its_history():
    now = utcnow()
    good = [Transition(None, Status.SUSPECTED, now, "created"),
            Transition(Status.SUSPECTED, Status.CONFIRMED, now, "replayed")]
    f = Finding(oracle="o", bug_class="b", language="c", target="t", message="m",
                history=list(good), _status=Status.CONFIRMED)
    assert f.status is Status.CONFIRMED            # consistent reconstruction is allowed
    with pytest.raises(InvariantViolation):        # history says CONFIRMED, label says VERIFIED
        Finding(oracle="o", bug_class="b", language="c", target="t", message="m",
                history=list(good), _status=Status.VERIFIED)


# ---------------------------------------------------------------- CLEAN_REFUZZ fails closed (H2)

@dataclass
class NoRefuzzTarget(FakeTarget):
    """A capable target that simply cannot run a fresh campaign."""
    def can_refuzz(self) -> bool:
        return False


def test_clean_refuzz_fails_closed_when_the_target_cannot_fuzz():
    f = confirmed_finding()
    f.mark_patched("real", RepairLane.TEMPLATE)   # a genuinely correct patch
    verdict = run_gate(f, NoRefuzzTarget(), reproducer=b"HDR" + b"\xff" * 9, corpus=corpus(),
                       refuzz_seconds=1)
    assert not verdict.passed and verdict.failed_check is GateCheck.CLEAN_REFUZZ
    assert not verdict.refuzz_ran
    decide(f, verdict)
    assert f.status is not Status.VERIFIED        # never silently VERIFIED on an un-run campaign
    # and with the repair budget spent, it ends reported — not verified
    for _ in range(5):
        if f.status is Status.CONFIRMED:
            f.mark_patched("real", RepairLane.TEMPLATE)
            decide(f, run_gate(f, NoRefuzzTarget(), reproducer=b"HDR" + b"\xff" * 9,
                               corpus=corpus(), refuzz_seconds=1))
    assert f.status is Status.REPORT_ONLY


def test_clean_refuzz_runs_when_the_target_can_fuzz():
    f = confirmed_finding()
    f.mark_patched("real", RepairLane.TEMPLATE)
    verdict = run_gate(f, FakeTarget(), reproducer=b"HDR" + b"\xff" * 9, corpus=corpus(),
                       refuzz_seconds=1)
    assert verdict.passed and verdict.refuzz_ran
    decide(f, verdict)
    assert f.status is Status.VERIFIED


# ------------------------------------------------------ differential keeps error-path inputs (H3)

@dataclass
class ErrorPathTarget:
    """exit 2 on b'bad' (a validation reject, NOT a crash); the patch changes that output."""
    def build(self, patch_diff):
        return BuildResult(True, "patched" if patch_diff else "vulnerable", "ok")

    def run(self, build, data):
        if data == b"bad":
            msg = b"rejected: bad" if build.label == "vulnerable" else b"rejected: BAD-DIFFERENT"
            return RunResult(2, msg, b"")           # deterministic non-zero exit, no oracle abort
        return RunResult(0, b"ok", b"")


def test_preflight_keeps_a_deterministic_error_exit_as_comparable():
    t = ErrorPathTarget()
    pf = preflight(t, t.build(None), [b"bad", b"fine"], runs=3,
                   is_abort=lambda text: False)     # nothing is an oracle abort here
    assert set(pf.stable) == {0, 1} and pf.crashing == []   # the exit-2 input is NOT dropped


def test_differential_catches_a_changed_error_path():
    t = ErrorPathTarget()
    before, after = t.build(None), t.build("p")
    mism = differential(t, before, after, [b"bad"], [0], canon=Canonicaliser())
    assert mism and mism[0].index == 0             # the patch altered the error path — caught


# ---------------------------------------------------------------- resource metric (C1)

def _verified_with_lane(lane: RepairLane) -> Finding:
    f = confirmed_finding()
    f.mark_patched("real", lane)
    verdict = run_gate(f, FakeTarget(), reproducer=b"HDR" + b"\xff" * 9, corpus=corpus(),
                       refuzz_seconds=1)
    decide(f, verdict)
    assert f.status is Status.VERIFIED
    return f


@pytest.mark.parametrize("lane", [RepairLane.TEMPLATE, RepairLane.RETRIEVAL, RepairLane.MITIGATION])
def test_non_llm_lanes_are_zero_inference(lane):
    assert _verified_with_lane(lane).zero_inference is True


def test_llm_lane_is_not_zero_inference():
    f = confirmed_finding()
    f.mark_patched("real", RepairLane.LLM)
    assert f.zero_inference is False


def test_zero_inference_pct_counts_retrieval_and_mitigation():
    findings = [_verified_with_lane(RepairLane.TEMPLATE),
                _verified_with_lane(RepairLane.RETRIEVAL),
                _verified_with_lane(RepairLane.MITIGATION)]
    card = scorecard(findings, gpu_probe=lambda: None).as_dict()
    # all three fixes cost zero tokens, so the asset reads 100% — not 33% as the old bug gave
    assert card["resource"]["zero_inference_fix_pct"] == 100.0
    assert card["resource"]["inference_attempts"] == 0


# ---------------------------------------------------------------- scoring interface (C3/C4/C6/H1)

def test_posture_and_token_counters_are_live():
    inference.reset_counters()
    assert inference.egress_call_count() == 0 and inference.completion_tokens_used() == 0
    card = scorecard([], gpu_probe=lambda: None).as_dict()
    assert card["posture"]["cloud_calls"] == 0            # measured, not a constant
    assert card["resource"]["tokens_per_validated_patch"] is None   # no model fix → honestly None
    assert card["resource"]["vram"] is None               # no GPU probe → honestly absent


def test_cross_confirm_promotions_are_counted():
    f = confirmed_finding()
    f.merged_from = ["static-finding-id"]
    card = scorecard([f], gpu_probe=lambda: None).as_dict()
    assert card["precision"]["static_findings_promoted"] == 1


def test_speed_emits_time_to_first_finding_and_first_window():
    f = confirmed_finding()
    card = scorecard([f], gpu_probe=lambda: None).as_dict()
    assert card["speed"]["time_to_first_proven_finding_seconds"] is not None
    assert card["speed"]["findings_in_first_10min"] == 1
