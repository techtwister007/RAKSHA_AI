"""G5: each finding's record shows its hypothesis → experiment → observation → conclusion cycles."""
from __future__ import annotations

from raksha.brief import jssd_brief
from raksha.finding import (Finding, FixSite, Frame, GateCheck, RepairLane, Reproducer, ReplayResult,
                            Status, utcnow)
from raksha.method import cycles


def _confirmed():
    f = Finding(oracle="asan", bug_class="CWE-121", language="c", target="svc", message="overflow",
                severity="high", frames=[Frame(symbol="f", uri="src/s.c", line=10)])
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 40, ["./r"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature="sig1"))
    f.add_fix_site(FixSite(uri="src/s.c", rank=0, start_line=10)); f.confirm()
    return f


def test_suspected_says_no_experiment_ran():
    f = Finding(oracle="cpg:x", bug_class="CWE-78", language="python", target="t", message="path")
    (c,) = cycles(f)
    assert c["experiment"] is None and "unproven" in c["conclusion"]


def test_a_rejected_round_then_a_verified_round():
    f = _confirmed()
    f.mark_patched("--- a/src/s.c\n+++ b/src/s.c\n@@\n-a\n+b\n", RepairLane.LLM)
    f.record_gate(GateCheck.COMPILES, True, detail="ok")
    f.record_gate(GateCheck.POV_DEAD, False, detail="reproducer still fires")
    f.gate_failed("reproducer still fires")
    f.mark_patched("--- a/src/s.c\n+++ b/src/s.c\n@@\n-a\n+c\n", RepairLane.TEMPLATE)
    for ch in GateCheck:
        f.record_gate(ch, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow())); f.verify()
    cs = cycles(f)
    assert cs[0]["conclusion"].startswith("supported") and "sig1" in cs[0]["observation"]
    r1, r2 = cs[1], cs[2]
    assert "LLM" in r1["hypothesis"] and r1["conclusion"].startswith("refuted at POV_DEAD")
    assert "TEMPLATE" in r2["hypothesis"] and r2["conclusion"] == "supported: all five checks passed"
    assert f.proof_block()["method"] == cs
    assert f.status is Status.VERIFIED                       # narrative only


def test_brief_carries_the_method_line():
    f = _confirmed()
    b = jssd_brief(f)
    assert "Method.  Each claim was tested as a hypothesis" in b
    assert "4.   Recommendation." in b
