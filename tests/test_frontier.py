"""The patch frontier: every candidate is gated, the passers are ranked by a documented total order,
and the chosen one earns its own confirming gate run before the finding is VERIFIED.

The simulated target is `test_gate.FakeTarget` with its patches keyed by diff text instead of by a
bare label, so two *passing* fixes of different size can be told apart by the frontier's cost axes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from raksha import autorepair
from raksha.autorepair import HELD_REASON, diff_cost, frontier_key, repair
from raksha.finding import GateCheck, RepairLane, Status
from raksha.repair import Candidate
from test_gate import REPRO, FakeTarget, confirmed_finding, corpus

SMALL = ("--- a/src/parser.c\n+++ b/src/parser.c\n@@ -142 +142 @@\n"
         "-    memcpy(buf, data, len);\n+    memcpy(buf, data, len < 16 ? len : 16);\n")
BIG = ("--- a/src/parser.c\n+++ b/src/parser.c\n@@ -130,2 +130,4 @@\n"
       "     int sum = 0;\n+    size_t cap = sizeof buf;\n+    if (len > (int) cap) len = (int) cap;\n"
       "     char buf[16];\n@@ -142 +144,2 @@\n-    memcpy(buf, data, len);\n+    /* bounded above */\n"
       "+    memcpy(buf, data, len);\n")
SMALL_LLM = SMALL.replace("len < 16 ? len : 16", "len > 16 ? 16 : len")   # same size, different lane
OVERFIT = ("--- a/src/parser.c\n+++ b/src/parser.c\n@@ -142 +142,2 @@\n"
           "+    if (len == 12) return -1;\n     memcpy(buf, data, len);\n")


@dataclass
class FrontierTarget(FakeTarget):
    """FakeTarget whose patches are real diff texts mapped onto its simulated variants."""

    variants: dict = field(default_factory=lambda: {SMALL: "real", BIG: "real", SMALL_LLM: "real",
                                                    OVERFIT: "overfit"})

    def build(self, patch_diff):
        if patch_diff is None:
            return super().build(None)
        return super().build(self.variants[patch_diff])


def _templates(monkeypatch, diffs):
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [(lambda d=d: d) for d in diffs])
    monkeypatch.setattr(autorepair, "_llm_candidates", lambda finding, root, client, n=3: [])


def _repair(f, t, **kw):
    return repair(f, t, root="/nonexistent", reproducer=REPRO, corpus=corpus(), use_model=False,
                  refuzz_seconds=1, **kw)


def test_the_total_order_is_hunks_then_lines_then_lane():
    small, big = diff_cost(SMALL), diff_cost(BIG)
    assert small["hunks"] == 1 and big["hunks"] == 2
    assert small["added_lines"] + small["removed_lines"] < big["added_lines"] + big["removed_lines"]
    e = lambda d, lane, rank=0: {**diff_cost(d), "lane": lane, "rank": rank}
    assert frontier_key(e(SMALL, "TEMPLATE")) < frontier_key(e(BIG, "TEMPLATE"))
    assert frontier_key(e(SMALL, "TEMPLATE")) < frontier_key(e(SMALL_LLM, "LLM"))
    assert frontier_key(e(SMALL, "MITIGATION")) > frontier_key(e(SMALL, "LLM"))


def test_the_smaller_passer_wins_and_earns_its_own_confirming_run(monkeypatch):
    """BIG is tried first and passes; SMALL passes second. The frontier picks SMALL, and because
    SMALL is already on the finding when the loop ends, its own verdict verifies it — no re-run."""
    _templates(monkeypatch, [BIG, SMALL])
    f = confirmed_finding()
    out = _repair(f, FrontierTarget())
    assert out.verified and out.frontier_size == 2 and out.lane is RepairLane.TEMPLATE
    assert f.patch_diff == SMALL
    chosen = [e for e in f.frontier if e["chosen"]]
    assert len(chosen) == 1 and chosen[0]["hunks"] == 1 and chosen[0]["rank"] == 1
    assert all(e["refuzz_variants"] == 24 and e["coverage_lines"] == 2 for e in f.frontier)
    # BIG passed, was held, then SMALL passed and stayed: two full gate runs, no third
    assert len(f.gate_history) == 10 and all(g.passed for g in f.gate_history)
    assert any(HELD_REASON in (t.reason or "") for t in f.history)


def test_a_held_passer_is_re_applied_and_re_gated_when_it_is_the_better_one(monkeypatch):
    """SMALL passes first and is held; BIG passes second and ends on the finding. The frontier
    chooses SMALL, so SMALL is re-applied and must earn all five again — gate_history shows both
    candidates' runs plus the confirming re-run."""
    _templates(monkeypatch, [SMALL, BIG])
    f = confirmed_finding()
    out = _repair(f, FrontierTarget())
    assert out.verified and f.patch_diff == SMALL and out.frontier_size == 2
    assert len(f.gate_history) == 15                        # SMALL, BIG, SMALL again
    assert f.repair_rounds == 3
    chosen = [e for e in f.frontier if e["chosen"]]
    assert chosen[0]["confirmed_on_rerun"] is True and chosen[0]["rank"] == 0
    statuses = [t.to_status for t in f.history]
    assert statuses == [Status.SUSPECTED, Status.CONFIRMED, Status.PATCHED, Status.CONFIRMED,
                        Status.PATCHED, Status.CONFIRMED, Status.PATCHED, Status.VERIFIED]
    held = [t for t in f.history if HELD_REASON in (t.reason or "")]
    assert len(held) == 2                                   # SMALL held, then BIG stepped aside
    assert f.gate[GateCheck.CLEAN_REFUZZ].passed             # the verdict on the record is the re-run's


def test_the_cheaper_lane_breaks_a_size_tie(monkeypatch):
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [lambda: SMALL])
    monkeypatch.setattr(autorepair, "_llm_candidates",
                        lambda finding, root, client, n=3: [Candidate(SMALL_LLM, RepairLane.LLM, model_version="m")])
    f = confirmed_finding()
    out = _repair(f, FrontierTarget())
    assert out.verified and out.lane is RepairLane.TEMPLATE and f.patch_diff == SMALL
    assert out.frontier_size == 2 and f.lane_history == [RepairLane.TEMPLATE, RepairLane.LLM, RepairLane.TEMPLATE]
    assert len(f.gate_history) == 15


def test_a_failure_after_a_held_passer_does_not_end_the_finding_report_only(monkeypatch):
    _templates(monkeypatch, [SMALL, OVERFIT])
    f = confirmed_finding()
    out = _repair(f, FrontierTarget())
    assert out.verified and f.patch_diff == SMALL and out.frontier_size == 1
    assert out.candidates_tried == 2
    failed = [g for g in f.gate_history if not g.passed]
    assert len(failed) == 1 and failed[0].check is GateCheck.CLEAN_REFUZZ
    assert len(f.gate_history) == 15                        # SMALL (5) + OVERFIT (5, fails last) + SMALL (5)


def test_frontier_off_restores_first_pass_wins(monkeypatch):
    _templates(monkeypatch, [BIG, SMALL])
    f = confirmed_finding()
    out = _repair(f, FrontierTarget(), frontier=False)
    assert out.verified and f.patch_diff == BIG and out.frontier_size == 1
    assert len(f.gate_history) == 5 and f.frontier[0]["chosen"] is True

    monkeypatch.setenv("RAKSHA_PATCH_FRONTIER", "0")
    f2 = confirmed_finding()
    out2 = _repair(f2, FrontierTarget())
    assert out2.verified and f2.patch_diff == BIG and len(f2.gate_history) == 5


def test_no_passer_still_ends_report_only(monkeypatch):
    _templates(monkeypatch, [OVERFIT])
    f = confirmed_finding()
    out = _repair(f, FrontierTarget())
    assert not out.verified and f.status is Status.REPORT_ONLY and out.frontier_size == 0
    assert f.frontier == []


def test_the_frontier_is_on_the_proof_block(monkeypatch):
    _templates(monkeypatch, [BIG, SMALL])
    f = confirmed_finding()
    _repair(f, FrontierTarget())
    block = f.proof_block()["assurance"]
    assert len(block["frontier"]) == 2 and sum(e["chosen"] for e in block["frontier"]) == 1
    assert "perf_delta" in block


@pytest.mark.parametrize("env,expected", [("1", True), ("0", False), ("off", False), ("", True)])
def test_the_env_knob(monkeypatch, env, expected):
    monkeypatch.setenv("RAKSHA_PATCH_FRONTIER", env)
    assert autorepair.frontier_enabled() is expected
    assert autorepair.frontier_enabled(True) is True and autorepair.frontier_enabled(False) is False
