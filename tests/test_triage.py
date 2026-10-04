"""The decision funnel: deterministic scoring, stable cascades, and a model that re-orders but
never vetoes."""

from __future__ import annotations

from types import SimpleNamespace

from raksha.finding import Finding, Frame
from raksha.harness.entrypoints import Entrypoint
from raksha.triage import (
    RankedItem,
    TriageItem,
    funnel,
    rank_with_triage_model,
    triage_score,
    _MODEL_FLOOR,
)


class MockClient:
    """Stand-in inference client returning fixed completions (shape copied from test_autorepair)."""

    def __init__(self, completions):
        self._c = completions
        self.config = SimpleNamespace(model_for=lambda role: "mock-triage-model")

    def complete(self, messages, *, role="triage", n=1, temperature=0.0, max_tokens=1024):
        return list(self._c)


def _finding(bug_class="CWE-121", severity="high", message="overflow in parse", reach="imported",
             structure=None, symbol="parse_record"):
    f = Finding(oracle="asan", bug_class=bug_class, language="c", target="t", message=message,
                severity=severity, frames=[Frame(symbol=symbol, uri="src/x.c", line=10)])
    f.reachability = reach
    f.structure = structure
    return f


# ---------------------------------------------------------------- triage_score

def test_score_is_in_unit_interval_and_deterministic():
    f = _finding()
    s1 = triage_score(f)
    s2 = triage_score(f)
    assert 0.0 <= s1 <= 1.0
    assert s1 == s2


def test_high_severity_reachable_sink_outranks_low_severity_not_imported():
    strong = _finding(severity="critical", message="system() command injection", reach="imported")
    weak = _finding(bug_class="CWE-200", severity="low", message="info leak", reach="not-imported",
                    symbol="helper")
    assert triage_score(strong) > triage_score(weak)


def test_structure_and_sink_each_raise_the_score():
    base = _finding(severity="medium", message="plain", reach="unknown", symbol="helper")
    with_sink = _finding(severity="medium", message="sql query built from input", reach="unknown",
                         symbol="helper")
    with_struct = _finding(severity="medium", message="plain", reach="unknown", symbol="helper",
                           structure={"path": ["source", "sink"]})
    assert triage_score(with_sink) > triage_score(base)
    assert triage_score(with_struct) > triage_score(base)


def test_history_hit_rate_moves_the_score():
    f = _finding()
    low = triage_score(f, hit_rates={"CWE-121": 0.0})
    high = triage_score(f, hit_rates={"CWE-121": 1.0})
    assert high > low


def test_scores_an_entrypoint_and_a_triage_item():
    ep = Entrypoint("c/c++", "src/p.c", "parse_packet", 3, "buf_len", 7.0,
                    signature="int parse_packet(const char* b, size_t n)")
    assert 0.0 <= triage_score(ep) <= 1.0
    item = TriageItem("site", {"severity": "critical", "sink": True, "reachability": "imported"})
    weak = TriageItem("site", {"severity": "low", "sink": False, "reachability": "not-imported"})
    assert triage_score(item) > triage_score(weak)


# ---------------------------------------------------------------- funnel

def test_funnel_counts_and_reduction_are_right():
    items = [_finding(severity=s) for s in
             ("critical", "critical", "high", "medium", "low", "low", "low", "low")]
    res = funnel(items, stages=[("coarse", 0.3, 100), ("fine", 0.5, 3)])
    assert res.stages[0]["entered"] == 8
    # every stage's survived count equals the next stage's entered count
    assert res.stages[0]["survived"] == res.stages[1]["entered"]
    assert res.stages[-1]["survived"] == len(res.kept)
    assert len(res.kept) <= 3
    assert res.reduction_ratio == round(len(res.kept) / 8, 6)


def test_funnel_is_deterministic_and_orders_best_first():
    items = [_finding(severity="low", symbol="helper"), _finding(severity="critical"),
             _finding(severity="medium", symbol="helper")]
    a = funnel(items, stages=[("keep", 0.0, 10)])
    b = funnel(items, stages=[("keep", 0.0, 10)])
    assert [triage_score(x) for x in a.kept] == [triage_score(x) for x in b.kept]
    scores = [triage_score(x) for x in a.kept]
    assert scores == sorted(scores, reverse=True)


def test_empty_funnel_reports_none_ratio():
    res = funnel([], stages=[("x", 0.5, 10)])
    assert res.kept == [] and res.reduction_ratio is None


# ---------------------------------------------------------------- model assist

def test_offline_fallback_is_pure_deterministic():
    items = [_finding(severity="low", symbol="helper"), _finding(severity="critical")]
    ranked = rank_with_triage_model(items, client=None)
    assert all(isinstance(r, RankedItem) for r in ranked)
    assert all(r.model is None for r in ranked)                 # model was not consulted
    assert ranked[0].deterministic >= ranked[1].deterministic   # best first
    assert ranked[0].score == ranked[0].deterministic


def test_model_blends_5050_and_reorders():
    strong = _finding(severity="critical")
    weak = _finding(severity="low", symbol="helper")
    # model loves the weak item and hates the strong one — it may reorder, within the floor
    ranked = rank_with_triage_model([strong, weak], client=MockClient(["0.0, 1.0"]))
    by_item = {id(r.item): r for r in ranked}
    rs, rw = by_item[id(strong)], by_item[id(weak)]
    assert rs.model == 0.0 and rw.model == 1.0
    # blended = 0.5*det + 0.5*model, but floored at 0.5*det
    assert abs(rw.score - (0.5 * rw.deterministic + 0.5 * 1.0)) < 1e-9


def test_model_can_never_drop_an_item_below_the_floor():
    strong = _finding(severity="critical")          # high deterministic score
    weak = _finding(severity="low", symbol="helper")
    ranked = rank_with_triage_model([strong, weak], client=MockClient(["0.0, 0.0"]))
    for r in ranked:
        assert r.score >= _MODEL_FLOOR * r.deterministic - 1e-9   # never vetoed below the floor


def test_bad_model_reply_degrades_to_deterministic():
    items = [_finding(severity="critical"), _finding(severity="low", symbol="helper")]
    ranked = rank_with_triage_model(items, client=MockClient(["sorry, I cannot comply"]))
    assert all(r.model is None for r in ranked)      # unparseable -> deterministic fallback
    assert ranked[0].deterministic >= ranked[1].deterministic
