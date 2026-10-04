"""The benchmark harness: aggregation, the report, and (opt-in) a real run of the deep cases.

The aggregation and report are pure and fast; they run in the normal suite over synthetic findings.
The real multi-language run is guarded (RAKSHA_RUN_BENCH=1) since it needs gcc/python/maven.
"""

from __future__ import annotations

import os

import pytest

from raksha.benchmark import BenchReport, CaseResult, run_cases
from raksha.finding import (
    DETERMINISTIC_MATCH, GATE_ORDER, Finding, FixSite, Frame, RepairLane, ReplayResult,
    Reproducer, utcnow,
)


def _verified(name="svc", lang="python", lane=RepairLane.TEMPLATE) -> Finding:
    f = Finding(oracle="o", bug_class="CWE-78", language=lang, target=name, message="m",
                frames=[Frame(symbol="s", uri="a", line=1)])
    f.add_fix_site(FixSite(uri="a", rank=0, start_line=1))
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.mark_patched("--- a\n+++ b\n", lane)
    for c in GATE_ORDER:
        f.record_gate(c, True)
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow()))
    f.verify()
    return f


def _match_confirmed(lang="go") -> Finding:
    f = Finding(oracle="osv:version-match", bug_class="CWE-1104", language=lang, target="dep",
                message="vulnerable dep", frames=[Frame(symbol="pkg", uri="go.mod", line=3)])
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["raksha", "match"], kind=DETERMINISTIC_MATCH))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    return f


def test_aggregates_count_fixes_languages_and_evidence():
    report = BenchReport(results=[
        CaseResult.from_finding("a", _verified(lang="python")),
        CaseResult.from_finding("b", _verified(lang="c/c++")),
        CaseResult.from_finding("c", _match_confirmed(lang="go")),
    ])
    a = report.aggregates()
    assert a["ran"] == 3 and a["verified_fixed"] == 2 and a["reported"] == 3
    assert a["language_count"] == 3
    assert a["evidence"] == {"exploit_replay": 2, "deterministic_match": 1}
    assert a["zero_inference_fix_pct"] == 100.0        # both fixes are template-lane


def test_report_only_counts_as_reported_not_fixed():
    f = _match_confirmed()
    f.report_only("no patch validated")
    a = BenchReport(results=[CaseResult.from_finding("x", f)]).aggregates()
    assert a["report_only"] == 1 and a["verified_fixed"] == 0 and a["reported"] == 1


def test_errors_are_recorded_not_fatal():
    def boom():
        raise RuntimeError("nope")
    report = run_cases([("ok", lambda: _verified()), ("bad", boom)])
    a = report.aggregates()
    assert a["errors"] == 1 and a["ran"] == 1


def test_markdown_states_methodology_and_shows_losses():
    report = BenchReport(results=[
        CaseResult.from_finding("win", _verified()),
        CaseResult.error("lost", "runner raised: toolchain missing"),
    ])
    md = report.markdown()
    assert "Methodology" in md and "borrowed" in md
    assert "not a statistical security fix-rate" in md
    assert "Losses, shown beside the wins" in md and "lost" in md
    assert "100%" in md  # precision statement


def test_markdown_handles_a_clean_sweep_with_the_caveat():
    md = BenchReport(results=[CaseResult.from_finding("a", _verified())]).markdown()
    assert "None on this set" in md and "small curated set" in md


def test_third_party_register_exists():
    import pathlib
    reg = pathlib.Path(__file__).parents[1] / "THIRD_PARTY.md"
    assert reg.exists() and "Apache-2.0" in reg.read_text() and "SARIF" in reg.read_text()


@pytest.mark.skipif(os.environ.get("RAKSHA_RUN_BENCH") != "1",
                    reason="set RAKSHA_RUN_BENCH=1 to run the real multi-language benchmark")
def test_real_benchmark_runs_all_deep_cases():
    from raksha.benchmark import deep_cases
    report = run_cases(deep_cases())
    a = report.aggregates()
    assert a["verified_fixed"] >= 2 and a["language_count"] >= 2


def test_negative_controls_draw_no_false_positives():
    # the precision number the report publishes is measured here; a rule that starts firing on the
    # clean estate fails CI instead of silently changing a published figure
    from raksha.benchmark import NEGATIVE_CONTROLS, negative_controls
    rep = BenchReport()
    negative_controls(rep)
    assert rep.negative_controls == len(NEGATIVE_CONTROLS) and rep.false_positives == 0, rep.false_positive_notes


def test_languages_exclude_lanes():
    rep = BenchReport(results=[
        CaseResult("a", "any", "CWE-798", "CONFIRMED", False, False, None, None, None, DETERMINISTIC_MATCH),
        CaseResult("b", "api", "CWE-862", "CONFIRMED", False, False, None, None, None, DETERMINISTIC_MATCH),
        CaseResult("c", "go", "CWE-444", "CONFIRMED", False, False, None, None, None, DETERMINISTIC_MATCH)])
    assert rep.aggregates()["languages"] == ["go"]
