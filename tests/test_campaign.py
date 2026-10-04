"""B1: the campaign loop — many proven fixes on one target, bounded by budget."""
from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from raksha import orchestrator
from raksha.finding import Finding, Reproducer, ReplayResult, FixSite, GateCheck, RepairLane, Status, utcnow
from raksha.orchestrator import Session

HAVE_GCC = shutil.which("gcc") is not None
C_TARGET = Path(__file__).parents[1] / "demo-targets" / "c-nolibfuzzer"


def _verified(sig_symbol, patch="--- a/s.c\n+++ b/s.c\n@@\n-a\n+b\n"):
    """A finding driven to VERIFIED, with a distinct signature via its top frame symbol."""
    from raksha.finding import Frame
    f = Finding(oracle="asan", bug_class="CWE-121", language="c", target="t", message="m",
                frames=[Frame(symbol=sig_symbol, uri="src/s.c", line=10)])
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 40, ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.add_fix_site(FixSite(uri="src/s.c", rank=0, start_line=10)); f.confirm()
    f.mark_patched(patch, RepairLane.TEMPLATE)
    for c in list(GateCheck): f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow())); f.verify()
    return f


def test_campaign_loops_until_clean_applying_each_fix(tmp_path, monkeypatch):
    """Two distinct bugs are found in sequence; each proven fix is applied to the working tree
    before the next round; the loop stops when a round finds nothing."""
    src = tmp_path / "t"; src.mkdir(); (src / "s.c").write_text("int main(){return 0;}\n")
    scripted = [_verified("bug_a"), _verified("bug_b")]
    calls = {"n": 0}

    def fake_dispatch(root):
        i = calls["n"]; calls["n"] += 1
        if i < len(scripted):
            f = scripted[i]
            return SimpleNamespace(found=True, finding=f, crashing_input=b"A" * 40,
                                   target=SimpleNamespace(source_root=root))
        return SimpleNamespace(found=False, finding=None, note="clean")

    monkeypatch.setattr(orchestrator, "_dispatch_autofuzz", fake_dispatch)
    monkeypatch.setattr("raksha.autorepair.repair", lambda f, *a, **k: None)  # findings arrive pre-verified
    monkeypatch.setattr(Session, "_apply_to_tree", staticmethod(lambda diff, tree: True))

    s = Session()
    t = s.ingest_campaign(src, name="t", max_bugs=6)
    assert t.name == "t" and len(t.finding_ids) == 2
    assert all(s.findings[i].status is Status.VERIFIED for i in t.finding_ids)
    assert calls["n"] == 3   # two finds + one clean round that ends the campaign


def test_campaign_stops_when_a_bug_cannot_be_fixed(tmp_path, monkeypatch):
    """A report-only finding (no proven patch) ends the campaign rather than re-finding it forever."""
    src = tmp_path / "t"; src.mkdir(); (src / "s.c").write_text("x\n")
    f = Finding(oracle="asan", bug_class="CWE-121", language="c", target="t", message="m")
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow())); f.confirm()
    f.report_only("no candidate cleared the gate")

    def fake_dispatch(root):
        return SimpleNamespace(found=True, finding=f, crashing_input=b"x",
                               target=SimpleNamespace(source_root=root))
    monkeypatch.setattr(orchestrator, "_dispatch_autofuzz", fake_dispatch)
    monkeypatch.setattr("raksha.autorepair.repair", lambda f, *a, **k: None)
    s = Session()
    t = s.ingest_campaign(src, name="t")
    assert len(t.finding_ids) == 1 and s.findings[t.finding_ids[0]].status is Status.REPORT_ONLY


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_campaign_on_the_single_bug_c_demo_verifies_one_then_stops():
    s = Session()
    t = s.ingest_campaign(C_TARGET, name="c-demo", corpus=[b"\x01\x04abcd", b"\x02zz", b"\x01\x02ab"])
    verified = [s.findings[i] for i in t.finding_ids if s.findings[i].status is Status.VERIFIED]
    assert len(verified) >= 1 and verified[0].reproducer.minimised


def test_e2_parallel_ingest_matches_serial():
    """E2: ingesting several targets concurrently gives the same findings as serial."""
    from raksha.orchestrator import Session
    roots = [C_TARGET.parent / "mixed-estate", C_TARGET.parent / "java-log4shell"]
    roots = [r for r in roots if r.exists()]
    a = Session()
    for r in roots:
        a.ingest_build_free(r)
    b = Session(); b.ingest_build_free_many(roots)
    assert sorted(f.dedup_key() for f in a.findings.values()) == sorted(f.dedup_key() for f in b.findings.values())


def test_e4_change_report_is_stable_across_an_unchanged_rescan():
    """E4: continuous mode — re-scanning an unchanged estate reports nothing new or gone."""
    from raksha.orchestrator import Session
    est = C_TARGET.parent / "mixed-estate"
    a = Session(); a.ingest_build_free(est); prev = a.snapshot()
    b = Session(); b.ingest_build_free(est)
    d = b.changes_since(prev)
    assert d["summary"]["new"] == 0 and d["summary"]["fixed_or_gone"] == 0 and d["summary"]["carried"] > 0


def test_campaign_budget_spent_reports_what_it_found(tmp_path, monkeypatch):
    """E3: a target that keeps yielding bugs stops at its budget and still reports what it found."""
    import itertools
    src = tmp_path / "t"; src.mkdir(); (src / "s.c").write_text("x\n")
    counter = itertools.count()
    clock = {"t": 0.0}

    def fake_dispatch(root):
        clock["t"] += 10.0                       # every round costs 10 "seconds"
        return SimpleNamespace(found=True, finding=_verified(f"bug_{next(counter)}"),
                               crashing_input=b"A" * 40, target=SimpleNamespace(source_root=root))

    monkeypatch.setattr(orchestrator, "_dispatch_autofuzz", fake_dispatch)
    monkeypatch.setattr("raksha.autorepair.repair", lambda f, *a, **k: None)
    monkeypatch.setattr(Session, "_apply_to_tree", staticmethod(lambda diff, tree: True))
    import time as _t
    monkeypatch.setattr(_t, "monotonic", lambda: clock["t"])
    s = Session()
    t = s.ingest_campaign(src, name="t", max_bugs=50, budget_s=25)
    assert 1 <= len(t.finding_ids) < 50
    assert "budget" in t.note and f"{len(t.finding_ids)} finding" in t.note


def test_campaign_killed_mid_run_resumes_with_findings_so_far(tmp_path, monkeypatch):
    """E1: kill the run during round three; resume() restores the target and both proven findings."""
    src = tmp_path / "t"; src.mkdir(); (src / "s.c").write_text("x\n")
    calls = {"n": 0}

    def fake_dispatch(root):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt("operator pulled the plug")
        return SimpleNamespace(found=True, finding=_verified(f"bug_{calls['n']}"),
                               crashing_input=b"A" * 40, target=SimpleNamespace(source_root=root))

    monkeypatch.setattr(orchestrator, "_dispatch_autofuzz", fake_dispatch)
    monkeypatch.setattr("raksha.autorepair.repair", lambda f, *a, **k: None)
    monkeypatch.setattr(Session, "_apply_to_tree", staticmethod(lambda diff, tree: True))
    journal = tmp_path / "run.jsonl"
    s = Session(); s.open_journal(journal)
    with pytest.raises(KeyboardInterrupt):
        s.ingest_campaign(src, name="t", max_bugs=6)
    r = Session.resume(journal)
    (t,) = [x for x in r.targets if x.name == "t"]
    assert len(t.finding_ids) == 2
    assert all(r.findings[i].status is Status.VERIFIED for i in t.finding_ids)
