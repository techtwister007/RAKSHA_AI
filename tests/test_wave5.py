"""Wave 5: project identity, signed versioned reports and their diff, needs-a-human, score,
exposure, secrets, drift, certificate, learning under probation, pre-merge, compliance pack, views.
Each test proves the property its "Done" line names, against real scans of the demo estate."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from raksha import compliance, premerge, reports, signdoc, views
from raksha.learning import Learning
from raksha.orchestrator import Session
from raksha.projects import Store, drift, surface

REPO = Path(__file__).parents[1]
ESTATE = REPO / "demo-targets" / "mixed-estate"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("RAKSHA_HOME", str(tmp_path / "home"))
    return tmp_path


def _copy(tmp_path, name="estate"):
    dst = tmp_path / name
    shutil.copytree(ESTATE, dst)
    return dst


def _run(root, name="mixed-estate"):
    s = Session()
    s.ingest_build_free(root, name=name)
    r = s.record_project_run(name)
    assert r["ok"], r
    return s, r


# ---- K1 identity -------------------------------------------------------------------------------

def test_same_project_same_id_across_paths_different_project_new_id(home):
    a = _copy(home, "a")
    b = _copy(home, "elsewhere/b")
    st = Store()
    p1 = st.identify(a, name="mixed-estate")
    p2 = st.identify(b, name="mixed-estate")
    assert p1.id == p2.id and len(p2.aliases) == 2
    other = home / "other"
    (other / "src").mkdir(parents=True)
    (other / "src" / "main.py").write_text("print(1)\n")
    p3 = st.identify(other, name="mixed-estate")            # same name, different project
    assert p3.id != p1.id


# ---- K2/K3/K4 versioned reports, diff, needs-human ---------------------------------------------

def test_versions_chain_and_diff_and_tamper(home):
    root = _copy(home)
    s, r1 = _run(root)
    props = root / "config" / "app.properties"
    props.write_text("db.url=x\n")                           # remove both secrets
    (root / "tool-py" / "srv.py").write_text("import socket\ns = socket.socket()\ns.bind(('', 1))\n")
    s2, r2 = _run(root)
    assert r1["project"] == r2["project"] and r2["version"] == 2
    st = s2.store()
    b2 = reports.load(st, r2["project"], 2)
    assert len(b2["diff"]["fixed"]) == 2 and not b2["diff"]["new"]   # secrets proven gone
    assert all(b2["versions_open"][k] == 2 for k in b2["diff"]["open"])
    assert any(a["category"] == "network-listener" for a in b2["drift"])      # K17
    assert all(s["rotated"] for s in b2["secrets"])                          # K19
    assert b2["needs_human"] and all(h["checklist"] for h in b2["needs_human"])
    ok, problems = reports.verify_chain(st, r2["project"])
    assert ok, problems
    # drop one finding from v1 by hand: v1 fails, and the chain breaks for v2
    d1 = st.dir(r2["project"]) / "reports" / "v1"
    body = json.loads((d1 / "report.json").read_text())
    body["findings"] = body["findings"][1:]
    (d1 / "report.json").write_text(json.dumps(body))
    ok2, problems2 = reports.verify_chain(st, r2["project"])
    assert not ok2 and any("v1" in p for p in problems2)


def test_new_finding_is_red_and_crash_not_refound_is_not_counted_fixed():
    prev = {"findings": [{"key": "k-crash", "evidence": "exploit-replay"},
                         {"key": "k-match", "evidence": "deterministic-match"}]}
    rows = [{"key": "k-new", "needs_human": None}]
    d = reports.diff(prev, rows)
    assert d["new"] == ["k-new"]
    assert d["fixed"] == ["k-match"] and d["not-refound"] == ["k-crash"]


def test_mark_done_is_rechecked_not_trusted(home):
    root = _copy(home)
    s, r = _run(root)
    st = s.store()
    b1 = reports.load(st, r["project"], 1)
    secret_key = next(h["key"] for h in b1["needs_human"]
                      if h["reason"] == "rotate-credential" and "password" in h["title"].lower())
    other_key = next(h["key"] for h in b1["needs_human"] if h["reason"] != "rotate-credential")
    st.mark_done(r["project"], secret_key, actor="owner")
    st.mark_done(r["project"], other_key, actor="owner")
    text = (root / "config" / "app.properties").read_text().splitlines()
    (root / "config" / "app.properties").write_text("\n".join(l for l in text if "password" not in l) + "\n")
    _s2, r2 = _run(root)
    b2 = reports.load(st, r["project"], 2)
    verdict = {m["key"]: m["closed"] for m in b2["marks_rechecked"]}
    assert verdict[secret_key] is True and verdict[other_key] is False


# ---- K16 score / K13 exposure / K15 certificate -----------------------------------------------

def test_score_breakdown_sums_and_null_below_floor():
    rows = [{"key": str(i), "title": "t", "severity": s, "state": "open"}
            for i, s in enumerate(["critical"] * 6 + ["high", "low"])]
    sc = reports.posture_score(rows, tier="mission-critical", files_scanned=5)
    assert round(sum(i["deduction"] for i in sc["breakdown"]), 3) == round(100 - sc["score"], 3)
    assert reports.posture_score(rows, tier=None, files_scanned=0)["score"] is None


def test_exposure_clock_stops_on_the_proving_run():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    hist = [{"created": t0.isoformat(), "findings": [{"key": "k", "severity": "critical"}]},
            {"created": (t0 + timedelta(days=10)).isoformat(), "findings": []}]
    ex = reports.exposure(hist, [], tier="mission-critical", now=t0 + timedelta(days=40))
    assert ex[0]["days"] == 10 and not ex[0]["open"]
    assert ex[0]["deadline_days"] == 3.5 and ex[0]["breached"]


def test_certificate_refused_with_open_critical_issued_when_clean(home):
    root = _copy(home)
    _s, r = _run(root)
    st = Store()
    assert not reports.issue_certificate(st, r["project"])["ok"]
    clean = home / "clean"
    (clean / "app").mkdir(parents=True)
    (clean / "app" / "main.py").write_text("def add(a, b):\n    return a + b\n")
    s2 = Session()
    s2.ingest_build_free(clean, name="clean-svc")
    r2 = s2.record_project_run("clean-svc")
    res = reports.issue_certificate(st, r2["project"])
    assert res["ok"], res
    ok, problems = signdoc.verify(res["path"], reports.CERT_STEM)
    assert ok, problems


# ---- K6 summary --------------------------------------------------------------------------------

def test_summary_marks_every_line_with_icon_and_word(home):
    root = _copy(home)
    _run(root)
    (root / "config" / "app.properties").write_text("x=1\n")
    _s, r = _run(root)
    b = reports.load(Store(), r["project"], 2)
    en = reports.summary_html(b, lang="en")
    hi = reports.summary_html(b, lang="hi")
    assert "✓" in en and "fixed" in en and "●" in en
    assert 'lang="hi"' in hi and "ठीक हुआ" in hi


# ---- K17 drift unit -----------------------------------------------------------------------------

def test_drift_ignores_moved_lines_flags_new_sites(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\nimport socket\ns.bind(('', 1))\n")
    s1 = surface(tmp_path)
    (tmp_path / "a.py").write_text("\n\nx = 1\nimport socket\ns.bind(('', 1))\n")    # moved
    assert drift(s1, surface(tmp_path)) == []
    (tmp_path / "b.py").write_text("import os\nos.system('ls')\n")
    alerts = drift(s1, surface(tmp_path))
    assert any(a["category"] == "privileged-call" and a["site"].startswith("b.py") for a in alerts)


# ---- K7-K11 learning ----------------------------------------------------------------------------

def test_lesson_needs_verified_cases_from_two_projects(home):
    L = Learning(Store())
    lid = L.propose_lesson("dangerous-call", "spawn_worker", source_project="P1", rationale="new framework")["id"]
    assert "spawn_worker" in L.active_calls("P1") and "spawn_worker" not in L.active_calls("P2")
    for _ in range(5):                                   # one project alone can never promote it
        L.record_outcome(lid, project="P1", finding_status="VERIFIED")
    assert L.state["lessons"][lid]["state"] == "probation"
    L.record_outcome(lid, project="P2", finding_status="CONFIRMED")     # not gate-verified: ignored
    assert L.state["lessons"][lid]["state"] == "probation"
    L.record_outcome(lid, project="P2", finding_status="VERIFIED")
    assert L.state["lessons"][lid]["state"] == "promoted"
    assert "spawn_worker" in L.active_calls("P3")


def test_false_positive_demotes_and_quarantines_source(home):
    L = Learning(Store())
    lid = L.propose_lesson("dangerous-call", "bad_call", source_project="EVIL", rationale="x")["id"]
    L.record_outcome(lid, project="P2", finding_status="VERIFIED", false_positive=True)
    assert L.state["lessons"][lid]["state"] == "demoted" and "EVIL" in L.state["quarantine"]
    lid2 = L.propose_lesson("dangerous-call", "other", source_project="P9", rationale="y")["id"]
    L.record_outcome(lid2, project="EVIL", finding_status="VERIFIED")
    assert not L.state["lessons"][lid2]["evidence"]       # quarantined source's evidence ignored


def test_rollback_restores_prior_behaviour(tmp_path, home):
    L = Learning(Store())
    lid = L.propose_lesson("dangerous-call", "launch_job", source_project="P1", rationale="r")["id"]
    for p in ("P1", "P2", "P3"):
        L.record_outcome(lid, project=p, finding_status="VERIFIED")
    (tmp_path / "x.py").write_text("launch_job('a')\n")
    assert surface(tmp_path, extra_privileged=L.active_calls("P1"))["privileged-call"]
    L.rollback(lid, actor="operator")
    assert not surface(tmp_path, extra_privileged=L.active_calls("P1"))["privileged-call"]


def test_guidelines_need_two_projects_and_a_named_approver(home):
    root_a = _copy(home, "a")
    _run(root_a, name="estate-a")
    root_b = _copy(home, "b")
    (root_b / "extra.py").write_text("x = 1\n")
    _run(root_b, name="estate-b")
    L = Learning(Store())
    gs = L.propose_guidelines()
    assert gs and all(len(g["projects"]) >= 2 for g in gs)
    gid = gs[0]["id"]
    assert not L.decide_guideline(gid, approver="", approve=True)["ok"]
    assert L.decide_guideline(gid, approver="Col. X", approve=True)["ok"]
    assert L.approved_guidelines()[0]["decided_by"] == "Col. X"


# ---- K20 pre-merge ------------------------------------------------------------------------------

def test_premerge_blocks_regression_and_approved_guideline(home):
    root = _copy(home)
    original = (root / "config" / "app.properties").read_text()
    _run(root)
    (root / "config" / "app.properties").write_text("x=1\n")
    _run(root)                                            # the secrets are now "fixed"
    (root / "config" / "app.properties").write_text(original)      # …and re-introduced
    r = premerge.check(root, name="mixed-estate")
    assert r["blocked"] and any("regression" in b["why"] for b in r["blocks"])


# ---- K28 compliance pack ------------------------------------------------------------------------

def test_compliance_pack_verifies_on_its_own(home):
    root = _copy(home)
    _run(root)
    (root / "config" / "app.properties").write_text("x=1\n")
    _run(root)
    out = home / "pack"
    res = compliance.build_pack(Store(), out, since="2000-01-01T00:00:00", until="2999-01-01T00:00:00")
    assert res["ok"] and res["documents"] == 2
    r = subprocess.run([sys.executable, "-I", str(out / "verify.py"), "--json"], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert all(v == "ok" for v in json.loads(r.stdout)["documents"].values())


# ---- K12/K14/K25/K26/K27 views -------------------------------------------------------------------

def test_views_render_only_the_record(home):
    root = _copy(home)
    _run(root)
    (root / "config" / "app.properties").write_text("x=1\n")
    s, r = _run(root)
    st = Store()
    assert views.mission_view(st)
    assert [v["version"] for v in views.heatmap(st)[0]["versions"]] == [1, 2]
    assert views.heatmap_at(st, "2000-01-01T00:00:00")[0]["state"] is None
    assert views.role_view(st, r["project"], "auditor")["chain_verified"]
    assert "patch_diff" in views.role_view(st, r["project"], "developer")["findings"][0]
    assert "error" in views.role_view(st, r["project"], "nobody")
    b2 = reports.load(st, r["project"], 2)
    assert views.alert(b2) is None                     # nothing new and serious
    assert "fixed" in views.digest(st, r["project"])["text"]
    L = Learning(st)
    assert views.team_scorecard(L, "Logistics IT", viewer_unit="Signals") is None
    assert views.team_scorecard(L, "Logistics IT", viewer_unit="HQ",
                                chain={"Logistics IT": ["HQ"]})["top"]


def test_before_after_splits_a_proven_patch():
    row = {"title": "t", "gate": {c: True for c in "abcde"},
           "patch_diff": "--- a/x.c\n+++ b/x.c\n@@ -1,2 +1,2 @@\n keep\n-old\n+new\n"}
    v = views.before_after(row)
    assert v["files"][0]["before"] == ["keep", "old"] and v["files"][0]["after"] == ["keep", "new"]
    assert v["gate_passed"]
