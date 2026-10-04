"""Wave 3 console: operator actions (F7), exports (F12), two voices (F13), lane trust (F14),
bilingual brief (F10), event narration (F1), estate map (F9), and the token-guarded write routes."""
from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from console.server import make_handler
from raksha import console_api
from raksha.finding import (GATE_ORDER, Finding, FixSite, Frame, RepairLane, ReplayResult,
                            Reproducer, Status, utcnow)
from raksha.orchestrator import Session

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
REPO = Path(__file__).parents[1]
C_TARGET = REPO / "demo-targets" / "c-nolibfuzzer"


def _verified(session):
    s = session
    f = Finding(oracle="asan:AddressSanitizer", bug_class="CWE-121", language="c", target="svc",
                message="stack overflow", severity="high", frames=[Frame(symbol="f", uri="s.c", line=10)])
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 40, ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.add_fix_site(FixSite(uri="s.c", rank=0, start_line=10)); f.confirm()
    f.mark_patched("--- a/s.c\n+++ b/s.c\n@@\n-a\n+b\n", RepairLane.TEMPLATE)
    for c in list(GATE_ORDER): f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow())); f.verify()
    s.add_finding(f)
    return f


# ---- F7 operator actions on the Session -------------------------------------------------------

def test_approve_records_and_needs_verified():
    s = Session(); f = _verified(s)
    r = s.approve(f.id, actor="maj.rao", reason="cleared for staging")
    assert r["ok"] and f.operator_actions[-1]["actor"] == "maj.rao"
    other = Finding(oracle="o", bug_class="CWE-78", language="python", target="t", message="m")
    s.add_finding(other)
    assert s.approve(other.id, actor="x")["ok"] is False      # only a VERIFIED fix


def test_reject_demotes_and_needs_reason():
    s = Session(); f = _verified(s)
    assert s.reject(f.id, actor="x", reason="")["ok"] is False
    r = s.reject(f.id, actor="x", reason="changes an API we must keep")
    assert r["ok"] and "demoted" in r


def test_false_positive_marks_without_changing_status():
    s = Session(); f = _verified(s)
    assert s.mark_false_positive(f.id, actor="x", reason="test fixture, not production")["ok"]
    assert f.disputed and f.status is Status.VERIFIED          # dispute recorded; gate still owns status
    assert console_api.lane_trust([f])["asan"]["disputed"] == 1


def test_actions_appear_in_the_event_stream():
    s = Session(); f = _verified(s)
    s.approve(f.id, actor="col.n", reason="go")
    kinds = [e["kind"] for e in s.events]
    assert "operator_approved" in kinds
    narrated = console_api.event_log(s)
    assert any("col.n approved" in n["text"] for n in narrated)


# ---- F13 two voices, F14 lane trust -----------------------------------------------------------

def test_two_voices_agree_on_facts():
    s = Session(); f = _verified(s)
    v = s.two_voices(f.id)
    assert v["staff"]["bug_class"] == v["engineer"]["bug_class"] == "CWE-121"
    assert v["staff"]["where"] == v["engineer"]["where"]
    assert "proven" in v["staff"]["action"].lower() or "rollback" in v["staff"]["action"].lower()
    assert "COMPILES" in v["engineer"]["gate"]


# ---- F1 narration -----------------------------------------------------------------------------

def test_narrate_covers_the_pipeline_and_drops_noise():
    assert console_api.narrate({"kind": "checkpoint"}) is None
    g = console_api.narrate({"kind": "candidate_gated", "target": "t", "round": 2, "lane": "LLM",
                             "passed": False, "failed_check": "POV_DEAD", "reason": "still fires"})
    assert g["level"] == "warn" and "rejected at pov dead" in g["text"]
    ok = console_api.narrate({"kind": "finding_status", "target": "t", "status": "VERIFIED",
                              "bug_class": "CWE-121", "lane": "template"})
    assert ok["level"] == "ok" and "VERIFIED" in ok["text"]


# ---- F10 bilingual brief ----------------------------------------------------------------------

def test_brief_is_bilingual_and_hindi_keeps_the_facts():
    s = Session(); f = _verified(s)
    b = s.commanders_brief(f.id)
    assert set(b["en"]) == {"plain", "jssd"} and set(b["hi"]) == {"plain", "jssd"}
    assert "CWE-121" in b["hi"]["jssd"] and "s.c:10" in b["hi"]["jssd"]   # facts verbatim
    assert "कमांडर ब्रीफ" in b["hi"]["jssd"]                               # prose translated


# ---- F12 exports ------------------------------------------------------------------------------

def test_csv_and_xlsx_and_pdf_exports():
    s = Session(); _verified(s)
    rows = console_api.findings_csv(s).splitlines()
    assert rows[0].startswith("id,severity") and len(rows) == 2
    x = console_api.findings_xlsx(s)
    z = zipfile.ZipFile(io.BytesIO(x))
    assert z.testzip() is None and "xl/worksheets/sheet1.xml" in z.namelist()
    pdf = console_api.brief_pdf("1. Subject. Test (CWE-121).\nRESTRICTED")
    assert pdf.startswith(b"%PDF-1.4") and b"%%EOF" in pdf


# ---- the server: token-guarded writes, exports, routes ----------------------------------------

@pytest.fixture
def live():
    s = Session(); f = _verified(s)
    handler = make_handler(s, token="test-token")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True; httpd.block_on_close = False
    th = threading.Thread(target=httpd.serve_forever, daemon=True); th.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", s, f
    httpd.shutdown(); httpd.server_close(); th.join(timeout=5)


def _req(url, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 — loopback test client
        return r.status, r.read(), dict(r.headers)


def test_index_injects_the_token_and_serves_app_js(live):
    base, _, _ = live
    _, body, _ = _req(base + "/")
    assert b"test-token" in body and b"__RAKSHA_TOKEN__" not in body
    st, js, hdr = _req(base + "/app.js")
    assert st == 200 and b"RAKSHA operator console" in js and "javascript" in hdr["Content-Type"]


def test_post_requires_the_token(live):
    base, _, f = live
    with pytest.raises(urllib.error.HTTPError) as e:
        _req(base + "/api/action/approve", "POST", {"finding": f.id}, {"Content-Type": "application/json"})
    assert e.value.code == 403


def test_post_action_with_token_records_it(live):
    base, s, f = live
    st, body, _ = _req(base + "/api/action/approve", "POST", {"finding": f.id, "actor": "op", "reason": "go"},
                       {"Content-Type": "application/json", "X-RAKSHA-Token": "test-token"})
    assert st == 200 and json.loads(body)["ok"]
    assert f.operator_actions[-1]["action"] == "approved"


def test_export_routes(live):
    base, _, f = live
    st, body, hdr = _req(base + "/api/export/findings.csv")
    assert st == 200 and b"id,severity" in body and "attachment" in hdr["Content-Disposition"]
    st, body, hdr = _req(base + "/api/export/findings.xlsx")
    assert st == 200 and body[:2] == b"PK"
    st, body, hdr = _req(base + f"/api/export/brief/{f.id}.pdf")
    assert st == 200 and body.startswith(b"%PDF")


def test_voices_and_labels_routes(live):
    base, _, f = live
    st, body, _ = _req(base + "/api/voices/" + f.id)
    assert st == 200 and json.loads(body)["staff"]["bug_class"] == "CWE-121"
    st, body, _ = _req(base + "/api/labels")
    assert st == 200 and "Mission Board" in json.loads(body)


def test_console_still_ships_no_external_assets():
    from raksha import airgap
    assert airgap.check_shipped_html([REPO / "console"]) == []
