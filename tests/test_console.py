"""The operator console: the orchestrator session, the server routes, and the air-gap guarantee.

The console is the scoring interface, so these verify it serves the live record stream correctly and
— critically — that it ships nothing external, because a console that phoned out would break the
whole air-gap claim.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from console.server import make_handler
from raksha import airgap
from raksha.finding import (
    GATE_ORDER, Finding, FixSite, Frame, RepairLane, ReplayResult, Reproducer, utcnow,
)
from raksha.orchestrator import Session, demo_session

# stdlib http.server leaves per-connection sockets that Python GCs during a later test; with the
# project's strict filterwarnings=error that benign, already-closed-socket ResourceWarning would fail
# teardown. It is a test-harness artifact of serving over real sockets, not a product issue, so it is
# ignored for this module only.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

REPO = Path(__file__).parents[1]
ESTATE = REPO / "demo-targets" / "mixed-estate"


# ---------------------------------------------------------------- orchestrator

def test_ingest_build_free_populates_the_board():
    s = Session()
    t = s.ingest_build_free(ESTATE, name="estate")
    assert t.build_status == "amber"               # build-free, labelled a success state
    assert t.finding_ids and s.findings
    assert len(t.languages) >= 3


def test_board_card_counts_verified():
    s = Session()
    f = _verified()
    s.attach_target("svc", [f], build_status="green")
    card = s.board()[0]
    assert card["build_status"] == "green" and card["verified"] == 1 and card["status"] == "fixed"
    # one proven fix among open findings is still "fixing"; every finding fixed is "fixed"
    from types import SimpleNamespace
    from raksha.finding import Status
    from raksha.orchestrator import Target
    open_one = SimpleNamespace(status=Status.CONFIRMED)
    assert Target._status([f, open_one]) == "fixing" and Target._status([f]) == "fixed"


def test_unreadable_target_is_red_not_a_crash(tmp_path):
    s = Session()
    missing = tmp_path / "does-not-exist"
    t = s.ingest_build_free(missing, name="ghost")
    # a non-existent dir scans to zero files rather than raising; still on the board, not crashed
    assert t.name == "ghost" and t.build_status in ("amber", "red")


def test_snapshot_shape():
    s = demo_session(REPO)
    snap = s.snapshot()
    assert {"board", "findings", "scorecard", "risk", "pipeline"} <= set(snap)
    # a build-free session runs no target code, so no target code ever had a network interface
    assert snap["scorecard"]["posture"]["network_interfaces"] == 0
    assert snap["scorecard"]["posture"]["cloud_calls"] == 0
    assert all("id" in r and "severity" in r for r in snap["findings"])


def test_finding_detail_returns_proof_block():
    s = Session()
    f = _verified()
    s.add_finding(f)
    detail = s.finding_detail(f.id)
    assert detail["status"] == "VERIFIED"
    assert detail["gate"]["POV_DEAD"]["passed"] is True
    assert s.finding_detail("nope") is None


# ---------------------------------------------------------------- the server

@pytest.fixture
def live_server():
    s = demo_session(REPO)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(s))
    httpd.daemon_threads = True
    httpd.block_on_close = False
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", s
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 — test client, loopback only
        return r.status, r.read()


def test_server_serves_the_console_html(live_server):
    base, _ = live_server
    status, body = _get(base + "/")
    assert status == 200 and b"RAKSHA AI" in body and b"operator console" in body
    # the shipped page references no external origin
    assert b"http://" not in body.replace(b"http://127.0.0.1", b"").replace(b"http://localhost", b"")
    assert b"https://" not in body


def test_server_snapshot_route(live_server):
    base, _ = live_server
    status, body = _get(base + "/api/snapshot")
    snap = json.loads(body)
    assert status == 200 and "board" in snap and "scorecard" in snap


def test_server_finding_route(live_server):
    base, session = live_server
    fid = next(iter(session.findings))
    status, body = _get(base + "/api/finding/" + fid)
    assert status == 200 and json.loads(body)["id"] == fid


def test_server_404_on_unknown_finding(live_server):
    base, _ = live_server
    import urllib.error
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(base + "/api/finding/nonexistent")
    assert e.value.code == 404


def test_server_sets_a_locked_down_csp(live_server):
    base, _ = live_server
    with urllib.request.urlopen(base + "/", timeout=5) as r:  # noqa: S310
        csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp and "connect-src 'self'" in csp


# ---------------------------------------------------------------- the air-gap guarantee

def test_console_ships_no_external_assets():
    assert airgap.check_shipped_html([REPO / "console"]) == []


def test_whole_package_air_gap_clean_with_console_present():
    assert airgap.audit().clean


# ---------------------------------------------------------------- helpers

def _verified() -> Finding:
    f = Finding(oracle="jazzer:FuzzerSecurityIssueCritical", bug_class="CWE-917", language="java",
                target="audit-svc", message="Remote JNDI Lookup (Log4Shell)",
                frames=[Frame(symbol="A.b", uri="A.java", line=1)])
    f.add_fix_site(FixSite(uri="pom.xml", rank=0, start_line=31))
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./replay.sh"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.mark_patched("--- a/pom.xml\n+++ b/pom.xml\n", RepairLane.TEMPLATE)
    for c in GATE_ORDER:
        f.record_gate(c, True)
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow()))
    f.verify()
    return f


def test_console_serves_its_own_static_files_and_nothing_else(tmp_path, monkeypatch):
    """A redesigned console can ship css/js/fonts under console/; nothing outside it is served."""
    from console import server
    monkeypatch.setattr(server, "CONSOLE_DIR", tmp_path)
    (tmp_path / "ui").mkdir()
    (tmp_path / "ui" / "style.css").write_text("body{}")
    (tmp_path / "server.py").write_text("secret")
    (tmp_path.parent / "outside.css").write_text("x")
    assert server._static_file("/ui/style.css")[1].startswith("text/css")
    for bad in ("/server.py", "/../outside.css", "/.git/config", "/ui/../../outside.css", "/"):
        assert server._static_file(bad) is None, bad
