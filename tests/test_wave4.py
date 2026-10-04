"""Wave 4: the says-no beat (J1), intake (J2), egress counter (J6), verifier media (J7),
internal-CERT advisory (J8), time-lapse (J9). Each proves the mechanism, not a mock of it."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from raksha.finding import (Finding, FixSite, Frame, GATE_ORDER, RepairLane,
                            Reproducer, ReplayResult, Status, utcnow)
from raksha.orchestrator import Session

REPO = Path(__file__).parents[1]
HAS_GCC = shutil.which("gcc") is not None
import os
SLOW = os.environ.get("RAKSHA_SLOW_TESTS") == "1"


# ---- a VERIFIED finding built without a toolchain, for the record-only tests -------------------

def _verified_finding() -> Finding:
    f = Finding(oracle="asan:AddressSanitizer", bug_class="CWE-121", language="c/c++",
                target="demo-svc", message="stack-buffer-overflow", severity="high",
                frames=[Frame(symbol="parse", uri="src/p.c", line=11)])
    f.fix_site_set = [FixSite(uri="src/p.c", rank=0, start_line=11, symbol="parse")]
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 48, ["./harness", "repro"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), exit_code=1))
    f.confirm()
    f.mark_patched("--- a/src/p.c\n+++ b/src/p.c\n@@ -11 +11 @@\n-bad\n+good\n", RepairLane.TEMPLATE)
    for c in GATE_ORDER:
        f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow(), exit_code=0))
    f._status = Status.VERIFIED
    f.red_team = {"held": True, "attempts": 100, "wins": 0}
    return f


# ---- J6 egress counter -------------------------------------------------------------------------

def test_egress_counter_reads_kernel_counters(tmp_path):
    from raksha import airgap
    netdev = tmp_path / "dev"
    netdev.write_text("Inter-|   Receive\n face |bytes\n"
                      "  lo: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n"
                      " eth0: 500 5 0 0 0 0 0 0 900 9 0 0 0 0 0 0\n")
    sysnet = tmp_path / "sys"
    (sysnet / "eth0").mkdir(parents=True)
    (sysnet / "eth0" / "operstate").write_text("up\n")
    (sysnet / "eth0" / "carrier").write_text("1\n")
    r = airgap.egress_counter(reset=True, netdev=str(netdev), sys_net=str(sysnet))
    assert r["available"] and r["links_up"] == 1
    names = {i["name"] for i in r["interfaces"]}
    assert "eth0" in names and "lo" not in names            # loopback is never egress
    assert r["tx_packets_delta"] == 0                       # just reset
    # a second reading after bytes move shows the delta
    netdev.write_text("Inter-|   Receive\n face |bytes\n"
                      " eth0: 500 5 0 0 0 0 0 0 1400 19 0 0 0 0 0 0\n")
    r2 = airgap.egress_counter(netdev=str(netdev), sys_net=str(sysnet))
    assert r2["tx_packets_delta"] == 10 and r2["tx_bytes_delta"] == 500


# ---- J8 advisory -------------------------------------------------------------------------------

def test_advisory_issued_and_verifies(tmp_path):
    from raksha import advisory
    f = _verified_finding()
    out = advisory.issue(f, tmp_path, advisory_id="RAKSHA-CERT-2026-0007")
    assert out.name == "RAKSHA-CERT-2026-0007"
    body = json.loads((out / "advisory.json").read_text())
    assert body["remedy"]["patch_diff"] and body["affected"][0]["finding"] == f.id
    ok, problems = advisory.verify_advisory(out)
    assert ok, problems
    # tamper with the patch: verification must fail
    bad = json.loads((out / "advisory.json").read_text())
    bad["remedy"]["patch_diff"] += "x"
    (out / "advisory.json").write_text(json.dumps(bad, indent=2, sort_keys=True))
    ok2, problems2 = advisory.verify_advisory(out)
    assert not ok2 and problems2


def test_advisory_refuses_unverified_finding(tmp_path):
    from raksha import advisory
    f = Finding(oracle="asan:x", bug_class="CWE-121", language="c/c++", target="t",
                message="m", severity="high")
    with pytest.raises(ValueError):
        advisory.body_for(f, advisory_id="RAKSHA-CERT-2026-0001")


def test_advisory_next_id_is_sequential(tmp_path):
    from raksha import advisory
    (tmp_path / "RAKSHA-CERT-2026-0001").mkdir()
    (tmp_path / "RAKSHA-CERT-2026-0005").mkdir()
    assert advisory.next_id(tmp_path, year=2026) == "RAKSHA-CERT-2026-0006"


# ---- J2 intake ---------------------------------------------------------------------------------

def test_intake_refuses_paths_outside_roots(tmp_path):
    from raksha.intake import Intake
    s = Session()
    desk = Intake(s, roots=[tmp_path / "media"])
    (tmp_path / "media").mkdir()
    (tmp_path / "elsewhere").mkdir()
    assert not desk.submit(str(tmp_path / "elsewhere"))["ok"]
    assert not desk.submit(str(tmp_path / "nope"))["ok"]


def test_intake_staging_is_bounded_and_skips_links(tmp_path):
    from raksha.intake import Limits, stage
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n")
    (src / "big.bin").write_bytes(b"\0" * 5000)
    try:
        (src / "link").symlink_to(src / "a.py")
    except OSError:
        pass
    rep = stage(src, tmp_path / "dst", Limits(max_file_bytes=1000))
    assert (tmp_path / "dst" / "a.py").exists()
    assert not (tmp_path / "dst" / "big.bin").exists() and rep.skipped_large == 1
    assert not (tmp_path / "dst" / "link").exists()


@pytest.mark.skipif(not HAS_GCC, reason="intake runs the build-free lanes; estate scan needs no gcc though")
def test_intake_finds_and_merges_without_restart(tmp_path):
    from raksha.intake import Intake
    s = Session()
    media = tmp_path / "media"
    shutil.copytree(REPO / "demo-targets" / "mixed-estate", media / "estate")
    desk = Intake(s, roots=[tmp_path])
    r = desk.submit(str(media / "estate"), name="judge-target")
    assert r["ok"], r
    desk.wait(120)
    job = desk.status()["history"][-1]
    assert job["state"] == "done" and job["findings"] > 0
    assert job["first_finding_s"] is not None
    assert any(t.name == "judge-target" for t in s.targets)   # merged into the live session


# ---- J9 time-lapse -----------------------------------------------------------------------------

def test_timelapse_replays_a_journal(tmp_path):
    from raksha import timelapse
    j = tmp_path / "run.jsonl"
    s = Session()
    s.open_journal(j)
    s.add_finding(_verified_finding())
    s.checkpoint()
    s.emit("red_team_round", target="demo-svc", held=True, attempts=50)
    rec = timelapse.Recording(j)
    assert rec.summary()["chain_verified"]
    end = rec.at(rec.duration + 1)
    assert end["findings"] == 1 and end["by_status"].get("VERIFIED") == 1
    frames = rec.frames(5)
    assert len(frames) == 5 and frames[-1]["findings"] == 1


def test_timelapse_rejects_tampered_journal(tmp_path):
    from raksha import journal, timelapse
    j = tmp_path / "run.jsonl"
    jour = journal.Journal(j)
    jour.emit("a", x=1)
    jour.emit("b", x=2)
    lines = j.read_text().splitlines()
    rec = json.loads(lines[0]); rec["x"] = 999
    lines[0] = json.dumps(rec)
    j.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        timelapse.Recording(j)


def test_shipped_recorded_run_verifies_if_present():
    from raksha import timelapse
    if not timelapse.RECORDED_RUN.exists():
        pytest.skip("no recorded run shipped")
    rec = timelapse.Recording(timelapse.RECORDED_RUN)
    s = rec.summary()
    assert s["chain_verified"] and s["records"] > 0 and rec.duration > 0


# ---- J1 says-no beat (needs gcc + ASan) --------------------------------------------------------

@pytest.mark.skipif(not (HAS_GCC and SLOW), reason="slow; set RAKSHA_SLOW_TESTS=1")
def test_saysno_beat_is_as_scripted():
    from raksha import saysno
    s = Session()
    report = saysno.run(s, refuzz_seconds=2.0, red_seconds=6.0)
    assert report.error is None, report.error
    beats = {b.name: b for b in report.beats}
    assert beats["shallow"].said_no and beats["shallow"].refused_by.startswith("gate:")
    assert beats["unsafe"].said_no and beats["unsafe"].refused_by == "hygiene"
    assert beats["weak"].said_no and beats["weak"].refused_by == "red-team"
    assert not beats["proper"].said_no
    assert report.as_scripted
    assert s.saysno and s.saysno["as_scripted"]


# ---- J7 verifier media (needs gcc only for the C replay; python replay always) -----------------

@pytest.mark.skipif(not SLOW, reason="slow; set RAKSHA_SLOW_TESTS=1")
def test_verifier_media_builds_and_self_verifies(tmp_path):
    import subprocess
    import sys
    from raksha import verifiermedia
    out = tmp_path / "media"
    verifiermedia.demo_media(out)
    assert (out / "verify.py").exists() and (out / "MEDIA.json").exists()
    media = json.loads((out / "MEDIA.json").read_text())
    assert media["findings"] and media["advisories"]
    r = subprocess.run([sys.executable, str(out / "verify.py"), "--json"],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    report = json.loads(r.stdout)
    assert report["ok"] and report["media"] == "ok"
    assert any(v.get("result") == "pass" for v in report["replays"].values())
