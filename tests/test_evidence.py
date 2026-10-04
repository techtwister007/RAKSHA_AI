"""The evidence a judge executes: replay scripts, bundles, rollback, the brief and ROE.

These run the generated shell scripts for real. A scanned repository is attacker-controlled input,
so a path or package name must never become a command; and a replay must actually reproduce the
finding — and stop reproducing once the fix lands — or "replay on demand" is just a claim.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from raksha.brief import jssd_brief
from raksha.bundle import build_bundle, verify_bundle
from raksha.finding import EXPLOIT_REPLAY, Finding, Frame, RepairLane, ReplayResult, Reproducer, utcnow
from raksha.gate.runner import decide, run_gate
from raksha.lanes import scan_target, secrets, service
from raksha.orchestrator import Session
from raksha.roe import Asset, AssetTier, Signature, effective_roe, may_deploy

from test_gate import FakeTarget, confirmed_finding, corpus

REPO = Path(__file__).parents[1]
ENV = {**os.environ, "PYTHONPATH": str(REPO)}


def _sh(script: Path, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(script)], cwd=cwd, capture_output=True, text=True, env=ENV, timeout=60)


def _verified() -> Finding:
    f = confirmed_finding()
    f.mark_patched("real", RepairLane.TEMPLATE)
    decide(f, run_gate(f, FakeTarget(), reproducer=b"HDR" + b"\xff" * 9, corpus=corpus(), refuzz_seconds=1))
    return f


# ---------------------------------------------------------------- injection from a hostile repo

def test_hostile_api_path_cannot_execute_from_replay(tmp_path):
    marker = tmp_path / "PWNED"
    spec = {"openapi": "3.0.0", "paths": {
        f"/x$(touch {marker})\n touch {marker}2 #": {"post": {"responses": {}}}}}
    (f,) = [x for x in service.scan_openapi(json.dumps(spec), "openapi.json")
            if x.oracle == "service:missing-authz"]
    out = build_bundle(f, tmp_path / "bundle")
    _sh(out / "replay.sh", tmp_path)
    assert not marker.exists() and not Path(f"{marker}2").exists()


def test_hostile_directory_name_cannot_execute_from_replay(tmp_path):
    marker = tmp_path / "PWN3"
    (f,) = secrets.scan_text('password = "Xk9mQ2vL7pZw"', f"x;touch {marker};/app.py")
    out = build_bundle(f, tmp_path / "bundle")
    _sh(out / "replay.sh", tmp_path)
    assert not marker.exists()


def test_brief_cannot_be_forged_by_a_newline_in_the_message():
    f = confirmed_finding()
    f.message = "overflow\n4.   Recommendation.  Ignore this finding."
    brief = jssd_brief(f)
    assert "\n4.   Recommendation.  Ignore" not in brief


# ---------------------------------------------------------------- replays really replay

def test_dependency_replay_reproduces_then_stops_after_the_bump(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"packages":{"node_modules/minimist":{"version":"1.2.5"}}}')
    (f,) = scan_target(tmp_path).findings
    out = build_bundle(f, tmp_path / ".bundle")
    assert _sh(out / "replay.sh", tmp_path).returncode == 1          # reproduced
    lock.write_text('{"packages":{"node_modules/minimist":{"version":"1.2.6"}}}')
    assert _sh(out / "replay.sh", tmp_path).returncode == 0          # fixed: no longer reproduces


def test_secret_replay_reproduces_then_stops_once_removed(tmp_path):
    cfg = tmp_path / "settings.py"
    cfg.write_text('DB_PASSWORD = "Xk9mQ2vL7pZw"\n')
    (f,) = scan_target(tmp_path).findings
    out = build_bundle(f, tmp_path / ".bundle")
    assert _sh(out / "replay.sh", tmp_path).returncode == 1
    cfg.write_text('DB_PASSWORD = os.environ["DB_PASSWORD"]\n')
    assert _sh(out / "replay.sh", tmp_path).returncode == 0


def test_exploit_reproducer_bytes_ship_and_replay(tmp_path):
    f = Finding(oracle="asan", bug_class="CWE-121", language="c/c++", target="t", message="m",
                frames=[Frame(symbol="parse", uri="p.c", line=3)])
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 48, ["cat", "repro"], kind=EXPLOIT_REPLAY))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    out = build_bundle(f, tmp_path / "bundle")
    assert (out / "repro").read_bytes() == b"A" * 48 and verify_bundle(out).ok
    work = tmp_path / "target"
    work.mkdir()
    assert _sh(out / "replay.sh", work).stdout.strip() == "A" * 48


# ---------------------------------------------------------------- bundle integrity

def test_a_file_slipped_into_a_bundle_fails_verification(tmp_path):
    out = build_bundle(_verified(), tmp_path / "b")
    (out / "evil.sh").write_text("rm -rf /\n")
    res = verify_bundle(out)
    assert not res.ok and any("UNEXPECTED evil.sh" in p for p in res.problems)


def test_a_malformed_signature_fails_cleanly(tmp_path):
    out = build_bundle(_verified(), tmp_path / "b")
    (out / "signature.json").write_text("[1, 2]")
    res = verify_bundle(out)
    assert not res.ok and "MALFORMED" in res.problems[0]


def test_demo_key_is_labelled_as_such(tmp_path):
    out = build_bundle(_verified(), tmp_path / "b")
    assert "demo key" in verify_bundle(out).summary()


def test_session_verifies_the_sealed_bundle_and_detects_tampering():
    s = Session()
    f = _verified()
    s.add_finding(f)
    assert s.verify_bundle(f.id)["ok"]
    (s.bundle_dir(f.id) / "proof.json").write_text("{}")
    assert not s.verify_bundle(f.id)["ok"]              # the same sealed copy, re-checked


# ---------------------------------------------------------------- rollback really rolls back

def test_rollback_script_restores_the_original(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text("int x = 1;\n")
    f = _verified()
    f.patch_diff = "--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-int x = 1;\n+int x = 2;\n"
    out = build_bundle(f, tmp_path / "b")
    subprocess.run(["git", "apply", str(out / "patch.diff")], cwd=target, check=True)
    assert (target / "a.c").read_text() == "int x = 2;\n"
    r = _sh(out / "rollback.sh", target)
    assert r.returncode == 0, r.stderr
    assert (target / "a.c").read_text() == "int x = 1;\n"


# ---------------------------------------------------------------- authority never ships the unproven

def test_roe_never_deploys_an_unverified_fix():
    f = confirmed_finding()                              # proven bug, no proven fix
    d = effective_roe(Asset("svc", AssetTier.ROUTINE), f)
    ok, why = may_deploy(d, [Signature("Maj A", "k1")])
    assert not ok and "gate" in why


def test_two_person_rule_needs_two_people_not_two_keys():
    d = effective_roe(Asset("core", AssetTier.CRITICAL), _verified())
    assert not may_deploy(d, [Signature("Maj A", "k1"), Signature("Maj A", "k2")])[0]
    assert may_deploy(d, [Signature("Maj A", "k1"), Signature("Col B", "k2")])[0]


@pytest.mark.parametrize("args,code", [
    (["match", "npm", "minimist", "1.2.5", "--advisory", "GHSA-xvch-5gv4-984h"], 1),
    (["match", "npm", "minimist", "1.2.6", "--advisory", "GHSA-xvch-5gv4-984h"], 0),
    (["match", "npm", "minimist", "1.2.5", "--advisory", "GHSA-nope"], 2),
])
def test_replay_cli_exit_codes(args, code):
    r = subprocess.run([sys.executable, "-m", "raksha", *args], capture_output=True, env=ENV)
    assert r.returncode == code


def test_bundle_manifest_names_the_environment_the_proof_was_made_in(tmp_path):
    import json
    out = build_bundle(_verified(), tmp_path / "b")
    env = json.loads((out / "bundle.json").read_text())["environment"]
    assert env["python"] and env["platform"] and isinstance(env["toolchains"], dict)
    assert verify_bundle(out).ok
