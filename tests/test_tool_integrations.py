"""External tools wired in: Checkov and offline Semgrep take lanes, cosign seals, OPA as a second ROE
opinion. Parsers are tested on fixed tool output; the real binaries are exercised when present."""
from __future__ import annotations

import json
import shutil

import pytest

from raksha import roe
from raksha.lanes import take
from raksha.roe import AssetTier, Level, RoeDecision, Signature


def test_checkov_parser_yields_confirmed_config_findings():
    out = json.dumps({"results": {"failed_checks": [
        {"check_id": "CKV_DOCKER_8", "check_name": "Ensure the last USER is not root",
         "file_path": "/Dockerfile", "file_abs_path": "/repo/Dockerfile", "file_line_range": [2, 2],
         "severity": None}]}})
    fs = take._checkov_findings(out, "/repo")
    assert len(fs) == 1 and fs[0].oracle == "take:checkov" and fs[0].bug_class == "CWE-16"
    assert fs[0].status.value == "CONFIRMED" and fs[0].fix_site_set[0].uri == "Dockerfile"


def test_semgrep_uses_offline_rules_by_default(monkeypatch):
    monkeypatch.delenv("RAKSHA_SEMGREP_RULES", raising=False)
    lane = next(l for l in take.LANES if l.tool == "semgrep")
    argv = lane.argv("/x")
    assert "auto" not in argv and argv[argv.index("--config") + 1].endswith("raksha-offline.yml")
    monkeypatch.setenv("RAKSHA_SEMGREP_RULES", "/rules")
    assert "/rules" in lane.argv("/x")


def test_osv_offline_flag(monkeypatch):
    lane = next(l for l in take.LANES if l.tool == "osv-scanner")
    monkeypatch.setenv("RAKSHA_OSV_OFFLINE", "1")
    argv = lane.argv("/x")       # the flag the installed version understands (v1 vs v2)
    assert "--offline" in argv or "--experimental-offline" in argv


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not installed")
def test_checkov_real_binary(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\nUSER root\n")
    fs = take.run_take_lanes(str(tmp_path), enabled={"checkov"})
    assert fs and all(f.oracle == "take:checkov" for f in fs)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_offline_rules_real_binary(tmp_path):
    (tmp_path / "a.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    fs = take.run_take_lanes(str(tmp_path), enabled={"semgrep"})
    assert any(f.bug_class == "CWE-78" for f in fs)
    assert all(f.status.value == "SUSPECTED" for f in fs)      # a static lead, never a report


def _decision(eff, two_person=False, verified=True):
    return RoeDecision("x", AssetTier.IMPORTANT, Level(eff), Level(eff), two_person=two_person,
                       verified=verified)


def test_opa_enabled_but_absent_fails_closed(monkeypatch):
    monkeypatch.setenv("RAKSHA_OPA", "1")
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "opa" else "/bin/" + name)
    ok, why = roe.may_deploy(_decision(3), [])
    assert not ok and "OPA" in why


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa not installed")
def test_opa_agrees_with_builtin_rule(monkeypatch):
    monkeypatch.setenv("RAKSHA_OPA", "1")
    cases = [(3, False, [], True), (2, False, [], True), (2, False, ["a"], True),
             (2, True, ["a"], True), (2, True, ["a", "b"], True), (1, False, ["a", "b"], True),
             (3, False, [], False), (2, True, ["a", "A "], True)]
    for eff, tp, sigs, ver in cases:
        d = _decision(eff, tp, ver)
        s = [Signature(o, "k") for o in sigs]
        assert roe._opa_allows(d, s) == roe._builtin_may_deploy(d, s)[0], (eff, tp, sigs, ver)


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_cosign_seal_signs_verifies_and_detects_tamper(tmp_path, monkeypatch):
    from raksha import cosign
    from raksha.orchestrator import Session
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    keys = cosign.init(tmp_path / "keys")
    monkeypatch.setenv("RAKSHA_COSIGN_KEY", keys["private"])
    s = Session()
    s.ingest_build_free("demo-targets/mixed-estate")
    fid = next(f.id for f in s.findings.values() if f.is_reportable)
    d = s.bundle_dir(fid)
    assert (d / cosign.SIG_FILE).is_file()
    assert cosign.verify_file(d / "bundle.json", d / cosign.SIG_FILE, keys["public"])
    from raksha.bundle import verify_bundle
    assert verify_bundle(d).ok                      # the extra seal does not upset the HMAC check
    (d / "bundle.json").write_text((d / "bundle.json").read_text() + " ")
    assert not cosign.verify_file(d / "bundle.json", d / cosign.SIG_FILE, keys["public"])
