"""The service lane (offline OpenAPI analysis) and the jury exporter."""

from __future__ import annotations

import json
import pathlib

import pytest

from raksha.export import export
from raksha.finding import (
    GATE_ORDER, RepairLane, ReplayResult, Reproducer, Status, utcnow,
)
from raksha.lanes import service, scan_target

FIX = pathlib.Path(__file__).parents[1] / "demo-targets" / "mixed-estate"

SPEC = json.dumps({
    "openapi": "3.0.0",
    "paths": {
        "/login": {"post": {"security": [{"basic": []}]}},   # secured write — ok
        "/users/{id}": {"delete": {}},                        # unsecured write — finding
        "/admin/flush": {"post": {}},                         # unsecured write + debug — two findings
        "/health": {"get": {}},                               # unsecured read — not flagged
    },
})


# ---------------------------------------------------------------- service lane

def test_unsecured_write_endpoint_is_flagged():
    findings = service.scan_openapi(SPEC, "openapi.json")
    authz = [f for f in findings if f.oracle == "service:missing-authz"]
    paths = {f.frames[0].symbol for f in authz}
    assert "DELETE /users/{id}" in paths
    assert "POST /admin/flush" in paths
    assert "POST /login" not in paths          # secured
    assert "GET /health" not in paths          # read-only


def test_debug_endpoint_is_flagged():
    findings = service.scan_openapi(SPEC, "openapi.json")
    assert any(f.oracle == "service:debug-endpoint" for f in findings)


def test_service_findings_are_confirmed_by_deterministic_match():
    for f in service.scan_openapi(SPEC, "openapi.json"):
        assert f.status is Status.CONFIRMED and f.is_reportable
        assert f.reproducer.kind == "deterministic-match"
        assert f.language == "api"


def test_global_security_scheme_secures_all_endpoints():
    spec = json.dumps({"openapi": "3.0.0", "security": [{"oauth": []}],
                       "paths": {"/x": {"delete": {}}}})
    assert service.scan_openapi(spec, "o.json") == []


def test_service_lane_runs_via_the_build_free_runner():
    # the bundled estate ships an openapi.json with an unsecured DELETE and an /admin route
    res = scan_target(FIX)
    assert any(f.language == "api" for f in res.findings)


# ---------------------------------------------------------------- exporter

def _verified_finding():
    from raksha.finding import Finding, FixSite, Frame
    f = Finding(oracle="jazzer:x", bug_class="CWE-917", language="java", target="svc",
                message="Log4Shell", frames=[Frame(symbol="A.b", uri="A.java", line=1)])
    f.add_fix_site(FixSite(uri="pom.xml", rank=0, start_line=1))
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./replay.sh"], artifact_path="crash"))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.mark_patched("--- a/pom.xml\n+++ b/pom.xml\n", RepairLane.TEMPLATE)
    for c in GATE_ORDER:
        f.record_gate(c, True)
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow()))
    f.verify()
    return f


def test_export_writes_a_complete_submission(tmp_path):
    verified = _verified_finding()
    match_findings = service.scan_openapi(SPEC, "openapi.json")
    out = export([verified, *match_findings], tmp_path / "submission")

    summary = json.loads((out / "summary.json").read_text())
    assert summary["counts"]["verified"] == 1
    assert summary["counts"]["total"] == 1 + len(match_findings)
    assert (out / "findings.sarif").exists()

    # the verified finding's folder carries its patch, replay and report
    fdir = out / "".join(c if c.isalnum() or c in "-_" else "-" for c in verified.id)[:40]
    assert (fdir / "patch.diff").exists()
    assert (fdir / "replay.sh").read_text().startswith("#!/usr/bin/env sh")
    assert "Proof the fix holds" in (fdir / "report.md").read_text()


def test_export_excludes_unreportable_findings(tmp_path):
    from raksha.finding import Finding, Frame
    suspected = Finding(oracle="semgrep", bug_class="CWE-89", language="java", target="svc",
                        message="maybe", frames=[Frame(symbol="x", uri="x.java", line=1)])
    out = export([suspected], tmp_path / "s")
    summary = json.loads((out / "summary.json").read_text())
    assert summary["counts"]["total"] == 0          # nothing unproven is exported


def test_exported_sarif_validates(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = pathlib.Path(__file__).parents[1] / "schemas" / "sarif-2.1.0.json"
    if not schema_path.exists():
        pytest.skip("schema not vendored")
    out = export(service.scan_openapi(SPEC, "openapi.json"), tmp_path / "s")
    jsonschema.validate(json.loads((out / "findings.sarif").read_text()), json.loads(schema_path.read_text()))
