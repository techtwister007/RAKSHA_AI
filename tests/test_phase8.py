"""Phase 8: rollback, risk register, Commander's Brief, signed evidence bundle, and the new routes."""

from __future__ import annotations

from raksha import brief, risk, rollback
from raksha.bundle import build_bundle, verify_bundle
from raksha.finding import (
    GATE_ORDER, Finding, FixSite, Frame, RepairLane, ReplayResult, Reproducer, Signature,
    utcnow,
)


def _verified(sev="critical", with_test=False) -> Finding:
    f = Finding(oracle="jazzer:x", bug_class="CWE-917", language="java", target="audit-svc",
                message="Remote JNDI Lookup (Log4Shell)", severity=sev,
                frames=[Frame(symbol="A.b", uri="A.java", line=1)])
    f.add_fix_site(FixSite(uri="pom.xml", rank=0, start_line=31, rationale="bump log4j to 2.17.1"))
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./replay.sh"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.mark_patched("--- a/pom.xml\n+++ b/pom.xml\n@@\n-2.14.1\n+2.17.1\n", RepairLane.TEMPLATE)
    for c in GATE_ORDER:
        f.record_gate(c, True)
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow()))
    if with_test:
        f.regression_test = "def test_no_jndi(): assert True"
    f.verify()
    return f


def _report_only() -> Finding:
    f = Finding(oracle="asan", bug_class="CWE-416", language="c/c++", target="parser",
                message="use-after-free", frames=[Frame(symbol="f", uri="p.c", line=9)])
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.report_only("no patch validated")
    return f


# ---------------------------------------------------------------- rollback

def test_rollback_script_reverses_the_patch():
    s = rollback.rollback_script(_verified(), test_cmd="mvn test")
    assert "git apply -R" in s and "patch -R" in s and s.startswith("#!/usr/bin/env sh")
    assert "mvn test" in s


def test_rollback_script_handles_no_patch():
    f = _report_only()
    assert "nothing to roll back" in rollback.rollback_script(f)


# ---------------------------------------------------------------- risk register

def test_register_ranks_by_severity_reachability_exploitability():
    crit = _verified(sev="critical")
    low = _verified(sev="low")
    rows = risk.register([low, crit])
    assert rows[0].finding.id == crit.id          # critical outranks low
    assert rows[0].score > rows[1].score


def test_exploit_proven_outranks_match_proven_at_equal_severity():
    from raksha.finding import DETERMINISTIC_MATCH
    exploit = _verified(sev="high")
    match = _verified(sev="high")
    match.reproducer = Reproducer.from_bytes(b"x", ["./r"], kind=DETERMINISTIC_MATCH)
    rows = risk.register([match, exploit])
    assert rows[0].finding.id == exploit.id


def test_fix_first_returns_top_n():
    findings = [_verified(sev="low"), _verified(sev="critical"), _verified(sev="medium")]
    top = risk.fix_first(findings, n=2)
    assert len(top) == 2 and top[0].finding.severity == "critical"


def test_register_excludes_suspected():
    suspected = Finding(oracle="semgrep", bug_class="CWE-89", language="java", target="x", message="m")
    assert risk.register([suspected]) == []


# ---------------------------------------------------------------- commander's brief

def test_plain_summary_is_actionable():
    s = brief.plain_summary(_verified())
    assert "CRITICAL" in s and "ready to deploy" in s and "CWE-917" in s


def test_jssd_brief_has_service_layout():
    b = brief.jssd_brief(_verified(), serial=7)
    assert "RESTRICTED" in b and "Serial No 007" in b
    assert "1.   Subject." in b and "4.   Recommendation." in b
    assert "ROE" in b


def test_jssd_brief_report_only_recommends_human_remediation():
    b = brief.jssd_brief(_report_only())
    assert "PROVEN real" in b and "do not auto-patch" in b


def test_jssd_brief_hindi_optional():
    b = brief.jssd_brief(_verified(), hindi=True)
    assert "सारांश" in b


# ---------------------------------------------------------------- signed bundle

def test_bundle_builds_and_verifies(tmp_path):
    out = build_bundle(_verified(with_test=True), tmp_path / "b")
    assert (out / "patch.diff").exists() and (out / "rollback.sh").exists()
    assert (out / "regression_test").exists() and (out / "commanders_brief.txt").exists()
    res = verify_bundle(out)
    assert res.ok, res.summary()


def test_bundle_detects_tampering(tmp_path):
    out = build_bundle(_verified(), tmp_path / "b")
    (out / "patch.diff").write_text("--- tampered\n")
    res = verify_bundle(out)
    assert not res.ok and any("CHANGED patch.diff" in p for p in res.problems)


def test_bundle_detects_manifest_tampering(tmp_path):
    out = build_bundle(_verified(), tmp_path / "b")
    manifest = (out / "bundle.json").read_text().replace("audit-svc", "evil-svc")
    (out / "bundle.json").write_text(manifest)
    res = verify_bundle(out)
    assert not res.ok


def test_bundle_refuses_unreportable_finding(tmp_path):
    import pytest
    suspected = Finding(oracle="semgrep", bug_class="CWE-89", language="java", target="x", message="m")
    with pytest.raises(ValueError):
        build_bundle(suspected, tmp_path / "b")


def test_bundle_carries_two_person_signatures(tmp_path):
    import json
    f = _verified()
    f.add_signature(Signature("Maj A", "k1", "sig", utcnow()))
    f.add_signature(Signature("Capt B", "k2", "sig", utcnow()))
    out = build_bundle(f, tmp_path / "b")
    manifest = json.loads((out / "bundle.json").read_text())
    assert len(manifest["approver_signatures"]) == 2
    assert verify_bundle(out).ok
