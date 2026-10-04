"""G7: derived CVSS vectors (3.1 scored exactly, 4.0 vector only) and ATT&CK / D3FEND mapping."""
from __future__ import annotations

import pytest

from raksha.cvss import attack_map, cvss31, derive
from raksha.finding import EXPLOIT_REPLAY, Finding, Reproducer, ReplayResult, utcnow


def _m(AV, AC, PR, UI, C, I, A, scope=False):
    return dict(AV=AV, AC=AC, AT="N", PR=PR, UI=UI, VC=C, VI=I, VA=A, SC="L" if scope else "N", SI="N", SA="N")


@pytest.mark.parametrize("m,score", [
    (_m("N", "L", "N", "N", "H", "H", "H"), 9.8), (_m("N", "L", "N", "N", "H", "H", "H", True), 10.0),
    (_m("L", "L", "N", "N", "H", "H", "H"), 8.4), (_m("N", "L", "N", "N", "H", "N", "N"), 7.5),
    (_m("N", "H", "N", "N", "H", "H", "H"), 8.1), (_m("L", "L", "N", "N", "N", "N", "H"), 6.2),
    (_m("N", "L", "N", "N", "L", "L", "N", True), 7.2)])
def test_cvss31_matches_first_reference_scores(m, score):
    assert cvss31(m)["base_score"] == score


def _exploit(cwe, oracle="asan"):
    f = Finding(oracle=oracle, bug_class=cwe, language="c", target="svc", message="m")
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r"], kind=EXPLOIT_REPLAY))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow())); f.confirm()
    return f


def test_derived_and_labelled():
    d = derive(_exploit("CWE-121"))
    assert d["derived"] is True and d["cvss40"]["score"] is None and "not bundled" in d["cvss40"]["score_note"]
    assert d["cvss40"]["vector"].startswith("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
    assert any("file/buffer" in b for b in d["basis"])


def test_out_of_bounds_read_has_no_integrity_impact():
    assert "/VI:N/" in derive(_exploit("CWE-125"))["cvss40"]["vector"]


def test_declared_network_exposure_raises_attack_vector_and_adds_t1190():
    f = _exploit("CWE-121")
    f.exposure = "network"
    assert "AV:N" in derive(f)["cvss40"]["vector"]
    assert attack_map(f)["attack"][0]["id"] == "T1190"


def test_technique_and_defence_mapping():
    inj = attack_map(_exploit("CWE-78", oracle="pysecsan"))
    assert {t["id"] for t in inj["attack"]} >= {"T1059"} and inj["defence"]["d3fend_tactic"] == "Harden"
    cred = Finding(oracle="secrets:aws", bug_class="CWE-798", language="any", target="c", message="m")
    assert attack_map(cred)["attack"][0]["id"] == "T1552.001" and attack_map(cred)["defence"]["d3fend_tactic"] == "Evict"
    race = attack_map(_exploit("CWE-362", oracle="tsan"))
    assert race["attack"] == [] and race["note"]                     # said, not forced


def test_record_sarif_and_brief_carry_it():
    from raksha.brief import jssd_brief
    f = _exploit("CWE-121")
    pb = f.proof_block()
    assert pb["severity_vector"]["cvss31"]["base_score"] == 8.4 and pb["techniques"]["attack"]
    assert f.to_sarif_result()["properties"]["security-severity"] == "8.4"
    assert "2.4   Severity (derived).  CVSS 3.1 8.4" in jssd_brief(f)
