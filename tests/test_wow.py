"""Phase 7 — the three WOW beats: ROE authority, the Vulnerability Vaccine, and (opt-in, slow) the
public rejection of a bad patch. ROE and vaccine are pure/fast and run in the normal suite; the
bad-patch beat drives a real build and is guarded like the other deep slices."""

from __future__ import annotations

import os

import pytest

from raksha import roe, vaccine
from raksha.finding import (
    GATE_ORDER, Finding, FixSite, Frame, RepairLane, ReplayResult, Reproducer, Status, utcnow,
)


# ---------------------------------------------------------------- helpers

def _verified(bug_class="CWE-78", patch="--- a/x\n+++ b/x\n+safe\n", lane=RepairLane.TEMPLATE,
              quarantined=0) -> Finding:
    f = Finding(oracle="o", bug_class=bug_class, language="python", target="svc",
                message="m", frames=[Frame(symbol="s", uri="app/runner.py", line=13)])
    f.add_fix_site(FixSite(uri="app/runner.py", rank=0, start_line=13))
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.mark_patched(patch, lane)
    for c in GATE_ORDER:
        f.record_gate(c, True, quarantined_inputs=(quarantined if c.value == "DIFFERENTIAL_CORPUS" else 0))
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow()))
    f.verify()
    return f


# ---------------------------------------------------------------- ROE

def test_tiers_are_distinct_and_cap_correctly():
    # the IntEnum-alias trap: IMPORTANT and CRITICAL both cap at R2 but must be distinct members
    assert roe.AssetTier.IMPORTANT is not roe.AssetTier.CRITICAL
    assert roe.AssetTier.CRITICAL.two_person and not roe.AssetTier.IMPORTANT.two_person
    assert roe.AssetTier.MISSION_CRITICAL.cap is roe.Level.R1


def test_routine_asset_allows_autonomy():
    d = roe.effective_roe(roe.Asset("lms", roe.AssetTier.ROUTINE), _verified())
    assert d.effective is roe.Level.R3 and d.autonomous and not d.two_person


def test_mission_critical_is_recommend_only():
    d = roe.effective_roe(roe.Asset("fire-control", roe.AssetTier.MISSION_CRITICAL), _verified())
    assert d.effective is roe.Level.R1 and d.requires_human
    ok, why = roe.may_deploy(d, [roe.Signature("A", "k1"), roe.Signature("B", "k2")])
    assert not ok and "recommend only" in why


def test_critical_asset_needs_two_signatures():
    d = roe.effective_roe(roe.Asset("c2", roe.AssetTier.CRITICAL), _verified())
    assert d.two_person
    assert roe.may_deploy(d, [roe.Signature("A", "k1")])[0] is False
    assert roe.may_deploy(d, [roe.Signature("A", "k1"), roe.Signature("B", "k2")])[0] is True
    # two signatures from the SAME key do not count as two people
    assert roe.may_deploy(d, [roe.Signature("A", "k1"), roe.Signature("A", "k1")])[0] is False


def test_step_down_when_patch_touches_auth():
    f = _verified(patch="--- a/x\n+++ b/x\n+    if password == stored: grant_access()\n")
    d = roe.effective_roe(roe.Asset("lms", roe.AssetTier.ROUTINE), f)
    assert d.effective is roe.Level.R2
    assert any("auth" in r for r in d.step_downs)


def test_step_down_for_mitigation_floor_fix():
    f = _verified(lane=RepairLane.MITIGATION)
    d = roe.effective_roe(roe.Asset("lms", roe.AssetTier.ROUTINE), f)
    assert d.effective is roe.Level.R2 and any("mitigation" in r for r in d.step_downs)


def test_step_down_when_advisor_disagrees_goes_to_r1():
    d = roe.effective_roe(roe.Asset("lms", roe.AssetTier.ROUTINE), _verified(), advisor_disagrees=True)
    assert d.effective is roe.Level.R1 and any("advisor" in r for r in d.step_downs)


def test_step_down_for_flaky_gate_and_first_sighting():
    d = roe.effective_roe(roe.Asset("lms", roe.AssetTier.ROUTINE), _verified(quarantined=6),
                          bug_class_seen_on_asset=False)
    assert d.effective is roe.Level.R2
    assert any("quarantined" in r for r in d.step_downs) and any("first time" in r for r in d.step_downs)


def test_operator_may_pin_lower_never_higher():
    # operator cap R1 on a routine (R3) asset -> R1
    d = roe.effective_roe(roe.Asset("lms", roe.AssetTier.ROUTINE, operator_cap=roe.Level.R1), _verified())
    assert d.effective is roe.Level.R1


# ---------------------------------------------------------------- the vaccine

def test_only_verified_findings_become_vaccines():
    f = Finding(oracle="o", bug_class="CWE-78", language="python", target="svc", message="m")
    assert vaccine.extract_rule(f) is None          # SUSPECTED -> no vaccine
    assert vaccine.extract_rule(_verified()) is not None


def test_rule_proof_three_checks():
    rule = vaccine.extract_rule(_verified("CWE-78"))
    good = vaccine.prove_rule(
        rule, vulnerable_sample="subprocess.run(cmd, shell=True)\n",
        fixed_sample="subprocess.run(cmd, shell=False)\n",
        clean_corpus=["print(1)\n", "x=2\n"])
    assert good.passed and good.hits_original and good.misses_fix and good.low_noise


def test_a_rule_that_flags_safe_code_is_discarded():
    rule = vaccine.extract_rule(_verified("CWE-78"))
    # a "fixed sample" that the rule still matches must fail the misses-fix check
    bad = vaccine.prove_rule(rule, vulnerable_sample="subprocess.run(x, shell=True)\n",
                             fixed_sample="subprocess.run(x, shell=True)  # not actually fixed\n",
                             clean_corpus=[])
    assert not bad.passed and not bad.misses_fix


def test_a_noisy_rule_is_discarded():
    rule = vaccine.extract_rule(_verified("CWE-78"))
    noisy = vaccine.prove_rule(rule, vulnerable_sample="subprocess.run(x, shell=True)\n",
                               fixed_sample="subprocess.run(x, shell=False)\n",
                               clean_corpus=["subprocess.run(a, shell=True)\n"] * 3)  # fires on "clean"
    assert not noisy.passed and not noisy.low_noise and noisy.noise_hits == 3


def test_sweep_finds_variants_and_skips_safe_and_fixed(tmp_path):
    rule = vaccine.extract_rule(_verified("CWE-78"))
    (tmp_path / "a").mkdir(); (tmp_path / "a" / "x.py").write_text("subprocess.run('echo '+x, shell=True)\n")
    (tmp_path / "b").mkdir(); (tmp_path / "b" / "y.py").write_text("subprocess.run(['echo', x], shell=False)\n")
    hits = vaccine.sweep(rule, {"a": tmp_path / "a", "b": tmp_path / "b"})
    assert {h.target for h in hits} == {"a"}         # the safe one is not flagged


def test_sweep_hit_is_suspected_until_reproduced(tmp_path):
    rule = vaccine.extract_rule(_verified("CWE-78"))
    hit = vaccine.SweepHit(rule.id, "svc-a", "handler.py", 3)
    f = vaccine.hit_to_finding(rule, hit)
    assert f.status is Status.SUSPECTED and not f.is_reportable   # precision stays structural
    assert "Vaccine sweep" in f.message


def test_c_overflow_rule_can_be_mined_and_matches():
    rule = vaccine.extract_rule(_verified("CWE-121"))
    assert rule is not None
    assert rule.matches("    memcpy(buf, data, len);\n")          # unbounded -> hit
    assert not rule.matches("    memcpy(buf, data, sizeof(buf));\n")  # sizeof-bounded -> miss


# ---------------------------------------------------------------- bad-patch beat (opt-in)

@pytest.mark.skipif(os.environ.get("RAKSHA_RUN_DEEP_SLICES") != "1",
                    reason="set RAKSHA_RUN_DEEP_SLICES=1 to run the real-build bad-patch beat")
def test_overfitting_patch_is_publicly_rejected():
    from raksha.slice_wow import reject_bad_patch
    r = reject_bad_patch()
    assert r["rejected"] and r["final_status"] == "CONFIRMED"
    assert r["failed_check"] == "CLEAN_REFUZZ" and r["refuzz_findings"] > 0
