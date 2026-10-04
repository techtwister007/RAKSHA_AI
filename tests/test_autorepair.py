"""Driving an autofuzz-confirmed finding to a proven fix through the repair ladder and the gate.

Offline, the generic templates carry it; with an endpoint, the model lane does. The model lane is
exercised here with a mock client (a real endpoint is not available in CI), so the plumbing —
prompt, diff extraction, gating, lane labelling — is tested deterministically. Nothing reaches
VERIFIED without the five-check gate passing.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from raksha import autorepair
from raksha.autorepair import repair
from raksha.finding import RepairLane, Status
from raksha.harness import autofuzz

HAVE_GCC = shutil.which("gcc") is not None
REPO = Path(__file__).parents[1]
C_TARGET = REPO / "demo-targets" / "c-nolibfuzzer"
PY_TARGET = REPO / "demo-targets" / "py-noharness"


class MockClient:
    """A stand-in inference client that returns fixed completions, to test the model lane offline."""
    def __init__(self, completions):
        self._c = completions
        self.config = SimpleNamespace(model_for=lambda role: "mock-repair-model")

    def complete(self, messages, *, role="repair", n=1, temperature=0.0, max_tokens=1024):
        return list(self._c)


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_autofuzz_c_overflow_reaches_verified_offline():
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd", b"\x02zz", b"\x01\x02ab"], use_model=False)
    assert out.verified and out.lane is RepairLane.TEMPLATE
    assert r.finding.status is Status.VERIFIED and r.finding.replay_after.oracle_fired is False


def test_autofuzz_python_injection_reaches_verified_offline():
    r = autofuzz(PY_TARGET, max_execs=6000, use_model=False)
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"10 m to ft", b"5 kg to lb", b"warm"], use_model=False)
    assert out.verified and out.lane is RepairLane.TEMPLATE


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_model_lane_patch_is_gated_and_labelled(monkeypatch):
    # force the model lane: no templates, a mock endpoint that returns a correct diff
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    from raksha.repair_templates import c_bound_copy
    good_diff = c_bound_copy(r.finding, Path(r.target.source_root))   # a diff we know the gate accepts
    assert good_diff and good_diff.startswith("--- a/")
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd", b"\x02zz"], client=MockClient([good_diff]))
    assert out.verified and out.lane is RepairLane.LLM
    assert r.finding.model_version == "mock-repair-model"


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_a_bad_model_patch_is_rejected_and_finding_is_report_only(monkeypatch):
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
    # a diff that compiles but does not fix the overflow (a no-op comment change)
    bad = ("--- a/src/tlv.c\n+++ b/src/tlv.c\n@@ -1,2 +1,3 @@\n"
           " /* A tiny TLV (tag-length-value) record parser. No fuzz harness ships with it — RAKSHA must\n"
           "+/* harmless comment */\n"
           "  * synthesize one, find the overflow, fix it and prove the fix. The bug: `length` comes from the\n")
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd"], client=MockClient([bad]))
    assert not out.verified and r.finding.status is Status.REPORT_ONLY


def test_repair_refuses_a_finding_that_is_not_confirmed():
    r = autofuzz(PY_TARGET, max_execs=6000, use_model=False)
    repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
           corpus=[b"10 m to ft"], use_model=False)                 # drives it to VERIFIED
    with pytest.raises(ValueError):
        repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
               corpus=[b"x"], use_model=False)                      # already terminal


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_orchestrator_autofuzz_session_shows_verified_deep_targets():
    from raksha.orchestrator import autofuzz_session
    s = autofuzz_session()
    board = {t["name"]: t for t in s.board()}
    assert board["py-noharness"]["verified"] == 1          # python always available
    assert board["py-noharness"]["build_status"] == "green"
    card = s.scorecard()
    assert card["performance"]["bugs_verified_fixed"] >= 1


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_a_shallow_fix_that_special_cases_the_reproducer_is_rejected(monkeypatch):
    """PVBench's finding: a patch can kill the observed crash and not the defect. The reproducer's
    own neighbourhood, replayed deterministically at the start of CLEAN_REFUZZ, catches it on every
    target — not only when a random fresh campaign happens to find a sibling."""
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
    n = len(r.crashing_input)
    shallow = ("--- a/src/tlv.c\n+++ b/src/tlv.c\n@@ -9,2 +9,3 @@\n"
               "     if (len < 2) return -1;\n"
               f"+    if (len == {n}) return -1;  /* silence the one input that crashed */\n"
               "     uint8_t tag = data[0];\n")
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd"], client=MockClient([shallow]))
    assert not out.verified and r.finding.status is Status.REPORT_ONLY
    from raksha.finding import GateCheck
    refuzz = [g for g in r.finding.gate_history if g.check is GateCheck.CLEAN_REFUZZ]
    assert refuzz and not refuzz[-1].passed and "variants of the reproducer" in refuzz[-1].detail
    assert r.finding.gate[GateCheck.POV_DEAD].passed      # the shallow fix did kill the exact input


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_a_patch_that_fixes_the_bug_and_adds_a_backdoor_never_reaches_the_gate(monkeypatch):
    """Prompt injection from target source has one exit: the diff. A diff that fixes the overflow
    AND adds an execution primitive is refused before it is applied — behavioural checks cannot
    see code the corpus never runs, so this is checked on the text."""
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    from raksha.repair_templates import c_bound_copy
    good = c_bound_copy(r.finding, Path(r.target.source_root))
    backdoor = good.replace("+++ b/src/tlv.c\n", "+++ b/src/tlv.c\n", 1)
    # append a second hunk that opens a shell when a magic tag arrives
    backdoor += ("@@ -17,2 +18,3 @@\n     }\n+    if (tag == 0x7f) system(\"/bin/sh\");\n     return 0;\n")
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd"], client=MockClient([backdoor]))
    assert not out.verified and out.rejected_before_gate == 1 and out.candidates_tried == 0
    assert r.finding.status is Status.REPORT_ONLY
    assert any("system" in why for why in r.finding.rejected_candidates)
    assert r.finding.repair_rounds == 0                      # never applied, never gated


def test_hygiene_scope_size_and_primitive_rules():
    from raksha import hygiene
    from raksha.finding import Finding, FixSite
    f = Finding(oracle="asan", bug_class="CWE-121", language="c", target="t", message="m")
    f.add_fix_site(FixSite(uri="src/tlv.c", rank=0, start_line=15))
    ok = "--- a/src/tlv.c\n+++ b/src/tlv.c\n@@ -1 +1 @@\n-memcpy(a,b,n);\n+memcpy(a,b,n<32?n:32);\n"
    assert hygiene.check(ok, f) is None
    other = ok.replace("src/tlv.c", "src/other.c")
    assert "not in the fix-site set" in hygiene.check(other, f)
    big = "--- a/src/tlv.c\n+++ b/src/tlv.c\n@@ -1 +1,200 @@\n" + "+int x;\n" * 200
    assert "cap" in hygiene.check(big, f)
    # a primitive already present in the removed lines is not "new": the Python shell template
    # rewrites subprocess.run(shell=True) into subprocess.run(argv) and must still be allowed
    f2 = Finding(oracle="pysecsan", bug_class="CWE-78", language="python", target="t", message="m")
    f2.add_fix_site(FixSite(uri="converter.py", rank=0, start_line=3))
    py = ("--- a/converter.py\n+++ b/converter.py\n@@ -1 +1 @@\n"
          "-subprocess.run(cmd, shell=True)\n+subprocess.run(shlex.split(cmd))\n")
    assert hygiene.check(py, f2) is None
    bad = py.replace("+subprocess.run(shlex.split(cmd))", "+subprocess.run(shlex.split(cmd)); os.system(cmd)")
    assert "os.system" in hygiene.check(bad, f2)


def test_single_template_targets_have_a_frontier_of_one_and_the_env_knob_restores_first_pass_wins(monkeypatch):
    """The Python demo has one template, so the frontier is size one and behaviour is unchanged."""
    r = autofuzz(PY_TARGET, max_execs=6000, use_model=False)
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"10 m to ft", b"5 kg to lb"], use_model=False)
    assert out.verified and out.frontier_size == 1
    assert len(r.finding.frontier) == 1 and r.finding.frontier[0]["chosen"] is True
    assert r.finding.frontier[0]["lane"] == "TEMPLATE" and r.finding.frontier[0]["hunks"] >= 1
    assert len(r.finding.gate_history) == 5           # one candidate, one gate run, no re-run

    monkeypatch.setenv("RAKSHA_PATCH_FRONTIER", "0")
    r2 = autofuzz(PY_TARGET, max_execs=6000, use_model=False)
    out2 = repair(r2.finding, r2.target, root=r2.target.source_root, reproducer=r2.crashing_input,
                  corpus=[b"10 m to ft"], use_model=False)
    assert out2.verified and out2.frontier_size == 1 and len(r2.finding.gate_history) == 5
