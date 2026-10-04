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
