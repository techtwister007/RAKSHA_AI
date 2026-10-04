"""Model-written and template regression tests: emitted by the repair ladder, VERIFIED by the gate's
existing fail-before / pass-after check, and shipped on the finding ONLY when verified.

The gate (`verify_regression_test`) already decides a test by running it on the vulnerable and the
patched build. These tests prove the repair ladder produces one for it to judge — from the model
(MockClient) and from the deterministic template generator (offline, no model) — and that a test
which does not exercise the bug is thrown away.
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
from raksha.repair_templates import c_bound_copy, template_regression_test

HAVE_GCC = shutil.which("gcc") is not None
REPO = Path(__file__).parents[1]
C_TARGET = REPO / "demo-targets" / "c-nolibfuzzer"


class MockClient:
    """Returns fixed completions, to exercise the model lane offline."""
    def __init__(self, completions):
        self._c = completions
        self.config = SimpleNamespace(model_for=lambda role: "mock-repair-model")

    def complete(self, messages, *, role="repair", n=1, temperature=0.0, max_tokens=1024):
        return list(self._c)


def _c_target_with_added_tests():
    """An autofuzz C result whose target can run an added test (`sh {test}` in the build dir)."""
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    r.target.added_test_cmd = "sh {test}"
    r.target.added_test_path = "raksha_added_test.sh"
    return r


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_model_diff_plus_good_test_is_verified_and_shipped(monkeypatch):
    r = _c_target_with_added_tests()
    good_diff = c_bound_copy(r.finding, Path(r.target.source_root))
    assert good_diff
    # a model test that aborts on the vulnerable build and not on the patched one: feed the
    # reproducer and assert no sanitizer abort (the same honest shape the template lane uses)
    good_test = template_regression_test(r.finding, r.crashing_input)
    completion = good_diff + "\n=== REGRESSION TEST ===\n" + good_test
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd", b"\x02zz"], client=MockClient([completion]))
    assert out.verified and out.lane is RepairLane.LLM
    assert r.finding.regression_test is not None and "raksha_harness" in r.finding.regression_test


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_a_test_that_passes_on_both_builds_is_rejected_and_not_shipped(monkeypatch):
    r = _c_target_with_added_tests()
    good_diff = c_bound_copy(r.finding, Path(r.target.source_root))
    trivial = "#!/bin/sh\n# never touches the bug\nexit 0\n"      # passes on vulnerable AND patched
    completion = good_diff + "\n=== REGRESSION TEST ===\n" + trivial
    monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd", b"\x02zz"], client=MockClient([completion]))
    assert out.verified and r.finding.status is Status.VERIFIED       # the diff still verifies
    assert r.finding.regression_test is None                          # the useless test is dropped


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_template_regression_generator_verifies_offline():
    r = _c_target_with_added_tests()
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=[b"\x01\x04abcd", b"\x02zz"], use_model=False)
    assert out.verified and out.lane is RepairLane.TEMPLATE
    # the deterministic (zero-inference) template test was generated AND verified by the gate
    assert r.finding.regression_test is not None
    assert "REGRESS" in r.finding.regression_test and "raksha_harness" in r.finding.regression_test
