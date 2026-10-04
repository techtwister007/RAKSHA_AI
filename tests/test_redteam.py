"""The independent red team: it re-attacks a VERIFIED patch and reports whether the fix held.

It never verifies anything and never changes a status; the tests check exactly that. The logic
tests use `test_gate.FakeTarget`: the finding is VERIFIED honestly through the gate against the
real fix, then red attacks either that fix (held) or a build that secretly carries the planted
shallow fix (not held). The last test runs red against the real tlv.c fix that autorepair proved.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from raksha.finding import Status
from raksha.redteam import RedResult, decode_proposals, red_round
from test_gate import REPRO, FakeTarget, corpus, patched

HAVE_GCC = shutil.which("gcc") is not None
REPO = Path(__file__).parents[1]
C_TARGET = REPO / "demo-targets" / "c-nolibfuzzer"


class ShallowTarget(FakeTarget):
    """The build labelled 'real' secretly behaves like the planted overfitting patch: the one
    reproducer is silenced, every sibling input still overflows."""

    def build(self, patch_diff):
        b = super().build(patch_diff)
        return b if patch_diff is None else type(b)(b.ok, "overfit", b.log, b.root)


class MockClient:
    def __init__(self, completions):
        self._c = completions
        self.calls = 0
        self.config = SimpleNamespace(model_for=lambda role: "mock-red-model")

    def complete(self, messages, *, role="repair", n=1, temperature=0.0, max_tokens=1024):
        self.calls += 1
        assert role == "red"
        assert "UNTRUSTED DIFF" in messages[-1]["content"]
        return list(self._c)


def verified_finding():
    from raksha.gate import decide, run_gate
    f = patched("real")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v.passed
    decide(f, v)
    assert f.status is Status.VERIFIED
    return f


def test_red_cannot_beat_the_real_fix_and_says_so_on_the_record():
    f = verified_finding()
    before = len(f.gate_history)
    r = red_round(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), rounds=100, seed=7)
    assert isinstance(r, RedResult) and r.held and r.survived and r.wins == []
    assert r.strategies["neighbourhood"] == 100 and r.strategies["mutation"] > 0 and "model" not in r.strategies
    assert r.attempts == sum(r.strategies.values()) and r.model_inputs == 0
    assert r.seconds >= 0
    assert f.red_team == {**f.red_team, "held": True, "wins": 0, "attempts": r.attempts, "seed": 7, "rounds": 100}
    # red reports; it never touches the gate or the status
    assert f.status is Status.VERIFIED and len(f.gate_history) == before


def test_red_beats_a_planted_shallow_fix_and_the_status_still_stands_until_the_orchestrator_acts():
    f = verified_finding()
    r = red_round(f, ShallowTarget(), reproducer=REPRO, corpus=corpus(), rounds=100, seed=7)
    assert not r.held and r.wins
    assert all(w != REPRO for w in r.wins)                  # the silenced input is not a win; its siblings are
    assert f.red_team["held"] is False and f.red_team["wins"] == len(r.wins)
    assert f.red_team["win_samples"] and bytes.fromhex(f.red_team["win_samples"][0]) in r.wins
    assert f.status is Status.VERIFIED                      # demotion is the orchestrator's call, via repair()+gate


def test_red_is_deterministic_for_a_fixed_seed():
    a = red_round(verified_finding(), ShallowTarget(), reproducer=REPRO, corpus=corpus(), rounds=60, seed=3)
    b = red_round(verified_finding(), ShallowTarget(), reproducer=REPRO, corpus=corpus(), rounds=60, seed=3)
    assert a.wins == b.wins and a.strategies == b.strategies
    c = red_round(verified_finding(), ShallowTarget(), reproducer=REPRO, corpus=corpus(), rounds=60, seed=4)
    assert c.wins != a.wins


def test_model_proposals_are_replayed_and_counted_but_never_decide():
    good = MockClient(['```json\n["hex:484452", "HDRA"]\n```', '["HDRAAAAAAAAAAAAAAAA", "hex:zz", 5]'])
    f = verified_finding()
    r = red_round(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), rounds=20, client=good)
    assert good.calls == 1
    assert r.model_inputs == 3 and r.strategies["model"] == 3 and r.held      # "hex:zz" and 5 are dropped
    assert f.red_team["model_inputs"] == 3
    f2 = verified_finding()
    r2 = red_round(f2, ShallowTarget(), reproducer=REPRO, corpus=corpus(), rounds=0, client=good)
    assert not r2.held and b"HDRAAAAAAAAAAAAAAAA" in r2.wins and r2.strategies == {"model": 3}


def test_a_failing_model_degrades_the_strategy_not_the_round():
    from raksha.inference import InferenceError

    class Broken(MockClient):
        def complete(self, *a, **k):
            raise InferenceError("down")
    r = red_round(verified_finding(), FakeTarget(), reproducer=REPRO, corpus=corpus(), rounds=10, client=Broken([]))
    assert r.held and r.model_inputs == 0 and "model" not in r.strategies


def test_decode_proposals_is_tolerant():
    assert decode_proposals('here: ["a", "hex:0001", "hex:abc", 3, "hex:FF"]') == [b"a", b"\x00\x01", b"\xff"]
    assert decode_proposals("no array here") == []
    assert decode_proposals('{"not": "a list"}') == []
    assert decode_proposals("[not json") == []


def test_red_refuses_anything_that_is_not_verified():
    with pytest.raises(ValueError):
        red_round(patched("real"), FakeTarget(), reproducer=REPRO, corpus=corpus())


def test_the_time_budget_bounds_the_round():
    f = verified_finding()
    r = red_round(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), rounds=100000, seconds=0.05)
    assert r.held and r.attempts < 100000 and r.seconds < 2.0


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_the_real_tlv_fix_holds_against_red():
    from raksha.autorepair import repair
    from raksha.harness import autofuzz
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    corpus_ = [b"\x01\x04abcd", b"\x02zz", b"\x01\x02ab"]
    out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                 corpus=corpus_, use_model=False)
    assert out.verified
    red = red_round(r.finding, r.target, reproducer=r.crashing_input, corpus=corpus_, rounds=60, seconds=3.0)
    assert red.held, f"red beat the template fix with {red.wins[:2]!r}"
    assert red.attempts >= 60 and r.finding.red_team["held"] is True
    assert r.finding.status is Status.VERIFIED
