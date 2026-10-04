"""The model parliament: records votes, measures disagreement, flags divergence for investigation,
NEVER touches status; and the offline epistemic-conflict substitute."""

from __future__ import annotations

from types import SimpleNamespace

from raksha.finding import (
    DETERMINISTIC_MATCH,
    EXPLOIT_REPLAY,
    Finding,
    Reproducer,
    ReplayResult,
    Status,
    utcnow,
)
from raksha.inference import ADVISOR, JUDGE, RED
from raksha.parliament import convene, epistemic_conflict


class RoleMockClient:
    """Returns a different completion per role, so the panel's votes can be made to diverge."""

    def __init__(self, by_role):
        self._by_role = by_role
        self.config = SimpleNamespace(model_for=lambda role: f"mock-{role}-model")

    def complete(self, messages, *, role="advisor", n=1, temperature=0.0, max_tokens=1024):
        return [self._by_role[role]]


def _finding():
    return Finding(oracle="asan", bug_class="CWE-121", language="c", target="t",
                   message="overflow", severity="high")


def _reproduced(finding, kind=EXPLOIT_REPLAY):
    """Drive a finding to CONFIRMED with a replaying reproducer, so we can assert status is untouched."""
    finding.attach_reproducer(Reproducer.from_bytes(b"\x01\x02", ["./replay"], kind=kind))
    finding.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    finding.confirm()
    return finding


# ---------------------------------------------------------------- convene (panel)

def test_divergent_panel_has_high_disagreement_and_flags():
    f = _finding()
    client = RoleMockClient({
        ADVISOR: '{"cwe": "CWE-121", "severity": "critical", "exploitability": 0.9}',
        JUDGE: '{"cwe": "CWE-787", "severity": "low", "exploitability": 0.1}',
    })
    v = convene(f, client=client)
    assert v.quorum == 2
    assert v.disagreement is not None and v.disagreement > 0.5
    assert v.flag_for_investigation is True
    # exactly the documented shape is written onto the record
    assert set(f.parliament) == {"votes", "disagreement", "panel", "quorum",
                                 "flag_for_investigation", "note", "by_axis", "pairwise",
                                 "independent_models"}
    assert f.parliament["disagreement"] == v.disagreement


def test_unanimous_panel_has_zero_disagreement_and_does_not_flag():
    f = _finding()
    same = '{"cwe": "CWE-121", "severity": "high", "exploitability": 0.8}'
    v = convene(f, client=RoleMockClient({ADVISOR: same, JUDGE: same}))
    assert v.disagreement == 0.0
    assert v.flag_for_investigation is False


def test_parliament_never_touches_status():
    f = _reproduced(_finding())
    assert f.status is Status.CONFIRMED
    client = RoleMockClient({
        ADVISOR: '{"cwe": "CWE-121", "severity": "critical", "exploitability": 0.9}',
        JUDGE: '{"cwe": "CWE-999", "severity": "low", "exploitability": 0.0}',
    })
    convene(f, client=client)
    assert f.status is Status.CONFIRMED          # annotation only; the gate owns status


def test_offline_returns_unmeasured_not_zero():
    f = _finding()
    v = convene(f, client=None)
    assert v.disagreement is None                # honest: unmeasured, NOT a flattering 0.0
    assert v.quorum == 0
    assert v.flag_for_investigation is False
    assert "gate remains sole authority" in v.note
    assert f.parliament["disagreement"] is None


def test_single_voter_is_single_source():
    f = _finding()
    v = convene(f, client=RoleMockClient({ADVISOR: '{"cwe":"CWE-121","severity":"high","exploitability":0.5}'}),
                panel=(ADVISOR,))
    assert v.disagreement is None and v.quorum == 1
    assert v.note is not None


def test_threshold_controls_the_flag():
    f = _finding()
    # agree on CWE + severity, differ only on exploitability band -> disagreement = 1/3 ~ 0.333
    client = RoleMockClient({
        ADVISOR: '{"cwe": "CWE-121", "severity": "high", "exploitability": 0.9}',
        JUDGE: '{"cwe": "CWE-121", "severity": "high", "exploitability": 0.1}',
    })
    v = convene(f, client=client)
    assert 0.3 < v.disagreement < 0.4
    assert v.flag_for_investigation is False               # 0.333 < default 0.5
    v2 = convene(_finding(), client=client, threshold=0.2)
    assert v2.flag_for_investigation is True                # same divergence, lower bar


# ---------------------------------------------------------------- epistemic_conflict (offline)

def test_conflict_fires_on_a_channel_mismatch():
    # dynamic + crossconfirm present, but the structural lane found no path -> a mild gap
    f = _reproduced(_finding())
    f.merged_from.append("some-other-id")
    assert f.structure is None
    c = epistemic_conflict(f)
    assert c is not None and c > 0.0


def test_conflict_is_none_with_a_single_channel():
    f = _reproduced(_finding())                  # only the dynamic channel
    assert not f.merged_from and f.structure is None
    assert epistemic_conflict(f) is None


def test_conflict_is_zero_when_all_three_channels_corroborate():
    f = _reproduced(_finding())
    f.structure = {"path": ["source", "sink"]}
    f.merged_from.append("other")
    assert epistemic_conflict(f) == 0.0


def test_structural_only_finding_has_no_conflict():
    f = _finding()
    f.structure = {"path": ["source", "sink"]}   # single (structural) channel
    assert epistemic_conflict(f) is None


def test_deterministic_match_channel_counts_as_dynamic():
    f = _reproduced(_finding(), kind=DETERMINISTIC_MATCH)
    f.structure = {"path": ["a", "b"]}           # dynamic (det-match) + structural = 2 channels
    c = epistemic_conflict(f)
    assert c is not None and c > 0.0             # crossconfirm absent -> mild gap



# ---------------------------------------------------------------- G4: three roles

def test_three_roles_measured_per_axis_and_per_pair():
    f = _finding()
    client = RoleMockClient({
        ADVISOR: '{"cwe": "CWE-121", "severity": "high", "exploitability": 0.8}',
        JUDGE: '{"cwe": "CWE-121", "severity": "high", "exploitability": 0.7}',
        RED: '{"cwe": "CWE-787", "severity": "critical", "exploitability": 0.95, '
             '"attack": "length byte 0xff overruns value[32] into the return address"}',
    })
    v = convene(f, client=client)
    assert v.quorum == 3 and v.independent_models == 3 and v.note is None
    assert v.pairwise["advisor|judge"] == 0.0                  # the specialists agree
    assert v.pairwise["advisor|red"] > 0.5                      # the attacker sees it differently
    assert v.by_axis["cwe_class"] > 0 and v.by_axis["exp_band"] == 0.0
    red = next(x for x in f.parliament["votes"] if x["role"] == RED)
    assert "overruns" in red["attack"]


def test_roles_on_one_model_are_marked_not_independent():
    f = _finding()
    same = '{"cwe": "CWE-121", "severity": "high", "exploitability": 0.8}'
    client = RoleMockClient({ADVISOR: same, JUDGE: same, RED: same})
    client.config = SimpleNamespace(model_for=lambda role: "one-model")
    v = convene(f, client=client)
    assert v.independent_models == 1 and "not independent" in v.note


def test_attacker_prompt_is_role_specific():
    from raksha.parliament import _prompt
    assert "attacker" in _prompt(_finding(), RED)[0]["content"]
    assert "attack" not in _prompt(_finding(), ADVISOR)[0]["content"].lower().replace("attacker", "")
