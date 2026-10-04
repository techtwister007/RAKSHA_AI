"""The evidence-fusion kernel: corroborate-only confidence, the anti-model-dominance cap, and the
invariant that fusion never promotes a finding out of SUSPECTED."""

from __future__ import annotations

from raksha.evidence import (
    NONPROVEN_CAP,
    PROVEN_THRESHOLD,
    EvidenceScore,
    fuse,
    fuse_all,
)
from raksha.finding import (
    DETERMINISTIC_MATCH,
    EXPLOIT_REPLAY,
    Finding,
    Reproducer,
    ReplayResult,
    Status,
    utcnow,
)


def _finding():
    return Finding(oracle="asan", bug_class="CWE-121", language="c", target="t",
                   message="overflow", severity="high")


def _with_reproducer(f, kind=EXPLOIT_REPLAY, fired=True):
    f.attach_reproducer(Reproducer.from_bytes(b"\x01\x02", ["./replay"], kind=kind))
    f.record_replay_before(ReplayResult(oracle_fired=fired, at=utcnow()))
    return f


def _parliament(f, exploitability=0.9, n=2):
    f.parliament = {"votes": [{"role": "advisor", "exploitability": exploitability}] * n,
                    "disagreement": 0.0, "panel": ["advisor", "judge"], "quorum": n}
    return f


# ---------------------------------------------------------------- single channels

def test_exploit_only_is_high_and_proven():
    s = fuse(_with_reproducer(_finding()))
    assert s.confidence >= PROVEN_THRESHOLD
    assert s.proven is True
    assert s.channels == ["exploit"]
    assert s.dominated_by == "exploit"
    assert s.independent_channels == 1


def test_deterministic_match_alone_is_proven():
    s = fuse(_with_reproducer(_finding(), kind=DETERMINISTIC_MATCH))
    assert s.confidence >= PROVEN_THRESHOLD and s.proven is True
    assert s.channels == ["deterministic"]


def test_model_votes_alone_can_never_reach_proven():
    # the anti-model-dominance cap: no reproducing channel, so confidence is held down
    s = fuse(_parliament(_finding(), exploitability=1.0, n=3))
    assert s.channels == ["parliament"]
    assert s.confidence < PROVEN_THRESHOLD
    assert s.proven is False
    assert s.independent_channels == 0            # models do not count as independent


# ---------------------------------------------------------------- corroboration

def test_exploit_plus_structural_plus_crossconfirm_is_higher_but_capped_at_one():
    base = fuse(_with_reproducer(_finding())).confidence
    f = _with_reproducer(_finding())
    f.structure = {"path": ["src", "sink"]}
    f.merged_from.append("other-id")
    s = fuse(f)
    assert s.confidence > base            # corroboration raises it
    assert s.confidence <= 1.0            # but never above 1.0
    assert s.independent_channels >= 2    # exploit + crossconfirm are independent
    assert set(s.channels) == {"exploit", "structural", "crossconfirm"}


def test_structural_plus_parliament_only_stays_below_proven_and_status_unchanged():
    f = _finding()
    f.structure = {"path": ["src", "sink"]}
    _parliament(f, exploitability=1.0, n=3)
    assert f.status is Status.SUSPECTED
    s = fuse(f)
    assert s.confidence < PROVEN_THRESHOLD
    assert s.capped or s.confidence <= NONPROVEN_CAP
    assert s.proven is False
    assert f.status is Status.SUSPECTED           # fusion NEVER promotes out of SUSPECTED
    assert f.evidence_score["confidence"] == s.confidence


def test_no_channels_is_zero_and_honest():
    s = fuse(_finding())
    assert s.confidence == 0.0 and s.channels == [] and s.dominated_by is None
    assert s.proven is False
    assert "unestablished" in s.rationale


def test_a_reproducer_that_did_not_fire_is_not_a_channel():
    f = _with_reproducer(_finding(), fired=False)
    s = fuse(f)
    assert "exploit" not in s.channels            # possessing an artifact is not evidence


def test_offline_parliament_with_no_votes_contributes_nothing():
    f = _with_reproducer(_finding())
    f.parliament = {"votes": [], "disagreement": None, "panel": [], "quorum": 0}
    s = fuse(f)
    assert "parliament" not in s.channels


# ---------------------------------------------------------------- fuse_all summary

def test_fuse_all_sets_scores_and_summarises():
    a = _with_reproducer(_finding())              # exploit only: 1 independent channel
    b = _with_reproducer(_finding())
    b.structure = {"path": ["s", "k"]}
    b.merged_from.append("x")                     # exploit + crossconfirm: >=2 independent
    c = _finding()                                # no channels
    summary = fuse_all([a, b, c])
    assert summary["count"] == 3
    assert summary["with_2plus_independent_channels"] == 1
    assert summary["proven"] == 2                 # a and b reproduce
    assert summary["median_confidence"] is not None
    for f in (a, b, c):
        assert f.evidence_score is not None       # every finding got its score set


def test_fuse_all_empty_median_is_none_not_zero():
    assert fuse_all([])["median_confidence"] is None


def test_evidence_score_is_the_documented_dict_shape():
    s = fuse(_with_reproducer(_finding()))
    assert isinstance(s, EvidenceScore)
    assert set(s.as_dict()) == {"confidence", "channels", "independent_channels",
                                "dominated_by", "proven", "capped", "rationale"}
