"""The evidence-fusion kernel — a deterministic assurance calculator, not a learned model.

The external review's third idea: an assurance kernel CALCULATES confidence from independent
evidence channels; the model only ever explains, never decides. This module is that kernel. It fuses
the evidence channels a finding has accumulated into a single transparent confidence number, with a
formula a human can read off the page — a noisy-OR over channel reliabilities, each discounted by how
INDEPENDENT that channel is from the others.

The channels (reliability, independence)
----------------------------------------
  E_exploit        a replaying exploit reproducer fired          reliability high, independence 1.0
  E_deterministic  a deterministic match (dep CVE / secret) fired reliability high, independence 1.0
  E_structural     a static source->sink path (`finding.structure`) moderate, LOWER independence
                   (it is static — correlated with other static reasoning)
  E_crossconfirm   two lanes merged on the same site/CWE          strong, fairly independent
  E_parliament     model votes                                    LOW independence (models correlate)
                   and HARD-CAPPED so the model tier can never dominate the kernel

The invariant this kernel exists to enforce
--------------------------------------------
Fusion can only CORROBORATE; it never manufactures proof. `confidence` is held below the "proven"
threshold unless there is at least one NON-model, reproducing channel (an exploit replay or a
deterministic match). So a finding carried only by a structural path plus model votes stays
low-confidence no matter how loudly the models agree — and, crucially, fusion writes
`finding.evidence_score` and NOTHING ELSE: it never sets status, so a high number cannot promote a
finding out of SUSPECTED. This is the quantitative face of "no reproducer, no report": the gate owns
status; the kernel only measures how much independent evidence corroborates it.

Everything here is deterministic and offline. No network, no model call, no learned weights.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

import json
from pathlib import Path

from .finding import DETERMINISTIC_MATCH, EXPLOIT_REPLAY, Finding

#: Confidence at or above this is "proven". Reachable only with a reproducing non-model channel.
PROVEN_THRESHOLD = 0.85
#: Hard ceiling applied when NO reproducing (exploit/deterministic) channel is present. Below the
#: proven threshold by construction, so structural+model evidence can never read as proof.
NONPROVEN_CAP = 0.6
#: The model tier's contribution is capped here before its independence discount, so even unanimous,
#: maximally-confident model votes cannot by themselves approach the proven threshold.
PARLIAMENT_CAP = 0.5
#: A channel counts toward `independent_channels` only if it is this independent — which excludes the
#: correlated static (structural) and model (parliament) channels by design.
INDEP_THRESHOLD = 0.7

#: Per-channel base reliability (how often this evidence, fired, means a real bug) and independence
#: (how uncorrelated it is with the others). Effective contribution = reliability * independence.
#: These hand values are the PRIORS. G6 measures reliability on a labelled corpus
#: (`python -m raksha.calibrate` -> raksha/data/calibration.json) and the calibrated value replaces
#: the prior wherever there were observations. Independence is not measurable on that corpus and
#: stays a stated prior.
_PRIOR_RELIABILITY = {
    "exploit": 0.97,
    "deterministic": 0.95,
    "crossconfirm": 0.80,
    "structural": 0.60,
    "parliament": 0.50,   # a placeholder; real value is the capped vote strength, see _channels()
}
_INDEPENDENCE = {
    "exploit": 1.0,
    "deterministic": 1.0,
    "crossconfirm": 0.8,
    "structural": 0.6,    # static: correlated with other static reasoning
    "parliament": 0.3,    # models correlate; low independence
}
_CALIBRATION_FILE = Path(__file__).parent / "data" / "calibration.json"


def calibration() -> dict | None:
    """The committed calibration table (G6), or None when it has not been generated."""
    try:
        return json.loads(_CALIBRATION_FILE.read_text())
    except (OSError, ValueError):
        return None


def _reliabilities() -> dict[str, float]:
    rel = dict(_PRIOR_RELIABILITY)
    table = (calibration() or {}).get("channels") or {}
    for name, row in table.items():
        if name in rel and row.get("n"):
            rel[name] = float(row["calibrated"])
    return rel


_RELIABILITY = _reliabilities()

#: The channels that reproduce (a replay or a deterministic re-match). At least one must be present
#: for a finding to be allowed past the proven threshold.
_REPRODUCING = frozenset({"exploit", "deterministic"})
#: Models never carry a finding on their own.
_MODEL_CHANNELS = frozenset({"parliament"})


@dataclass
class EvidenceScore:
    confidence: float = 0.0
    channels: list[str] = field(default_factory=list)
    independent_channels: int = 0
    dominated_by: str | None = None
    rationale: str = ""
    proven: bool = False
    capped: bool = False

    def as_dict(self) -> dict:
        return {
            "confidence": self.confidence,
            "channels": list(self.channels),
            "independent_channels": self.independent_channels,
            "dominated_by": self.dominated_by,
            "proven": self.proven,
            "capped": self.capped,
            "rationale": self.rationale,
        }


def _parliament_strength(finding: Finding) -> float | None:
    """The model channel's reliability: the mean exploitability the panel voted, capped. None when
    there were no votes (e.g. the offline panel), so the channel is simply absent rather than 0."""
    p = finding.parliament or {}
    votes = p.get("votes") or []
    exps = [v.get("exploitability") for v in votes if isinstance(v.get("exploitability"), (int, float))]
    if not exps:
        return None
    return min(PARLIAMENT_CAP, statistics.mean(exps))


def _channels(finding: Finding) -> dict[str, float]:
    """The present channels mapped to their reliability. A channel absent from this dict did not
    fire for this finding and contributes nothing."""
    out: dict[str, float] = {}
    r, rb = finding.reproducer, finding.replay_before
    if r is not None and rb is not None and rb.oracle_fired:
        if r.kind == EXPLOIT_REPLAY:
            out["exploit"] = _RELIABILITY["exploit"]
        elif r.kind == DETERMINISTIC_MATCH:
            out["deterministic"] = _RELIABILITY["deterministic"]
    if finding.structure:
        out["structural"] = _RELIABILITY["structural"]
    if finding.merged_from:
        out["crossconfirm"] = _RELIABILITY["crossconfirm"]
    ps = _parliament_strength(finding)
    if ps is not None:
        out["parliament"] = ps
    return out


def fuse(finding: Finding) -> EvidenceScore:
    """Fuse a finding's evidence channels into a transparent confidence score.

    Formula: noisy-OR over each present channel's effective reliability, where
    `effective = reliability * independence` so a correlated channel (static structural, or the model
    parliament) contributes less. The result is then held below `PROVEN_THRESHOLD` (capped at
    `NONPROVEN_CAP`) unless a reproducing non-model channel is present — the corroborate-only
    invariant. Writes `finding.evidence_score` and returns the score; NEVER changes status.
    """
    chans = _channels(finding)
    if not chans:
        score = EvidenceScore(confidence=0.0, channels=[], independent_channels=0,
                              dominated_by=None, proven=False, capped=False,
                              rationale="no evidence channels; confidence is unestablished")
        finding.evidence_score = score.as_dict()
        return score

    confidence, capped = fuse_channels(chans)
    has_reproducing = bool(_REPRODUCING & chans.keys())
    contributions = {name: rel * _INDEPENDENCE[name] for name, rel in chans.items()}
    dominated_by = max(contributions, key=lambda k: contributions[k])
    independent = sum(1 for name in chans if _INDEPENDENCE[name] >= INDEP_THRESHOLD)
    proven = confidence >= PROVEN_THRESHOLD and has_reproducing

    rationale = _rationale(chans, confidence, dominated_by, has_reproducing, capped)
    score = EvidenceScore(
        confidence=confidence,
        channels=sorted(chans.keys()),
        independent_channels=independent,
        dominated_by=dominated_by,
        proven=proven,
        capped=capped,
        rationale=rationale,
    )
    finding.evidence_score = score.as_dict()
    return score


def fuse_channels(chans: dict[str, float]) -> tuple[float, bool]:
    """(confidence, capped) for a channel -> reliability map: the noisy-OR of effective
    reliabilities, held at NONPROVEN_CAP without a reproducing channel. Shared with the calibrator,
    so the bands it checks are produced by exactly this formula."""
    if not chans:
        return 0.0, False
    product = 1.0
    for name, rel in chans.items():
        product *= (1.0 - rel * _INDEPENDENCE[name])
    confidence = 1.0 - product
    capped = False
    if not (_REPRODUCING & chans.keys()) and confidence > NONPROVEN_CAP:
        confidence, capped = NONPROVEN_CAP, True
    return round(max(0.0, min(1.0, confidence)), 3), capped


_CHANNEL_PHRASE = {
    "exploit": "a replaying exploit reproducer",
    "deterministic": "a deterministic match that re-fired",
    "crossconfirm": "a cross-lane confirmation on the same site",
    "structural": "a static source-to-sink path",
    "parliament": "model votes (capped, low independence)",
}


def _rationale(chans: dict[str, float], confidence: float, dominated_by: str,
               has_reproducing: bool, capped: bool) -> str:
    parts = [f"Confidence {confidence:.2f} from " + ", ".join(
        _CHANNEL_PHRASE.get(c, c) for c in sorted(chans.keys())) + "."]
    parts.append(f"The weight is carried by {_CHANNEL_PHRASE.get(dominated_by, dominated_by)}.")
    if not has_reproducing:
        parts.append("No reproducing channel, so confidence is held below the proven threshold "
                     f"({PROVEN_THRESHOLD:.2f})" + (" (capped)." if capped else "."))
    return " ".join(parts)


def fuse_all(findings) -> dict:
    """Fuse every finding, setting `f.evidence_score` on each, and return a scorecard-shaped summary.

    The summary carries `median_confidence` (None when there is nothing to measure, never a
    flattering 0), the count of findings with at least two independent channels, how many reach the
    proven threshold, and the total count — shaped so the scorecard can read it later.
    """
    findings = list(findings)
    scores = [fuse(f) for f in findings]
    confidences = [s.confidence for s in scores]
    return {
        "count": len(scores),
        "median_confidence": round(statistics.median(confidences), 3) if confidences else None,
        "with_2plus_independent_channels": sum(1 for s in scores if s.independent_channels >= 2),
        "proven": sum(1 for s in scores if s.proven),
    }
