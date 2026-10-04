"""The model parliament — no single model decides, and disagreement is itself a signal.

The external review's second idea: never trust one reasoner, and treat the places your reasoners
disagree as the places to look harder. This module convenes a *panel* of model roles, has each one
classify a finding INDEPENDENTLY, records every vote, and measures how much they diverge.

What it is, and the one rule it obeys
-------------------------------------
The parliament NEVER sets a finding's status and NEVER changes what the five-check gate decided. Its
only effects are to (a) annotate the record under `finding.parliament`, and (b) return a boolean
`flag_for_investigation` that is true when the measured disagreement exceeds a threshold. That flag
is a hook for the orchestrator to spend MORE analysis on a finding — it can only raise scrutiny,
never lower it. A unanimous panel does not make a finding more real; a divided panel does not make
it less real. Only the gate decides that. This is the gate-is-authority rule, applied to the model
tier: models propose and vote, the gate adjudicates.

Offline honesty
---------------
With no model endpoint there is no panel. `convene` then returns `disagreement=None` (UNMEASURED,
not a flattering 0.0), `quorum=0`, and a note that says plainly there was no independent panel and
the gate remains the sole authority. A single-model panel is treated the same way — you cannot
measure disagreement with one voter.

`epistemic_conflict` is the offline substitute: a deterministic, model-free conflict signal fused
from channels the pipeline already produces (did the dynamic reproducer, the structural lane and the
cross-confirm merge all corroborate each other?). It needs no model, so it works air-gapped, and it
is documented as the stand-in for the panel when no models are available.

Everything here is a HEURISTIC scrutiny signal. Nothing in this module constructs, confirms, patches
or reports a finding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .finding import DETERMINISTIC_MATCH, EXPLOIT_REPLAY, Finding
from .inference import ADVISOR, JUDGE, RED, InferenceError

#: Disagreement above this fraction trips `flag_for_investigation`.
_DEFAULT_THRESHOLD = 0.5

_SEV_BANDS = ("critical", "high", "medium", "low")


def _severity_band(text: str) -> str | None:
    low = text.lower()
    for band in _SEV_BANDS:
        if band in low:
            return band
    return None


def _cwe_class(cwe: str | None) -> str | None:
    """Normalise a voted CWE to a comparable identifier (e.g. 'cwe-121').

    HEURISTIC: this compares the voted CWE id, normalised for case and separator. It does not walk
    the CWE tree, so two siblings in the same family (CWE-121 vs CWE-122) read as a disagreement —
    which is the honest outcome here: the panel disagreeing on the exact weakness IS a divergence
    worth flagging. A finer taxonomy mapping would only ever lower disagreement, never raise it.
    """
    if not cwe:
        return None
    m = re.search(r"cwe[-\s]?(\d+)", cwe, re.IGNORECASE)
    return f"cwe-{m.group(1)}" if m else cwe.strip().lower()


def _exploitability_band(x: float | None) -> str | None:
    if x is None:
        return None
    if x > 0.66:
        return "high"
    if x >= 0.34:
        return "medium"
    return "low"


def _parse_vote(role: str, reply: str, model: str) -> dict:
    """Turn one model reply into a structured vote. Tolerant: accepts JSON or free text."""
    cwe: str | None = None
    severity: str | None = None
    exploitability: float | None = None
    # Prefer a JSON object if the model emitted one.
    m = re.search(r"\{.*\}", reply, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group(0))
            cwe = obj.get("cwe") or obj.get("CWE")
            severity = (obj.get("severity") or "").lower() or None
            ex = obj.get("exploitability")
            exploitability = float(ex) if ex is not None else None
        except (ValueError, TypeError, AttributeError):
            pass
    if cwe is None:
        cm = re.search(r"cwe[-\s]?\d+", reply, re.IGNORECASE)
        cwe = cm.group(0) if cm else None
    if severity is None:
        severity = _severity_band(reply)
    if exploitability is None:
        em = re.search(r"exploitability[\"']?\s*[:=]?\s*([01](?:\.\d+)?)", reply, re.IGNORECASE)
        if not em:
            em = re.search(r"\b(0(?:\.\d+)?|1(?:\.0+)?)\b", reply)
        if em:
            try:
                exploitability = max(0.0, min(1.0, float(em.group(1))))
            except ValueError:
                exploitability = None
    return {
        "role": role,
        "model": model,
        "cwe": cwe,
        "cwe_class": _cwe_class(cwe),
        "severity": severity,
        "exploitability": exploitability,
    }


def _disagreement(votes: list[dict]) -> float:
    """Fraction of pairwise disagreements across the axes {CWE class, severity band, exploitability
    band}: 0.0 when every voter agrees on every axis, up to 1.0 when every pair differs on every
    axis. Axes where neither voter expressed an opinion are skipped (not counted as agreement)."""
    axes = ("cwe_class", "severity", "exp_band")
    enriched = [{**v, "exp_band": _exploitability_band(v.get("exploitability"))} for v in votes]
    pairs = [(a, b) for i, a in enumerate(enriched) for b in enriched[i + 1:]]
    comparisons = 0
    disagreements = 0
    for a, b in pairs:
        for axis in axes:
            av, bv = a.get(axis), b.get(axis)
            if av is None and bv is None:
                continue
            comparisons += 1
            if av != bv:
                disagreements += 1
    return round(disagreements / comparisons, 3) if comparisons else 0.0


_AXES = ("cwe_class", "severity", "exp_band")


def _by_axis(votes: list[dict]) -> dict:
    """G4: disagreement per axis (None where nobody voted on it)."""
    enriched = [{**v, "exp_band": _exploitability_band(v.get("exploitability"))} for v in votes]
    out = {}
    for axis in _AXES:
        vals = [v.get(axis) for v in enriched if v.get(axis) is not None]
        pairs = [(a, b) for i, a in enumerate(vals) for b in vals[i + 1:]]
        out[axis] = round(sum(a != b for a, b in pairs) / len(pairs), 3) if pairs else None
    return out


def _pairwise(votes: list[dict]) -> dict:
    """G4: disagreement for each pair of roles, e.g. {"advisor|red": 0.667}."""
    out = {}
    for i, a in enumerate(votes):
        for b in votes[i + 1:]:
            out[f"{a['role']}|{b['role']}"] = _disagreement([a, b])
    return out


@dataclass
class Verdicts:
    """The panel's record. `disagreement` is None when it could not be measured (no panel)."""

    votes: list[dict] = field(default_factory=list)
    disagreement: float | None = None
    quorum: int = 0
    panel: list[str] = field(default_factory=list)
    flag_for_investigation: bool = False
    note: str | None = None
    by_axis: dict | None = None            # G4: disagreement per axis
    pairwise: dict | None = None           # G4: disagreement per pair of roles
    independent_models: int = 0            # G4: distinct models among the voters

    def as_dict(self) -> dict:
        return {
            "votes": list(self.votes),
            "disagreement": self.disagreement,
            "panel": list(self.panel),
            "quorum": self.quorum,
            "flag_for_investigation": self.flag_for_investigation,
            "note": self.note,
            "by_axis": self.by_axis,
            "pairwise": self.pairwise,
            "independent_models": self.independent_models,
        }


_SINGLE_SOURCE_NOTE = ("single-source: no independent panel offline; gate remains sole authority")


def convene(finding: Finding, *, client=None, panel: tuple[str, ...] = (ADVISOR, JUDGE, RED),
            threshold: float = _DEFAULT_THRESHOLD) -> Verdicts:
    """Ask each role in `panel` to classify the finding independently; record and measure the votes.

    Each role gets its own call (its own model via `config.model_for(role)`), so the votes are
    genuinely independent. The result is written to `finding.parliament` and returned. STATUS IS
    NEVER TOUCHED and the gate's verdict is never changed — the only live effect is
    `flag_for_investigation`, true when disagreement exceeds `threshold`, which tells the
    orchestrator to spend more analysis here (it raises scrutiny, never lowers it).

    Offline (`client is None`) or with fewer than two voters, there is no panel to measure:
    `disagreement` is None (unmeasured, not 0.0), `quorum` is the number of voters, and `note`
    says the gate remains the sole authority.
    """
    votes: list[dict] = []
    if client is not None:
        for role in panel:
            prompt = _prompt(finding, role)
            try:
                model = client.config.model_for(role)
            except AttributeError:
                model = role
            try:
                reply = client.complete(prompt, role=role, temperature=0.1, n=1)[0]
            except (InferenceError, IndexError, KeyError):
                continue
            vote = _parse_vote(role, reply, model)
            if role == RED:
                am = re.search(r'"attack"\s*:\s*"([^"]{1,300})"', reply)
                vote["attack"] = am.group(1) if am else None   # annotation only; never executed
            votes.append(vote)

    if len(votes) < 2:
        verdicts = Verdicts(
            votes=votes,
            disagreement=None,
            quorum=len(votes),
            panel=list(panel),
            flag_for_investigation=False,
            note=_SINGLE_SOURCE_NOTE,
            independent_models=len({v["model"] for v in votes}),
        )
    else:
        d = _disagreement(votes)
        verdicts = Verdicts(
            votes=votes,
            disagreement=d,
            quorum=len(votes),
            panel=list(panel),
            flag_for_investigation=d > threshold,
            note=(None if len({v["model"] for v in votes}) == len(votes) else
                  f"{len({v['model'] for v in votes})} distinct model(s) behind {len(votes)} roles: "
                  "votes from one model are not independent"),
            by_axis=_by_axis(votes),
            pairwise=_pairwise(votes),
            independent_models=len({v["model"] for v in votes}),
        )

    # Annotate only. Status is the gate's; we never call a transition method.
    finding.parliament = verdicts.as_dict()
    return verdicts


_ROLE_BRIEF = {
    ADVISOR: "You are the security specialist on a review panel. Classify the reported finding.",
    JUDGE: "You give an independent second opinion. You have not seen anyone else's review; "
           "classify the reported finding on its own evidence.",
    RED: "You are the independent attacker on the panel. Judge the finding as someone who wants to "
         "exploit it: how real and how reachable is it? Add a one-line \"attack\" sketch (a "
         "description only; nothing will be run).",
}


def _prompt(finding: Finding, role: str = ADVISOR) -> list[dict]:
    extra = ', "attack": "<one line>"' if role == RED else ""
    return [
        {"role": "system", "content": _ROLE_BRIEF.get(role, _ROLE_BRIEF[ADVISOR]) + " Respond ONLY "
         'with a JSON object: {"cwe": "CWE-nnn", "severity": "critical|high|medium|low", '
         '"exploitability": 0.0-1.0' + extra + "}."},
        {"role": "user", "content": f"bug_class={finding.bug_class} oracle={finding.oracle} "
         f"language={finding.language} severity={finding.severity}\nmessage: {finding.message}"},
    ]


# ---------------------------------------------------------------- offline conflict signal

def _dynamic_fired(finding: Finding) -> bool:
    """The dynamic channel: a reproducer was replayed and the oracle fired (exploit OR det. match)."""
    r, rb = finding.reproducer, finding.replay_before
    return (r is not None and rb is not None and rb.oracle_fired
            and r.kind in (EXPLOIT_REPLAY, DETERMINISTIC_MATCH))


def epistemic_conflict(finding: Finding) -> float | None:
    """A deterministic, offline conflict signal — the stand-in for the model panel when air-gapped.

    It fuses three channels the pipeline already produces and asks whether they corroborate each
    other: the dynamic oracle (a reproducer that fired), the structural lane (`finding.structure`'s
    source->sink path) and the cross-confirm merge (`finding.merged_from`). When two or more of these
    channels exist, a channel that is ABSENT where its siblings fired is an epistemic gap worth
    noting — e.g. a crash cross-confirmed by two lanes that the structural lane never found a path
    to, or a structural path no dynamic run ever triggered.

    Returns the fraction of the three channels that are missing (0.0 = all three corroborate; ~0.33 =
    one of a corroborating pair is silent — a mild conflict), or None when there is only one (or no)
    channel, because a single channel has nothing to be checked against. This is a HEURISTIC gap
    measure, not a measurement of logical contradiction, and never touches status.
    """
    channels = {
        "dynamic": _dynamic_fired(finding),
        "structural": bool(finding.structure),
        "crossconfirm": bool(finding.merged_from),
    }
    present = [k for k, v in channels.items() if v]
    if len(present) <= 1:
        return None
    absent = len(channels) - len(present)
    return round(absent / len(channels), 3)
