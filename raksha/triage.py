"""The decision funnel — spend the expensive budget only where cheap signals earn it.

The external review's "heterogeneous intelligence" asks for a cheap decision tier in front of the
expensive ones: fuzzing, symbolic execution and the model repair lane cost orders of magnitude more
than reading a signature off a record, so they must run only where a fast, deterministic score says
the site is worth it. This module is that tier.

Why deterministic first, model second
--------------------------------------
`triage_score` is pure arithmetic over features already present on the record — bug-class severity,
a sink keyword, an entry-point name bonus, a structural path, import-level reachability, and a
per-bug-class historical hit rate the caller passes in. No model is consulted and none is needed; the
score is a *measurement* of the evidence on hand, reproducible to the last digit, so the console can
show the same "47k sites -> 4k -> 600 -> 100 -> 17" reduction on every run.

The model assist (`rank_with_triage_model`) is strictly optional and strictly subordinate. It may
only RE-ORDER candidates the deterministic scorer already ranked; it is blended 50/50 and then
floored, so a biased or broken triage model can at most halve an item's rank-score, never zero it.
That is the gate-is-authority rule applied one tier up: triage decides *order of spend*, never
whether a bug exists — so even a hostile triage model cannot hide a real bug, only make us reach it
a little later. With no endpoint configured (the normal offline case) the model path is skipped
entirely and the pure deterministic ranking is returned, and the result says so (`model is None`).

This module is heuristic by construction and says so: a triage score is a *betting odds* on where to
look, not a claim that anything is wrong. Nothing here ever constructs, confirms or reports a
finding; the five-check gate remains the only thing that decides a vulnerability is real.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .harness.entrypoints import Entrypoint, _name_bonus
from .inference import TRIAGE, InferenceError

# --- feature weights (sum to 1.0, so triage_score is in 0..1 by construction) ----------------
#: Severity and reachability dominate, with a sink keyword close behind: a critical, reachable site
#: at a dangerous sink is where attacker data does damage, so it is where the budget should go.
_WEIGHTS = {
    "severity": 0.30,
    "sink": 0.20,
    "reachability": 0.20,
    "structure": 0.10,
    "name": 0.10,
    "history": 0.10,
}

_SEV = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}
#: import-level reachability -> feature value (same ordering the risk register uses).
_REACH = {"imported": 1.0, "unknown": 0.5, "not-imported": 0.1}
#: When no severity / reachability is known, a neutral prior that neither boosts nor buries.
_NEUTRAL_SEV = 0.4
_NEUTRAL_REACH = 0.5
#: A bug class with no history passed in gets a neutral prior, not a flattering 1.0 or a punishing 0.
_DEFAULT_HIST = 0.5

#: Sink keywords: the places untrusted data becomes dangerous. Substring match, case-insensitive.
_SINK_KEYWORDS = (
    "system", "exec", "eval", "popen", "subprocess", "shell", "os.system",
    "sql", "query", "select ", "deserial", "pickle", "unmarshal", "yaml.load",
    "overflow", "memcpy", "strcpy", "strcat", "sprintf", "gets", "alloca",
    "injection", "jndi", "lookup", "format", "printf", "traversal", "path", "open(",
    "ldap", "xpath", "xxe", "ssrf", "redirect", "template", "regex",
)

#: The 50/50 blend plus this floor is the anti-veto guarantee: the model-blended score can never
#: fall below `_MODEL_FLOOR` of the deterministic score, so the model re-orders but cannot drop a
#: high-signal item out of contention. Keep it equal to the deterministic blend weight.
_MODEL_FLOOR = 0.5


@dataclass(frozen=True)
class TriageItem:
    """A minimal candidate when the caller has neither a Finding nor an Entrypoint.

    `signals` carries any of the feature keys `triage_score` reads: `severity` (a band string),
    `sink` (bool), `name` (a symbol for the entry-point name bonus), `structure` (truthy if a
    structural path exists), `reachability` (imported/unknown/not-imported), `bug_class` /
    `hist_class` (the key into the historical hit-rate table) and `text` (free text scanned for a
    sink keyword). Every key is optional; absent ones fall back to the documented neutral priors.
    """

    kind: str
    signals: dict = field(default_factory=dict)


@dataclass
class FunnelResult:
    """The record of one cascade of cut-offs, for the console to render and a human to trust.

    `stages` holds one `{name, entered, survived}` dict per stage, in order, so the reduction is
    auditable end to end. `kept` is the survivors of the last stage. `reduction_ratio` is the
    fraction of the original items that survived (`len(kept) / entered of stage 0`); lower means a
    more aggressive funnel. It is None when there was nothing to funnel.
    """

    stages: list[dict] = field(default_factory=list)
    kept: list = field(default_factory=list)
    reduction_ratio: float | None = None


# ---------------------------------------------------------------- feature extraction

def _extract(candidate: Any) -> dict:
    """Pull the raw feature inputs off any supported candidate into one normalised dict.

    Supported: `Finding`, `Entrypoint`, `TriageItem`, or any object exposing a `signals` dict.
    Deterministic and side-effect free.
    """
    # TriageItem / anything with a signals dict: the explicit escape hatch.
    sig = getattr(candidate, "signals", None)
    if isinstance(sig, dict):
        return {
            "severity": (sig.get("severity") or "").lower() or None,
            "text": " ".join(str(sig.get(k, "")) for k in ("text", "bug_class", "name"))
            + " " + str(getattr(candidate, "kind", "")),
            "sink_explicit": sig.get("sink"),
            "name": str(sig.get("name", "")),
            "structure": bool(sig.get("structure")),
            "reachability": sig.get("reachability"),
            "hist_class": sig.get("bug_class") or sig.get("hist_class") or getattr(candidate, "kind", None),
        }
    # Entrypoint: no severity / reachability of its own; its kind and name carry the signal.
    if isinstance(candidate, Entrypoint):
        return {
            "severity": None,
            "text": f"{candidate.symbol} {candidate.signature} {candidate.kind}",
            "sink_explicit": None,
            "name": candidate.symbol,
            "structure": False,
            "reachability": None,
            "hist_class": candidate.kind,
        }
    # Otherwise treat it as a Finding (duck-typed, so a Finding import is not required here).
    frames = list(getattr(candidate, "frames", []) or [])
    sym = frames[0].symbol if frames else (getattr(candidate, "bug_class", "") or "")
    text = " ".join(str(x) for x in (
        getattr(candidate, "bug_class", ""), getattr(candidate, "message", ""),
        getattr(candidate, "oracle", ""), *(f.symbol for f in frames)))
    return {
        "severity": (getattr(candidate, "severity", "") or "").lower() or None,
        "text": text,
        "sink_explicit": None,
        "name": sym,
        "structure": bool(getattr(candidate, "structure", None)),
        "reachability": getattr(candidate, "reachability", None),
        "hist_class": getattr(candidate, "bug_class", None),
    }


def _has_sink(text: str) -> bool:
    low = text.lower()
    return any(k in low for k in _SINK_KEYWORDS)


def _features(candidate: Any, hit_rates: dict[str, float]) -> dict[str, float]:
    """The six normalised sub-scores (each 0..1) that `triage_score` combines."""
    raw = _extract(candidate)
    sink = raw["sink_explicit"]
    if sink is None:
        sink = _has_sink(raw["text"])
    hist_class = raw["hist_class"]
    return {
        "severity": _SEV.get(raw["severity"], _NEUTRAL_SEV),
        "sink": 1.0 if sink else 0.0,
        "name": 1.0 if _name_bonus(raw["name"]) > 0 else 0.0,
        "structure": 1.0 if raw["structure"] else 0.0,
        "reachability": _REACH.get(raw["reachability"], _NEUTRAL_REACH),
        "history": hit_rates.get(hist_class, _DEFAULT_HIST) if hist_class else _DEFAULT_HIST,
    }


def triage_score(candidate: Any, *, hit_rates: dict[str, float] | None = None) -> float:
    """A deterministic 0..1 betting-odds on whether a candidate is worth expensive work.

    Pure arithmetic over features already on the record (see module docstring). `hit_rates` is an
    optional per-bug-class historical success table, e.g. `{"CWE-121": 0.8}`; an absent class gets a
    neutral prior. This is a HEURISTIC ranking signal, never a claim that a bug exists.
    """
    f = _features(candidate, hit_rates or {})
    score = sum(f[k] * _WEIGHTS[k] for k in _WEIGHTS)
    return max(0.0, min(1.0, score))


# ---------------------------------------------------------------- the funnel

def funnel(items: list, *, stages: list[tuple[str, float, int]],
           hit_rates: dict[str, float] | None = None) -> FunnelResult:
    """Apply successive (name, min_score, max_keep) cut-offs, recording survival at each stage.

    Deterministic and O(n log n): every item is scored once, then each stage keeps those at or above
    its `min_score`, orders them by score (ties broken by original position, so the order is stable),
    and truncates to `max_keep`. The returned `FunnelResult` records how many entered and survived
    each stage so the console can show the reduction honestly.
    """
    hit_rates = hit_rates or {}
    # Score once; carry the original index as a stable tie-breaker.
    scored = [(triage_score(it, hit_rates=hit_rates), i, it) for i, it in enumerate(items)]
    initial = len(scored)
    out_stages: list[dict] = []
    current = scored
    for name, min_score, max_keep in stages:
        entered = len(current)
        survivors = [t for t in current if t[0] >= min_score]
        survivors.sort(key=lambda t: (-t[0], t[1]))
        if max_keep is not None and max_keep >= 0:
            survivors = survivors[:max_keep]
        out_stages.append({"name": name, "entered": entered, "survived": len(survivors)})
        current = survivors
    kept = [t[2] for t in current]
    ratio = round(len(kept) / initial, 6) if initial else None
    return FunnelResult(stages=out_stages, kept=kept, reduction_ratio=ratio)


# ---------------------------------------------------------------- optional model assist

@dataclass
class RankedItem:
    """One ranked candidate. `model` is None on the offline / fallback path, so the caller can see
    whether the model was consulted at all."""

    item: Any
    score: float          # the score used for ordering (blended + floored when a model voted)
    deterministic: float
    model: float | None = None


def _parse_model_scores(reply: str, n: int) -> list[float] | None:
    """Parse exactly `n` floats in 0..1 from the model's reply, or None if it does not comply."""
    nums = re.findall(r"[-+]?\d*\.?\d+", reply)
    if len(nums) < n:
        return None
    out: list[float] = []
    for s in nums[:n]:
        try:
            out.append(max(0.0, min(1.0, float(s))))
        except ValueError:
            return None
    return out


def rank_with_triage_model(items: list, *, client=None,
                           hit_rates: dict[str, float] | None = None) -> list[RankedItem]:
    """Rank candidates, re-ordered by a cheap TRIAGE model when one is configured.

    One batched call (role=TRIAGE, low temperature) asks the model for a 0..1 score per item; the
    result is blended 50/50 with `triage_score` and then floored, so the model can REORDER but never
    VETO: the blended score can never fall below `_MODEL_FLOOR` of the deterministic score. A biased
    triage model therefore cannot bury a high-signal site below the floor and hide a real bug.

    With `client is None` (the normal offline case) or on any model/parse failure, the function falls
    back to the pure deterministic ranking and the returned `RankedItem`s carry `model=None`, so the
    caller can tell the model was not consulted. Ordering is deterministic in both paths.
    """
    hit_rates = hit_rates or {}
    det = [triage_score(it, hit_rates=hit_rates) for it in items]

    if client is None or len(items) < 2:
        # Offline / nothing to re-order: pure deterministic ranking, model=None. Python's sort is
        # stable, so ties keep their original order.
        return sorted(
            (RankedItem(it, d, d, None) for it, d in zip(items, det)),
            key=lambda r: -r.score,
        )

    listing = "\n".join(f"{i}: {_describe(it)}" for i, it in enumerate(items))
    prompt = [
        {"role": "system", "content": "You triage candidate code sites for a security pipeline. "
         "For each numbered candidate, output a worth-investigating score from 0 to 1. Return ONLY "
         "a comma-separated list of scores in the SAME order as the candidates, nothing else."},
        {"role": "user", "content": listing},
    ]
    model_scores: list[float] | None = None
    try:
        reply = client.complete(prompt, role=TRIAGE, temperature=0.1, n=1)[0]
        model_scores = _parse_model_scores(reply, len(items))
    except (InferenceError, IndexError, KeyError):
        model_scores = None

    ranked: list[RankedItem] = []
    for it, d, idx in zip(items, det, range(len(items))):
        if model_scores is None:
            ranked.append(RankedItem(it, d, d, None))
            continue
        m = model_scores[idx]
        blended = 0.5 * d + 0.5 * m
        floored = max(blended, _MODEL_FLOOR * d)   # the model can at most halve the rank-score
        ranked.append(RankedItem(it, floored, d, m))
    ranked.sort(key=lambda r: -r.score)
    return ranked


def _describe(item: Any) -> str:
    """A short, deterministic one-line description of a candidate for the model listing."""
    if isinstance(item, Entrypoint):
        return f"{item.language} entrypoint {item.symbol} [{item.signature}]"
    bc = getattr(item, "bug_class", None)
    if bc is not None:
        return f"{getattr(item, 'language', '?')} {bc} {str(getattr(item, 'message', ''))[:80]}"
    return f"{getattr(item, 'kind', 'item')}"
