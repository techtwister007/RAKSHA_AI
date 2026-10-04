"""G5 — the scientific method, made explicit on every finding's record.

RAKSHA already works this way: it forms a hypothesis (this input reaches a defect; this patch removes
it), runs an experiment (replay the reproducer; run the five-check gate; ask the solver; attack the
patch), observes the outcome, and concludes. This module writes those cycles down, one per question,
from events the record ALREADY holds — transitions, the reproducer and its replay, every gate result
of every repair round, the analytic proofs and the red team. Nothing here is measured afresh and
nothing is asserted that the record does not show; a cycle with no experiment yet says so.
"""

from __future__ import annotations

from .finding import DETERMINISTIC_MATCH, GATE_ORDER, GateCheck, Finding, Status

_CHECK_WORDS = {
    GateCheck.COMPILES: "the patched build compiles",
    GateCheck.POV_DEAD: "the original attack no longer fires",
    GateCheck.DIFFERENTIAL_CORPUS: "legitimate inputs behave identically",
    GateCheck.COVERAGE_HELD: "the fixed code is still exercised",
    GateCheck.CLEAN_REFUZZ: "a fresh attack campaign finds nothing new",
}


def _site(f: Finding) -> str:
    s = f.fix_site_set[0] if f.fix_site_set else None
    if s is None:
        return f.target
    return f"{s.uri}:{s.start_line}" if s.start_line else s.uri


def _detection(f: Finding) -> dict:
    r, rb = f.reproducer, f.replay_before
    if r is not None and r.kind == DETERMINISTIC_MATCH:
        hyp = f"the artifact at {_site(f)} carries a known weakness ({f.bug_class})"
        exp = f"re-run the deterministic detector ({' '.join(r.replay_cmd[:3])} ...)"
    else:
        hyp = f"an attacker-controlled input reaches a {f.bug_class} defect at {_site(f)}"
        exp = ("replay the reproducer"
               + (f" ({r.size_bytes} bytes{', minimised' if r.minimised else ''})" if r and r.size_bytes else "")
               + " against the unpatched build") if r else None
    if rb is None:
        obs = None
        concl = "unproven: no experiment has run yet; held at SUSPECTED and not reported"
        if f.contract:
            concl = f"held at SUSPECTED: {f.contract}"
    else:
        obs = ("the oracle fired" + (f" (signature {rb.abort_signature})" if rb.abort_signature else "")
               if rb.oracle_fired else "the oracle did not fire")
        concl = "supported: the defect is real (CONFIRMED)" if rb.oracle_fired else "refuted"
    return {"question": "is the defect real?", "hypothesis": hyp, "experiment": exp,
            "observation": obs, "conclusion": concl}


def _rounds(f: Finding) -> list[list]:
    """gate_history split into repair rounds: a round starts at each COMPILES result."""
    out: list[list] = []
    for g in f.gate_history:
        if g.check is GateCheck.COMPILES or not out:
            out.append([])
        out[-1].append(g)
    return out


def _repairs(f: Finding) -> list[dict]:
    cycles = []
    lanes = list(f.lane_history)
    for i, rnd in enumerate(_rounds(f)):
        lane = lanes[i].value if i < len(lanes) else "unknown"
        failed = next((g for g in rnd if not g.passed), None)
        ran = [g.check for g in rnd]
        obs = "; ".join(f"{_CHECK_WORDS[g.check]}: {'yes' if g.passed else 'NO'}" for g in rnd)
        if failed is not None:
            concl = f"refuted at {failed.check.value}" + (f" — {failed.detail}" if failed.detail else "")
        elif all(c in ran for c in GATE_ORDER):
            concl = "supported: all five checks passed"
        else:
            concl = "incomplete: not every check ran"
        cycles.append({"question": f"does repair candidate {i + 1} remove the defect safely?",
                       "hypothesis": f"the {lane} candidate removes the defect without changing "
                                     "any other behaviour",
                       "experiment": "the five-check gate on a fresh patched build",
                       "observation": obs, "conclusion": concl})
    for reason in f.rejected_candidates:
        cycles.append({"question": "is this candidate fit to test?",
                       "hypothesis": "a proposed candidate is a well-behaved patch",
                       "experiment": "patch hygiene review before any build",
                       "observation": reason, "conclusion": "refuted before the gate"})
    return cycles


def _analytic(f: Finding) -> list[dict]:
    out = []
    rp = f.reach_proof or {}
    if rp.get("before") or rp.get("after"):
        b, a = rp.get("before") or {}, rp.get("after") or {}
        out.append({"question": "does the patched guard close every path to the bad index?",
                    "hypothesis": "under the patched guard the out-of-bounds index is unreachable",
                    "experiment": "an SMT query on the guards before and after the patch",
                    "observation": f"before: {b.get('status')} ({b.get('detail', '')}); "
                                   f"after: {a.get('status')} ({a.get('detail', '')})",
                    "conclusion": {"unreachable": "supported (premises: " + ", ".join(rp.get("premises", [])) + ")",
                                   "reachable": "refuted: the solver found a path"}.get(
                                       a.get("status"), f"undecided: {a.get('status')}")})
    bp = f.bound_proof or {}
    if bp.get("status") in ("proved", "refuted"):
        out.append({"question": "is the clamp arithmetic sound?",
                    "hypothesis": "the clamped length never exceeds the buffer",
                    "experiment": "an SMT proof obligation read from the patch",
                    "observation": bp.get("detail"),
                    "conclusion": "supported" if bp["status"] == "proved" else "refuted"})
    rb = f.rollback_proof or {}
    if rb.get("status"):
        out.append({"question": "can the fix be undone exactly?",
                    "hypothesis": "reversing the patch restores the original tree byte for byte",
                    "experiment": "apply and reverse the patch on a scratch copy; compare tree hashes",
                    "observation": f"status {rb['status']}",
                    "conclusion": "supported" if rb["status"] == "proved" else f"refuted ({rb['status']})"})
    return out


def _falsification(f: Finding) -> list[dict]:
    rt = f.red_team
    if not rt:
        return []
    return [{"question": "can a fresh adversary defeat the verified patch?",
             "hypothesis": "an attacker who has seen the patch can still reach the defect",
             "experiment": f"{rt.get('attempts', 0)} independent attack attempts "
                           f"({', '.join(sorted((rt.get('strategies') or {}).keys())) or 'no strategy ran'})",
             "observation": f"{rt.get('wins', 0)} attempt(s) reached the defect",
             "conclusion": ("the attacker's hypothesis is refuted: the patch held" if rt.get("held")
                            else "the attacker's hypothesis is supported: the patch was broken"
                            if rt.get("held") is False else "not run")}]


def cycles(f: Finding) -> list[dict]:
    """Every hypothesis → experiment → observation → conclusion cycle the record supports."""
    out = [_detection(f)]
    if f.status is not Status.SUSPECTED:
        out += _repairs(f) + _analytic(f) + _falsification(f)
    return out


def one_line(c: dict) -> str:
    return f"{c['question']} {c['conclusion']}."
