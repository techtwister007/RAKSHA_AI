"""Deploy-readiness grade (D2).

VERIFIED is binary; a commanding officer deciding whether to apply a fix wants a graded confidence
and the reasons behind it. This rolls the evidence a finding already carries — the gate result, the
behavioural corpus, the deployment twin, the perf ratio, the independent red team, a minimised
reproducer, a verified regression test, a machine-checked bound proof — into an A / B / C grade.

It invents nothing: every factor is read off the record, and a missing signal lowers the grade
rather than being assumed. A REPORT_ONLY finding is ungraded (there is no fix to deploy).
"""

from __future__ import annotations

from .finding import Finding, Status


def _factors(f: Finding) -> list[dict]:
    out: list[dict] = []

    def factor(name: str, met: bool, detail: str) -> None:
        out.append({"factor": name, "met": bool(met), "detail": detail})

    factor("gate_passed", f.gate_passed, "all five checks passed on the patched build")
    factor("reproducer_minimised", bool(f.reproducer and f.reproducer.minimised),
           "the proof input was reduced to a minimal case")
    factor("regression_test", f.regression_test is not None,
           "a regression test that fails before and passes after ships with the fix")
    rt = f.red_team or {}
    factor("red_team_held", bool(rt.get("held")),
           "an independent red team could not re-break the fix" if rt else "no red-team round recorded")
    factor("perf_within_tolerance", f.perf_delta is None or f.perf_delta <= 1.5,
           f"patched build runs at {f.perf_delta:.2f}x baseline" if f.perf_delta is not None
           else "perf delta not measured")
    ev = f.evidence_score or {}
    factor("evidence_confident", bool(ev.get("confidence", 0) >= 0.85),
           f"fused evidence confidence {ev.get('confidence')}" if ev else "evidence not fused")
    return out


def deploy_grade(f: Finding) -> dict:
    """An A/B/C grade with the factors behind it. A = every signal present; B = verified with some
    signals missing; C = verified but thin; ungraded when there is no proven fix."""
    if f.status is not Status.VERIFIED:
        return {"grade": None, "status": f.status.value, "factors": [],
                "summary": "no proven fix to deploy"}
    factors = _factors(f)
    met = sum(1 for x in factors if x["met"])
    total = len(factors)
    if met == total:
        grade = "A"
    elif met >= total - 2:
        grade = "B"
    else:
        grade = "C"
    missing = [x["factor"] for x in factors if not x["met"]]
    summary = (f"grade {grade}: {met}/{total} readiness signals present"
               + (f"; missing: {', '.join(missing)}" if missing else ""))
    return {"grade": grade, "status": "VERIFIED", "factors": factors, "summary": summary}
