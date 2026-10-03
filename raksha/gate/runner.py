"""The five-check gate, run for real against a target.

Cheapest check first, stop at the first failure, record every verdict on the finding. The gate
decides; it does not transition the finding — `decide()` does that, so the pure judgement and the
status change stay separable and testable.

Order and cost:

    1 COMPILES              one build
    2 POV_DEAD              one run
    3 DIFFERENTIAL_CORPUS   N inputs × 2 builds (+ pre-flight) and the project's own tests
    4 COVERAGE_HELD         one coverage run over the corpus
    5 CLEAN_REFUZZ          a bounded fresh campaign — the expensive one, so it is last
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..finding import Finding, FixSite, GateCheck, ReplayResult, Status, utcnow
from ..oracles import KEYSTONE_ORACLES, Oracle
from .differential import Canonicaliser, Mismatch, Quarantined, differential, preflight
from .target import BuildResult, RunResult, Target, TestResult

MAX_REPAIR_ROUNDS = 3


def oracle_fired(raw: str, oracles: Iterable[Oracle] = KEYSTONE_ORACLES) -> bool:
    """Did any oracle recognise an abort in this output?"""
    return any(o.parse(raw, target="<gate>") for o in oracles)


@dataclass
class GateVerdict:
    passed: bool
    failed_check: GateCheck | None = None
    detail: str = ""
    quarantined: list[Quarantined] = field(default_factory=list)
    mismatches: list[Mismatch] = field(default_factory=list)
    tests_ran: int = 0
    refuzz_findings: int = 0
    regression_test_verified: bool | None = None
    before: BuildResult | None = None
    after: BuildResult | None = None


def _fail(finding: Finding, verdict: GateVerdict, check: GateCheck, detail: str, **kw) -> GateVerdict:
    finding.record_gate(check, False, detail=detail, **kw)
    verdict.passed = False
    verdict.failed_check = check
    verdict.detail = detail
    return verdict


def verify_regression_test(target: Target, before: BuildResult, after: BuildResult, test_source: str) -> tuple[bool, str]:
    """The model's test must FAIL on the vulnerable build and PASS on the patched one.

    A test that passes on both never exercised the bug; a test that fails on both is broken.
    Either way it is not a proof and does not enter the bundle.
    """
    on_vuln = target.run_added_test(before, test_source)
    on_fixed = target.run_added_test(after, test_source)
    if on_vuln.passed:
        return False, "added test passes on the vulnerable build — it does not exercise the bug"
    if not on_fixed.passed:
        return False, "added test fails on the patched build"
    return True, "fails before, passes after"


def run_gate(
    finding: Finding,
    target: Target,
    *,
    reproducer: bytes,
    corpus: list[bytes],
    refuzz_seconds: float = 30.0,
    oracles: Iterable[Oracle] = KEYSTONE_ORACLES,
    canon: Canonicaliser | None = None,
    coverage_tolerance: int = 3,
    regression_test: str | None = None,
    preflight_runs: int = 3,
) -> GateVerdict:
    """Judge `finding.patch_diff`. Records each check on the finding; returns the verdict."""
    if finding.status is not Status.PATCHED or not finding.patch_diff:
        raise ValueError("run_gate needs a PATCHED finding carrying a patch_diff")
    oracles = tuple(oracles)
    verdict = GateVerdict(passed=True)

    # 1 ── COMPILES
    before = target.build(None)
    if not before.ok:
        return _fail(finding, verdict, GateCheck.COMPILES, "baseline does not build: " + before.log[-400:])
    after = target.build(finding.patch_diff)
    verdict.before, verdict.after = before, after
    if not after.ok:
        return _fail(finding, verdict, GateCheck.COMPILES, "patched build fails: " + after.log[-400:])
    finding.record_gate(GateCheck.COMPILES, True, detail="patched build ok")

    # 2 ── POV_DEAD
    replay: RunResult = target.run(after, reproducer)
    fired = oracle_fired(replay.text, oracles) or replay.timed_out
    finding.record_replay_after(ReplayResult(
        oracle_fired=fired, at=utcnow(), exit_code=replay.exit_code,
        stderr_excerpt=replay.stderr.decode("utf-8", "replace")[:600],
    ))
    if fired:
        return _fail(finding, verdict, GateCheck.POV_DEAD, "the original reproducer still fires the oracle on the patched build")
    finding.record_gate(GateCheck.POV_DEAD, True, detail="reproducer no longer fires")

    # 3 ── DIFFERENTIAL_CORPUS  (corpus inputs + the project's own tests)
    canon = canon or Canonicaliser()
    pf = preflight(target, before, corpus, runs=preflight_runs, canon=canon)
    verdict.quarantined = pf.quarantined
    mism = differential(target, before, after, corpus, pf.stable, canon=canon)
    verdict.mismatches = mism
    tests: TestResult = target.run_tests(after)
    verdict.tests_ran = tests.ran
    if mism:
        return _fail(finding, verdict, GateCheck.DIFFERENTIAL_CORPUS,
                     f"{len(mism)} of {len(pf.stable)} corpus inputs changed output",
                     quarantined_inputs=len(pf.quarantined))
    if not tests.passed:
        return _fail(finding, verdict, GateCheck.DIFFERENTIAL_CORPUS,
                     f"{tests.failed} of {tests.ran} of the target's own tests fail on the patched build",
                     quarantined_inputs=len(pf.quarantined))
    finding.record_gate(GateCheck.DIFFERENTIAL_CORPUS, True,
                        detail=f"{len(pf.stable)} inputs identical · {tests.ran} own tests pass · "
                               f"{len(pf.quarantined)} quarantined · {len(pf.crashing)} crash on baseline",
                        quarantined_inputs=len(pf.quarantined))

    # 4 ── COVERAGE_HELD
    covered = target.covered_lines(after, [corpus[i] for i in pf.stable] + [reproducer])
    if not _fix_site_covered(finding.fix_site_set, covered, coverage_tolerance):
        return _fail(finding, verdict, GateCheck.COVERAGE_HELD,
                     "no corpus input reaches the fix site on the patched build — fixed by deleting it?")
    finding.record_gate(GateCheck.COVERAGE_HELD, True, detail="fix site still reached")

    # 5 ── CLEAN_REFUZZ
    crashes = target.refuzz(after, refuzz_seconds)
    new = [c for c in crashes if oracle_fired(c, oracles)]
    verdict.refuzz_findings = len(new)
    if new:
        return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                     f"fresh campaign found {len(new)} abort(s) on the patched build")
    finding.record_gate(GateCheck.CLEAN_REFUZZ, True, detail=f"{int(refuzz_seconds)}s campaign, nothing new")

    # The model's test, if any: verified or discarded, never assumed.
    if regression_test is not None:
        ok, why = verify_regression_test(target, before, after, regression_test)
        verdict.regression_test_verified = ok
        verdict.detail = why
        if ok:
            finding.regression_test = regression_test
    return verdict


def _fix_site_covered(sites: list[FixSite], covered: set[tuple[str, int]], tol: int) -> bool:
    if not sites:
        return False  # nothing to check against is not a pass
    by_base = {}
    for file, line in covered:
        by_base.setdefault(file.rsplit("/", 1)[-1], set()).add(line)
    for s in sites:
        lines = by_base.get(s.uri.rsplit("/", 1)[-1], set())
        if s.start_line is None:
            if lines:
                return True
            continue
        if any(abs(l - s.start_line) <= tol for l in lines):
            return True
    return False


def decide(finding: Finding, verdict: GateVerdict) -> Status:
    """Apply the verdict: VERIFIED, back to CONFIRMED for another round, or REPORT_ONLY."""
    if verdict.passed:
        finding.verify()
    elif finding.repair_rounds >= MAX_REPAIR_ROUNDS:
        finding.report_only(f"{MAX_REPAIR_ROUNDS} repair rounds exhausted; last failure: "
                            f"{verdict.failed_check.value if verdict.failed_check else '?'} — {verdict.detail}")
    else:
        finding.gate_failed(f"{verdict.failed_check.value if verdict.failed_check else '?'}: {verdict.detail}")
    return finding.status
