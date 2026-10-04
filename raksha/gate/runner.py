"""The five-check gate, run for real against a target.

Cheapest check first, stop at the first failure, record every verdict on the finding. The gate
decides; it does not transition the finding — `decide()` does that, so the pure judgement and the
status change stay separable and testable.

Order and cost:

    1 COMPILES              one build
    2 POV_DEAD              one run
    3 DIFFERENTIAL_CORPUS   N inputs × 2 builds (+ pre-flight) and the project's own tests;
                            the two sides are timed and a patch slower than `perf_tolerance`×
                            fails (loose: sanitizer timing is noisy; 5× means something was disabled)
    4 COVERAGE_HELD         one coverage run over the corpus
    5 CLEAN_REFUZZ          the reproducer's own neighbourhood, then a bounded fresh campaign —
                            the expensive one, so it is last

Check 5 opens with a deterministic neighbourhood of the reproducer (bit flips, length changes,
boundary integers — the moves a fuzzer would make first) replayed on the patched build. A patch
that special-cases the exact crashing input — the "shallow fix" that kills the observed crash and
not the defect — dies here on every target, instead of only when a random fresh campaign happens
to stumble on a sibling. The fresh campaign then runs as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..finding import Finding, FixSite, GateCheck, ReplayResult, Status, utcnow
from ..oracles import KEYSTONE_ORACLES, Oracle
from .. import profile as _profile
from ..signature import signature
from .differential import (PERF_FLOOR_SECONDS, Canonicaliser, Mismatch, Quarantined, differential_timed,
                           preflight, regression_vs_previous)
from .target import BuildResult, RunResult, Target, TestResult

MAX_REPAIR_ROUNDS = 3

#: Deterministic reproducer variants replayed at the start of CLEAN_REFUZZ.
POV_VARIANTS = 24


def pov_neighbourhood(reproducer: bytes, n: int = POV_VARIANTS, seed: int = 0x5A4B) -> list[bytes]:
    """`n` distinct deterministic mutants of the reproducer: the inputs a shallow fix forgets.

    Same reproducer, same list — so the record is reproducible and a judge can replay it.
    """
    import random
    from ..harness.mutator import _mutate
    rng = random.Random(seed)
    seen = {reproducer}
    out: list[bytes] = []
    tries = 0
    while len(out) < n and tries < n * 20:
        tries += 1
        base = reproducer if rng.random() < 0.7 or not out else rng.choice(out)
        m = _mutate(rng, base)
        if m and m not in seen:
            seen.add(m)
            out.append(m)
    return out


def oracle_fired(raw: str, oracles: Iterable[Oracle] = KEYSTONE_ORACLES) -> bool:
    """Did any oracle recognise an abort in this output?"""
    return any(o.parse(raw, target="<gate>") for o in oracles)


def _signatures_in(raw: str, oracles: Iterable[Oracle]) -> set[str]:
    """Every distinct crash signature an oracle recognises in this output. A crash with no parseable
    frames still yields one signature (its bug class), so a frameless abort is never invisible."""
    out: set[str] = set()
    for o in oracles:
        for f in o.parse(raw, target="<gate>"):
            out.add(signature(f))
    return out


@dataclass
class GateVerdict:
    passed: bool
    failed_check: GateCheck | None = None
    detail: str = ""
    quarantined: list[Quarantined] = field(default_factory=list)
    mismatches: list[Mismatch] = field(default_factory=list)
    tests_ran: int = 0
    refuzz_findings: int = 0
    refuzz_ran: bool = False
    regression_test_verified: bool | None = None
    #: Behaviour divergence between a previous known-good build and the current (pre-patch) build,
    #: when a `previous_good` baseline was supplied — a regression that predates this patch.
    regression_vs_previous: int | None = None
    #: A2: behavioural-evidence units behind this verdict (stable corpus inputs + own tests + the
    #: reproducer). Below the profile floor, a passing patch is REPORT_ONLY, not VERIFIED.
    stable_inputs: int = 0
    insufficient_evidence: bool = False
    #: A1: signatures of OTHER defects that were present on the vulnerable build and are not what
    #: this patch fixed. They are not failures of this patch; the campaign loop (B1) harvests them.
    sibling_signatures: list = field(default_factory=list)
    #: A3: the deployment twin. True = the proven patch also held on a release-flavour (optimised,
    #: no sanitizer) build; False = it diverged there; None = the target has no distinct release
    #: build, so the twin was not run. A divergence fails the gate closed.
    twin_checked: bool | None = None
    before: BuildResult | None = None
    after: BuildResult | None = None
    #: patched/baseline wall-time over the stable corpus; None when the baseline was too short to mean anything
    perf_delta: float | None = None
    #: distinct (file, line) pairs the stable corpus + reproducer executed on the patched build
    coverage_lines: int | None = None
    #: deterministic reproducer variants replayed in CLEAN_REFUZZ
    refuzz_variants: int = 0


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
    pov_variants: int = POV_VARIANTS,
    perf_tolerance: float = 5.0,
    perf_floor_seconds: float = PERF_FLOOR_SECONDS,
    previous_good: BuildResult | None = None,
    min_stable_inputs: int | None = None,
    twin: bool = True,
) -> GateVerdict:
    """Judge `finding.patch_diff`. Records each check on the finding; returns the verdict.

    `perf_tolerance`: DIFFERENTIAL_CORPUS also fails when the patched build takes more than this
    many times the baseline's wall-time over the stable corpus. Sanitizer-build timing is noisy and
    the corpus runs are short, so the default is deliberately loose (5×): it is there to catch a
    "fix" that disabled something, not to benchmark. The ratio is `None` (and never fails) when the
    baseline total is under `perf_floor_seconds`.

    The two scratch builds the gate makes are discarded when it returns: an endurance run gates
    thousands of candidates, and leaving two full copies of the target per candidate fills the disk.
    """
    if finding.status is not Status.PATCHED or not finding.patch_diff:
        raise ValueError("run_gate needs a PATCHED finding carrying a patch_diff")
    verdict = GateVerdict(passed=True)
    try:
        return _judge(finding, target, verdict, reproducer=reproducer, corpus=corpus,
                      refuzz_seconds=refuzz_seconds, oracles=tuple(oracles), canon=canon,
                      coverage_tolerance=coverage_tolerance, regression_test=regression_test,
                      preflight_runs=preflight_runs, pov_variants=pov_variants,
                      perf_tolerance=perf_tolerance, perf_floor_seconds=perf_floor_seconds,
                      previous_good=previous_good, min_stable_inputs=min_stable_inputs, twin=twin)
    finally:
        discard = getattr(target, "discard", None)
        if discard is not None:
            for build in (verdict.before, verdict.after):
                if build is not None:
                    discard(build)


def _judge(finding: Finding, target: Target, verdict: GateVerdict, *, reproducer: bytes,
           corpus: list[bytes], refuzz_seconds: float, oracles: tuple, canon: Canonicaliser | None,
           coverage_tolerance: int, regression_test: str | None, preflight_runs: int,
           pov_variants: int, perf_tolerance: float, perf_floor_seconds: float,
           previous_good: BuildResult | None, min_stable_inputs: int | None,
           twin: bool) -> GateVerdict:

    # 1 ── COMPILES
    before = target.build(None)
    verdict.before = before
    if not before.ok:
        return _fail(finding, verdict, GateCheck.COMPILES, "baseline does not build: " + before.log[-400:])
    after = target.build(finding.patch_diff)
    verdict.after = after
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
    pf = preflight(target, before, corpus, runs=preflight_runs, canon=canon,
                   is_abort=lambda text: oracle_fired(text, oracles))
    verdict.quarantined = pf.quarantined
    diff = differential_timed(target, before, after, corpus, pf.stable, canon=canon,
                              floor_seconds=perf_floor_seconds)
    mism = diff.mismatches
    verdict.mismatches = mism
    verdict.perf_delta = diff.perf_delta
    finding.perf_delta = diff.perf_delta
    perf_note = (f"perf {diff.perf_delta:.2f}× baseline" if diff.perf_delta is not None
                 else "perf n/a (baseline under the timing floor)")
    tests: TestResult = target.run_tests(after)
    verdict.tests_ran = tests.ran
    if mism:
        return _fail(finding, verdict, GateCheck.DIFFERENTIAL_CORPUS,
                     f"{len(mism)} of {len(pf.stable)} corpus inputs changed output · {perf_note}",
                     quarantined_inputs=len(pf.quarantined))
    if not tests.passed:
        return _fail(finding, verdict, GateCheck.DIFFERENTIAL_CORPUS,
                     f"{tests.failed} of {tests.ran} of the target's own tests fail on the patched build"
                     f" · {perf_note}",
                     quarantined_inputs=len(pf.quarantined))
    if diff.perf_delta is not None and diff.perf_delta > perf_tolerance:
        return _fail(finding, verdict, GateCheck.DIFFERENTIAL_CORPUS,
                     f"perf regression: patched build {diff.perf_delta:.2f}× the baseline wall-time over "
                     f"{len(pf.stable)} inputs (tolerance {perf_tolerance:g}×) — a fix this slow disabled something",
                     quarantined_inputs=len(pf.quarantined))
    floor = min_stable_inputs if min_stable_inputs is not None else _profile.current().min_stable_inputs
    evidence_units = len(pf.stable) + tests.ran + 1   # + the reproducer, which always replayed here
    verdict.stable_inputs = len(pf.stable)
    verdict.insufficient_evidence = evidence_units < floor
    ev_note = (f"evidence {evidence_units} (floor {floor})"
               + (" — INSUFFICIENT, report-only" if verdict.insufficient_evidence else ""))
    finding.record_gate(GateCheck.DIFFERENTIAL_CORPUS, True,
                        detail=f"{len(pf.stable)} inputs identical · {tests.ran} own tests pass · "
                               f"{len(pf.quarantined)} quarantined · {len(pf.crashing)} crash on baseline · "
                               f"{perf_note} · {ev_note}",
                        quarantined_inputs=len(pf.quarantined))

    # Optional second baseline: a previous known-good build vs the current one. A divergence here is
    # a pre-existing regression — reported, never a gate failure (the patch is judged against current).
    if previous_good is not None and previous_good.ok:
        verdict.regression_vs_previous = len(
            regression_vs_previous(target, previous_good, before, corpus, pf.stable, canon=canon))

    # 4 ── COVERAGE_HELD
    covered = target.covered_lines(after, [corpus[i] for i in pf.stable] + [reproducer])
    verdict.coverage_lines = len(covered)
    if not _fix_site_covered(finding.fix_site_set, covered, coverage_tolerance):
        return _fail(finding, verdict, GateCheck.COVERAGE_HELD,
                     "no corpus input reaches the fix site on the patched build — fixed by deleting it?")
    finding.record_gate(GateCheck.COVERAGE_HELD, True, detail="fix site still reached")

    # 5 ── CLEAN_REFUZZ
    # A target that cannot fuzz cannot satisfy this check. Failing it OPEN (recording a pass
    # for a campaign that never ran) would let an overfitting patch — one that silences the
    # exact reproducer and nothing else — reach VERIFIED with the fifth check a silent no-op.
    # So fail closed: the finding is reported, not verified, and the record says why.
    can_refuzz = getattr(target, "can_refuzz", None)
    if can_refuzz is not None and not can_refuzz():
        return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                     "target provides no fresh-fuzz campaign; CLEAN_REFUZZ cannot be certified — "
                     "reported, not verified")
    # 5a — the reproducer's neighbourhood, deterministic, as a controlled A/B over identical inputs.
    # Multi-bug semantics (A1): the patch must kill the DEFECT it targeted (its signature), and must
    # not introduce a signature the vulnerable build did not have (a regression). A DIFFERENT defect
    # that the vulnerable build already had is NOT a failure of this patch — it is a sibling, harvested
    # for the campaign loop. "Any abort fails" would make a real multi-bug target unfixable.
    fixed_sig = signature(finding)
    variants = pov_neighbourhood(reproducer, pov_variants) if pov_variants else []
    verdict.refuzz_variants = len(variants)
    inputs = [reproducer, *variants]
    base_sigs: set[str] = set()
    for data in inputs:
        r = target.run(before, data)
        if oracle_fired(r.text, oracles) or r.timed_out:
            base_sigs |= _signatures_in(r.text, oracles)
    patched_sigs: set[str] = set()
    fixed_recurs = False
    for data in inputs:
        r = target.run(after, data)
        if r.timed_out:
            patched_sigs.add(fixed_sig)   # a hang with no parseable frames counts against the fix
        if oracle_fired(r.text, oracles):
            patched_sigs |= _signatures_in(r.text, oracles)
    if fixed_sig in patched_sigs:
        fixed_recurs = True
    regressions = patched_sigs - base_sigs - {fixed_sig}
    verdict.refuzz_findings = len(patched_sigs)
    if fixed_recurs:
        return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                     f"the targeted defect ({fixed_sig}) still fires on the patched build — the patch "
                     f"silences the input, not the defect")
    if regressions:
        return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                     f"the patch introduced {len(regressions)} new defect signature(s) absent from the "
                     f"vulnerable build: {', '.join(sorted(regressions))}")
    # siblings: other defects already present on the vulnerable build, untouched by this patch
    verdict.sibling_signatures = sorted((patched_sigs & base_sigs) - {fixed_sig})
    # 5b — a fresh exploratory campaign. Here we cannot A/B identical inputs, so only a recurrence of
    # the fixed defect fails; any other abort is recorded as a sibling candidate, never a failure
    # (failing a correct patch on a pre-existing bug the neighbourhood did not reach is the worse error).
    verdict.refuzz_ran = True
    crashes = target.refuzz(after, refuzz_seconds)
    campaign_sigs: set[str] = set()
    for c in crashes:
        if oracle_fired(c, oracles):
            campaign_sigs |= _signatures_in(c, oracles)
    if fixed_sig in campaign_sigs:
        return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                     f"a fresh campaign re-triggered the targeted defect ({fixed_sig}) on the patched build")
    for sib in sorted(campaign_sigs - {fixed_sig}):
        if sib not in verdict.sibling_signatures:
            verdict.sibling_signatures.append(sib)
    sib_note = (f"; {len(verdict.sibling_signatures)} other pre-existing defect(s) noted for follow-up"
                if verdict.sibling_signatures else "")
    finding.record_gate(GateCheck.CLEAN_REFUZZ, True,
                        detail=f"{len(variants)} reproducer variants dead; fresh fuzzing pass on the "
                               f"patched build found nothing new ({len(crashes)} crash candidate(s) "
                               f"checked, budget {int(refuzz_seconds)}s){sib_note}")

    # A3 — the deployment twin. The five checks ran on the sanitizer build; the system actually
    # deploys an optimised, instrumentation-free build, where undefined behaviour can manifest
    # differently. When the target has a distinct release build, re-run POV_DEAD and a quick
    # differential on it; a divergence fails the gate closed. Targets with no release build (the
    # default) record twin_checked = None — the seam is honest, not a silent pass.
    if twin and getattr(target, "release_build_cmd", None):
        rbefore = target.build(None, flavour="release")
        rafter = target.build(finding.patch_diff, flavour="release")
        if not (rbefore.ok and rafter.ok):
            verdict.twin_checked = None
        else:
            rr = target.run(rafter, reproducer)
            if oracle_fired(rr.text, oracles) or rr.timed_out:
                try:
                    target.discard(rbefore); target.discard(rafter)
                except Exception:  # noqa: BLE001
                    pass
                return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                             "the reproducer fires on the release-flavour (deployment) build — the fix "
                             "holds only under the sanitizer build")
            tw = differential_timed(target, rbefore, rafter, corpus, pf.stable, canon=canon).mismatches
            verdict.twin_checked = not tw
            try:
                target.discard(rbefore); target.discard(rafter)
            except Exception:  # noqa: BLE001
                pass
            if tw:
                return _fail(finding, verdict, GateCheck.CLEAN_REFUZZ,
                             f"{len(tw)} corpus input(s) behave differently on the release build — the "
                             "patch changes behaviour under optimisation")

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
    if verdict.passed and verdict.insufficient_evidence:
        finding.report_only(
            f"all gate checks passed but behavioural evidence is insufficient "
            f"({verdict.stable_inputs} stable corpus input(s)); not verified on thin evidence")
    elif verdict.passed:
        finding.verify()
    elif finding.repair_rounds >= MAX_REPAIR_ROUNDS:
        finding.report_only(f"{MAX_REPAIR_ROUNDS} repair rounds exhausted; last failure: "
                            f"{verdict.failed_check.value if verdict.failed_check else '?'} — {verdict.detail}")
    else:
        finding.gate_failed(f"{verdict.failed_check.value if verdict.failed_check else '?'}: {verdict.detail}")
    return finding.status
