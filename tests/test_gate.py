"""The gate, judged against a simulated program with known good and bad patches.

The Phase 1 exit gate, in test form: a deliberately planted overfitting patch must be REJECTED,
the real fix must PASS, and a noisy target must not cause a false rejection. The simulated target
is tiny but behaves like a real one: it has a bug, a corpus, its own test suite, coverage, and a
fuzzer that finds variants the overfitting patch did not cover.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from raksha.finding import (
    Finding, FixSite, Frame, GateCheck, RepairLane, ReplayResult, Reproducer, Status, utcnow,
)
from raksha.gate import TestResult as _TestResult
from raksha.gate import (
    BuildResult, Canonicaliser, RunResult, cross_confirm, decide, run_gate,
    verify_regression_test,
)

ASAN = """==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118 at pc 0x4f1b2d
WRITE of size 8 at 0x602000000118 thread T0
    #0 0x4f1b2c in parse_header /src/target/src/parser.c:142:9
    #1 0x4f09b1 in LLVMFuzzerTestOneInput /src/target/fuzz/fuzz_parser.c:21:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/target/src/parser.c:142:9 in parse_header
"""

REPRO = b"HDR" + b"\xff" * 9  # 12 bytes: header + 9 payload -> overflow in the vulnerable build


@dataclass
class FakeTarget:
    """A parser with a heap overflow on payloads longer than 8 bytes, and several 'patches'."""

    noisy: bool = False                 # append timestamp/uuid noise to stdout
    refuzz_seed: int = 7
    builds: list[str] = field(default_factory=list)

    # --- the program, by variant ---------------------------------------------------------
    def _program(self, variant: str, data: bytes) -> RunResult:
        if data == b"RAND":               # a genuinely non-deterministic input
            return RunResult(0, str(random.random()).encode(), b"")
        if variant == "delete":           # "fixed" by removing the parser
            return RunResult(0, b"", b"")
        if not data.startswith(b"HDR"):
            out = b"no header"
        else:
            payload = data[3:]
            overflow = len(payload) > 8
            if variant == "vulnerable" or (variant == "overfit" and data != REPRO):
                if overflow:
                    return RunResult(1, b"", ASAN.encode())
                out = b"parsed %d bytes" % len(payload)
            elif variant == "overfit":    # special-cases the exact reproducer only
                out = b"error: too long"
            elif variant == "real":
                out = b"error: too long" if overflow else b"parsed %d bytes" % len(payload)
            elif variant == "break":      # fixes the crash but changes normal behaviour
                out = b"error: too long" if overflow else b"PARSED %d BYTES" % len(payload)
            else:
                raise AssertionError(variant)
        if self.noisy:
            out += f"  at {datetime.now(timezone.utc).isoformat()} id={uuid.uuid4()} took 3ms".encode()
        return RunResult(0, out, b"")

    # --- Target protocol -----------------------------------------------------------------
    def build(self, patch_diff):
        variant = "vulnerable" if patch_diff is None else patch_diff.strip()
        if variant == "nocompile":
            return BuildResult(False, variant, "parser.c:142: error: expected ';'")
        self.builds.append(variant)
        return BuildResult(True, variant, "ok")

    def run(self, build, data):
        return self._program(build.label, data)

    def run_tests(self, build):
        # the project's own suite: two normal-path assertions
        a = self._program(build.label, b"HDRabc").stdout.startswith(b"parsed 3 bytes")
        b = self._program(build.label, b"nope").stdout.startswith(b"no header")
        return _TestResult(ran=2, failed=(not a) + (not b))

    def run_added_test(self, build, test_source):
        # the model's test: "a 9-byte payload must not crash and must say 'error: too long'"
        if test_source == "good":
            r = self._program(build.label, REPRO)
            ok = r.exit_code == 0 and r.stdout.startswith(b"error: too long")
        elif test_source == "trivial":        # passes everywhere: never touches the bug
            ok = True
        else:
            ok = False
        return _TestResult(ran=1, failed=0 if ok else 1)

    def covered_lines(self, build, inputs):
        if build.label == "delete":
            return set()
        return {("/src/target/src/parser.c", 142), ("/src/target/src/parser.c", 131)}

    def refuzz(self, build, seconds):
        rng = random.Random(self.refuzz_seed)
        crashes = []
        for _ in range(40):
            data = b"HDR" + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 16)))
            r = self._program(build.label, data)
            if r.exit_code != 0:
                crashes.append(r.stderr.decode())
        return crashes


def corpus() -> list[bytes]:
    return [b"HDR", b"HDRa", b"HDRabc", b"HDR12345678", b"nope", b"", b"HDRxyz"]


def confirmed_finding() -> Finding:
    f = Finding(
        oracle="asan:AddressSanitizer", bug_class="CWE-122", language="c/c++", target="parser",
        message="heap-buffer-overflow in parse_header",
        frames=[Frame(symbol="parse_header", uri="/src/target/src/parser.c", line=142)],
    )
    f.add_fix_site(FixSite(uri="/src/target/src/parser.c", rank=0, start_line=142, symbol="parse_header"))
    f.attach_reproducer(Reproducer.from_bytes(REPRO, ["./replay.sh"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature="x", exit_code=1))
    f.confirm()
    return f


def patched(variant: str) -> Finding:
    f = confirmed_finding()
    f.mark_patched(variant, RepairLane.LLM)
    return f


# ----------------------------------------------------------------------------- the five


def test_the_real_fix_passes_all_five_checks():
    f = patched("real")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v.passed, v.detail
    assert all(f.gate[c].passed for c in GateCheck)
    assert f.replay_after is not None and not f.replay_after.oracle_fired
    assert v.tests_ran == 2
    decide(f, v)
    assert f.status is Status.VERIFIED


def test_the_overfitting_patch_is_rejected():
    """The Phase 1 exit gate. It silences the exact reproducer; refuzz finds its siblings."""
    f = patched("overfit")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert not v.passed
    assert v.failed_check is GateCheck.CLEAN_REFUZZ
    assert v.refuzz_findings > 0
    # earlier checks genuinely passed — the rejection came from the last, expensive one
    assert f.gate[GateCheck.POV_DEAD].passed and f.gate[GateCheck.DIFFERENTIAL_CORPUS].passed
    decide(f, v)
    assert f.status is Status.CONFIRMED          # back for another round


def test_a_fix_that_changes_normal_behaviour_fails_the_differential_check():
    f = patched("break")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v.failed_check is GateCheck.DIFFERENTIAL_CORPUS
    assert v.mismatches, "the changed outputs must be reported, not just counted"


def test_fixing_by_deleting_the_code_fails():
    f = patched("delete")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    # output changes for every corpus input, so it falls at the differential check first
    assert v.failed_check is GateCheck.DIFFERENTIAL_CORPUS


def test_a_patch_that_does_not_compile_fails_first_and_cheapest():
    f = patched("nocompile")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v.failed_check is GateCheck.COMPILES
    assert GateCheck.POV_DEAD not in f.gate     # nothing more expensive was run


def test_a_patch_that_leaves_the_pov_alive_fails_at_check_two():
    f = patched("vulnerable")                   # an empty "patch": same behaviour
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v.failed_check is GateCheck.POV_DEAD
    assert f.replay_after is not None and f.replay_after.oracle_fired


# ----------------------------------------------------------------- noisy real services


def test_a_noisy_service_does_not_cause_a_false_rejection():
    """Timestamps, UUIDs and durations in output are canonicalised away."""
    f = patched("real")
    v = run_gate(f, FakeTarget(noisy=True), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v.passed, v.detail


def test_a_truly_nondeterministic_input_is_quarantined_and_counted_not_failed():
    f = patched("real")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus() + [b"RAND"], refuzz_seconds=1)
    assert v.passed
    assert len(v.quarantined) == 1
    assert f.gate[GateCheck.DIFFERENTIAL_CORPUS].quarantined_inputs == 1   # shown, never hidden


def test_canonicaliser_strips_noise_by_construction():
    c = Canonicaliser()
    a = c.canon(b"done at 2026-10-03T12:00:00Z id=1b4e28ba-2fa1-11d2-883f-0016d3cca427 took 12ms "
                b"0x7ffd5a3c1e20 /tmp/tmpab12cd34/out Obj@1b6d3586")
    b = c.canon(b"done at 2026-10-03T12:00:09Z id=5c1e0f00-9d4a-4c0d-9a1b-0123456789ab took 40ms "
                b"0x7ffc0b9e4410 /tmp/tmpzz98yy76/out Obj@7a81197d")
    assert a == b


@pytest.mark.parametrize("before,after", [
    (b"count: 3 s", b"count: 4 s"),                   # a number followed by "s" is not a duration
    (b"crc=0x1234", b"crc=0x1235"),                   # a short hex value is data, not a pointer
    (b"sha=" + b"ab" * 32, b"sha=" + b"cd" * 32),     # a hash is output: a patch that breaks it must show
    (b"open /tmp/safe.txt", b"open /tmp/x/../../etc/passwd"),   # path behaviour is never masked
    (b"thread 1 exited", b"thread 2 exited"),
])
def test_canonicaliser_does_not_hide_behaviour(before, after):
    c = Canonicaliser()
    assert c.canon(before) != c.canon(after)


# ---------------------------------------------------------------- the model's own test


def test_the_models_test_must_fail_before_and_pass_after():
    t = FakeTarget()
    before, after = t.build(None), t.build("real")
    ok, _ = verify_regression_test(t, before, after, "good")
    assert ok
    ok, why = verify_regression_test(t, before, after, "trivial")
    assert not ok and "does not exercise the bug" in why


def test_a_verified_test_enters_the_record_and_an_unverified_one_does_not():
    f = patched("real")
    run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1, regression_test="trivial")
    assert f.regression_test is None
    f2 = patched("real")
    run_gate(f2, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1, regression_test="good")
    assert f2.regression_test == "good"
    assert f2.proof_block()["regression_test_verified"] is True


# ----------------------------------------------------------------------- the loop


def test_three_failed_rounds_end_in_report_only():
    f = confirmed_finding()
    for _ in range(3):
        f.mark_patched("overfit", RepairLane.LLM)
        v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
        decide(f, v)
    assert f.status is Status.REPORT_ONLY
    assert f.is_reportable
    assert f.repair_rounds == 3


def test_each_round_must_earn_all_five_again():
    f = confirmed_finding()
    f.mark_patched("overfit", RepairLane.LLM)
    decide(f, run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1))
    f.mark_patched("real", RepairLane.TEMPLATE)
    assert f.gate == {}
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    decide(f, v)
    assert f.status is Status.VERIFIED
    assert len(f.gate_history) == 10


# ------------------------------------------------------------- cross-confirmation


def static_finding(cwe="CWE-122", line=143, uri="src/parser.c") -> Finding:
    f = Finding(oracle="semgrep", bug_class=cwe, language="c/c++", target="parser",
                message="possible overflow", frames=[Frame(symbol="parse_header", uri=uri, line=line)])
    f.add_fix_site(FixSite(uri=uri, rank=0, start_line=line))
    return f


def test_a_static_finding_is_promoted_by_another_lanes_reproducer_and_merged():
    fuzz = confirmed_finding()
    static = static_finding()
    out = cross_confirm([static, fuzz])
    assert out == [fuzz]                              # merged: one bug, one record
    assert fuzz.merged_from == [static.id]
    assert static.status is Status.CONFIRMED          # it was right, and now it is proven
    assert "cross-confirmed" in static.history[-1].reason


def test_cross_confirmation_requires_the_same_cwe():
    fuzz = confirmed_finding()
    static = static_finding(cwe="CWE-476")           # null deref at the same line is a different bug
    out = cross_confirm([static, fuzz])
    assert len(out) == 2 and static.status is Status.SUSPECTED


def test_cross_confirmation_requires_the_same_site():
    fuzz = confirmed_finding()
    static = static_finding(line=300)
    out = cross_confirm([static, fuzz])
    assert len(out) == 2 and static.status is Status.SUSPECTED


def test_run_gate_refuses_a_finding_that_is_not_patched():
    with pytest.raises(ValueError):
        run_gate(confirmed_finding(), FakeTarget(), reproducer=REPRO, corpus=corpus())


# ------------------------------------------------------------------- perf delta


class SlowFakeTarget(FakeTarget):
    """The 'slow' patch behaves exactly like 'real' but takes 2 ms per run: a fix that disabled
    something (a retry loop, a fallback parser) rather than bounding a copy."""

    def _program(self, variant, data):
        if variant == "slow":
            import time
            time.sleep(0.002)
            return super()._program("real", data)
        return super()._program(variant, data)


def test_a_patch_that_makes_the_target_much_slower_fails_the_differential_check():
    f = patched("slow")
    big_corpus = corpus() * 4                       # enough runs for the baseline total to mean something
    v = run_gate(f, SlowFakeTarget(), reproducer=REPRO, corpus=big_corpus, refuzz_seconds=1,
                 perf_floor_seconds=0.0)
    assert v.failed_check is GateCheck.DIFFERENTIAL_CORPUS
    assert "perf" in v.detail and "perf" in f.gate[GateCheck.DIFFERENTIAL_CORPUS].detail
    assert v.perf_delta is not None and v.perf_delta > 5.0
    assert f.perf_delta == v.perf_delta             # the number is on the record, measured


def test_perf_delta_is_measured_on_a_passing_patch_and_the_tolerance_is_loose():
    f = patched("real")
    v = run_gate(f, FakeTarget(), reproducer=REPRO, corpus=corpus() * 4, refuzz_seconds=1,
                 perf_floor_seconds=0.0)
    assert v.passed, v.detail
    assert v.perf_delta is not None and f.perf_delta == v.perf_delta
    assert "perf" in f.gate[GateCheck.DIFFERENTIAL_CORPUS].detail
    # the same slow patch passes when the operator widens the tolerance: the check is a knob, not a guess
    f2 = patched("slow")
    v2 = run_gate(f2, SlowFakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1,
                  perf_floor_seconds=0.0, perf_tolerance=1e6)
    assert v2.passed, v2.detail


def test_perf_delta_is_none_below_the_timing_floor_and_never_fails():
    f = patched("slow")
    v = run_gate(f, SlowFakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1,
                 perf_floor_seconds=3600.0)         # a baseline this short is noise, not a measurement
    assert v.passed, v.detail
    assert v.perf_delta is None and f.perf_delta is None
    assert "n/a" in f.gate[GateCheck.DIFFERENTIAL_CORPUS].detail


def test_previous_known_good_second_baseline_flags_a_pre_existing_regression():
    """Multi-baseline (A<->B): a previous known-good build compared against the current one surfaces
    a divergence that predates this patch. It is a reported signal, never a gate failure — the patch
    still passes, judged against the current build."""
    f = patched("real")
    t = FakeTarget()
    prev = t.build("break")   # a "previous" build whose normal-path output differs from current
    v = run_gate(f, t, reproducer=REPRO, corpus=corpus(), refuzz_seconds=1, previous_good=prev)
    assert v.passed                                   # the patch is sound against the current build
    assert v.regression_vs_previous and v.regression_vs_previous > 0   # but behaviour already drifted
    # and with no previous baseline the field stays None (unmeasured, not a false 0)
    f2 = patched("real")
    v2 = run_gate(f2, FakeTarget(), reproducer=REPRO, corpus=corpus(), refuzz_seconds=1)
    assert v2.regression_vs_previous is None
