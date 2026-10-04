"""Tests for the four new oracles (A7 UBSan+LSan, A8 hang, A9 metamorphic) and their demos.

Each oracle is exercised two ways: a unit test against a captured/synthetic report (always on),
and — where a toolchain is needed — an end-to-end test that compiles and runs the bundled demo so
the oracle parses a *real* report. The end-to-end C tests skip without gcc; the ReDoS test needs
only the stdlib. A `claimants` check mirrors the keystone's "exactly one oracle claims this" rule,
documenting the co-claims (AsanOracle also reads UBSan / LeakSanitizer reports, as GoOracle also
reads a Go race) exactly as tests/test_tsan.py does.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from raksha.finding import Frame, Status
from raksha.oracles import ALL_ORACLES
from raksha.oracles.hang import (
    HangOracle,
    HangSignal,
    detect_hang,
    frames_from_traceback,
    run_under_budget,
    sample_python_stack,
)
from raksha.oracles.metamorphic import (
    Idempotence,
    MetamorphicOracle,
    PaddingInvariance,
    RoundTrip,
    check_relations,
    decode_pair,
    encode_pair,
    pair_from_finding,
)
from raksha.oracles.ubsan import LeakOracle, UbsanOracle

REPO = Path(__file__).parents[1]
DEMOS = REPO / "demo-targets"
HAVE_GCC = shutil.which("gcc") is not None

#: The full routed set the integrator will have once the four oracles are registered: the shipped
#: ALL_ORACLES plus the new four. Used only to assert routing / co-claims, never mutated.
ROUTED = (*ALL_ORACLES, UbsanOracle(), LeakOracle(), HangOracle(), MetamorphicOracle())


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(root: Path, tmp: Path, sources: list[str], flags: list[str]) -> Path:
    """Copy a demo into tmp, compile its harness, return the built binary path."""
    work = tmp / root.name
    shutil.copytree(root, work)
    cmd = ["gcc", "-g", "-fno-omit-frame-pointer", *flags, "-o", "harness", "harness.c", *sources]
    r = subprocess.run(cmd, cwd=work, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return work


# ============================================================ A7: captured / synthetic reports

UBSAN_REPORT = """src/calc.c:13:16: runtime error: signed integer overflow: 1020000 * 1020000 cannot be represented in type 'int'
    #0 0x55888bc43616 in fold src/calc.c:13
    #1 0x55888bc434d5 in main /tmp/io/harness.c:15
    #2 0x7fa39982a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x7fa39982a28a in __libc_start_main_impl ../csu/libc-start.c:360
"""

LSAN_REPORT = """
=================================================================
==1610==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 7 byte(s) in 1 object(s) allocated from:
    #0 0x7fc304818132 in malloc ../../../../src/libsanitizer/lsan/lsan_interceptors.cpp:75
    #1 0x56459dd8f3f7 in stash src/store.c:13
    #2 0x56459dd8f396 in main /tmp/leak/harness.c:15

SUMMARY: LeakSanitizer: 7 byte(s) leaked in 1 allocation(s).
"""


def test_ubsan_oracle_maps_signed_overflow_to_cwe_190():
    (f,) = UbsanOracle().parse(UBSAN_REPORT, target="calc")
    assert f.language == "c/c++" and f.status is Status.SUSPECTED
    assert f.bug_class == "CWE-190"
    assert "signed integer overflow" in f.message
    assert f.frames[0].symbol == "fold" and f.frames[0].uri == "src/calc.c" and f.frames[0].line == 13
    assert f.fix_site_set[0].uri == "src/calc.c" and f.fix_site_set[0].start_line == 13
    assert f.abort_signature and f.dedup_key()


@pytest.mark.parametrize("desc,cwe", [
    ("shift exponent 40 is too large for 32-bit type 'int'", "CWE-1335"),
    ("division by zero", "CWE-369"),
    ("load of null pointer of type 'int'", "CWE-476"),
    ("unsigned integer overflow: 4294967295 + 1", "CWE-190"),
    ("index 7 out of bounds for type 'int [4]'", "CWE-129"),
    ("misaligned address 0x1 for type 'int'", "CWE-704"),
    ("value 1e+30 is outside the range of representable values of type 'int'", "CWE-681"),
])
def test_ubsan_oracle_message_to_cwe_table(desc, cwe):
    (f,) = UbsanOracle().parse(f"a.c:1:1: runtime error: {desc}\n", target="t")
    assert f.bug_class == cwe


def test_ubsan_oracle_one_claim_on_multiple_diagnostics():
    raw = ("a.c:1:1: runtime error: signed integer overflow: x\n"
           "a.c:2:2: runtime error: division by zero\n")
    findings = UbsanOracle().parse(raw, target="t")
    assert len(findings) == 1 and findings[0].bug_class == "CWE-190"   # first diagnostic only


def test_ubsan_oracle_silent_on_clean_and_non_native():
    assert UbsanOracle().parse("fold=86436\n2 tests passed\n", target="t") == []
    # a .py "runtime error" log line is not undefined behaviour
    assert UbsanOracle().parse("app.py:12:3: runtime error: retrying\n", target="t") == []


def test_leak_oracle_maps_to_cwe_401_and_localises_past_the_allocator():
    (f,) = LeakOracle().parse(LSAN_REPORT, target="store")
    assert f.language == "c/c++" and f.status is Status.SUSPECTED
    assert f.bug_class == "CWE-401"
    assert "memory leaks" in f.message and "7 byte" in f.message
    # the malloc interceptor frame is dropped; the fix site is the caller that forgot to free
    assert f.frames[0].symbol == "stash"
    assert f.fix_site_set[0].uri == "src/store.c" and f.fix_site_set[0].start_line == 13
    assert all(fr.symbol != "malloc" for fr in f.frames)


def test_leak_oracle_silent_on_clean():
    assert LeakOracle().parse("stash=97\n1 test passed\n", target="t") == []


# ============================================================ A7: end-to-end (real reports)


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_ubsan_demo_produces_a_real_signed_overflow_report(tmp_path):
    work = _build(DEMOS / "c-intoverflow", tmp_path, ["src/calc.c"],
                  ["-fsanitize=undefined", "-fno-sanitize-recover=all"])
    big = work / "big"
    big.write_bytes(b"\xff" * 4000)
    r = subprocess.run(["./harness", "big"], cwd=work, capture_output=True, text=True,
                       env={"UBSAN_OPTIONS": "print_stacktrace=1", "PATH": "/usr/bin:/bin"})
    raw = r.stdout + r.stderr
    (f,) = UbsanOracle().parse(raw, target="c-intoverflow")
    assert f.bug_class == "CWE-190" and "signed integer overflow" in f.message
    assert any(fr.uri and fr.uri.endswith("calc.c") for fr in f.frames)
    # benign short input does not overflow -> no report
    (work / "ok").write_bytes(b"abc")
    clean = subprocess.run(["./harness", "ok"], cwd=work, capture_output=True, text=True,
                           env={"UBSAN_OPTIONS": "print_stacktrace=1", "PATH": "/usr/bin:/bin"})
    assert UbsanOracle().parse(clean.stdout + clean.stderr, target="c-intoverflow") == []


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_leak_demo_produces_a_real_lsan_report(tmp_path):
    work = _build(DEMOS / "c-leak", tmp_path, ["src/store.c"], ["-fsanitize=leak"])
    (work / "leaky").write_bytes(b"Xhello")
    r = subprocess.run(["./harness", "leaky"], cwd=work, capture_output=True, text=True)
    (f,) = LeakOracle().parse(r.stdout + r.stderr, target="c-leak")
    assert f.bug_class == "CWE-401"
    assert any(fr.uri and fr.uri.endswith("store.c") for fr in f.frames)
    # benign first byte frees its copy -> no leak
    (work / "ok").write_bytes(b"abc")
    clean = subprocess.run(["./harness", "ok"], cwd=work, capture_output=True, text=True)
    assert LeakOracle().parse(clean.stdout + clean.stderr, target="c-leak") == []


# ============================================================ A8: hang / resource exhaustion


def test_detect_hang_benign_finite_run_is_not_a_hang():
    assert detect_hang(0.01, 1.0, [], killed=False) is None


def test_detect_hang_generic_timeout_is_cwe_400():
    f = detect_hang(2.0, 1.0, [Frame("process", "src/loop.c", 8)], killed=True,
                    target="c-hang", language="c/c++")
    assert f is not None and f.bug_class == "CWE-400" and f.severity == "high"
    assert f.status is Status.SUSPECTED and f.abort_signature


def test_detect_hang_regex_frame_is_redos_cwe_1333():
    frames = frames_from_traceback(
        'Thread (most recent call first):\n'
        '  File "/usr/lib/python3.11/re/__init__.py", line 166 in match\n'
        '  File "/app/redos.py", line 27 in scan\n'
    )
    f = detect_hang(0.3, 0.3, frames, killed=True, target="py-redos")
    assert f.bug_class == "CWE-1333"
    assert f.fix_site_set[0].uri.endswith("redos.py")   # the re frame is a tool frame, skipped


def test_hang_oracle_round_trips_a_signal_and_is_silent_otherwise():
    sig = HangSignal(2.0, 1.0, True, [Frame("process", "src/loop.c", 8)])
    (f,) = HangOracle().parse(sig.as_text(), target="c-hang")
    assert f.bug_class == "CWE-400" and f.language == "c/c++"
    assert HangOracle().parse("all tests passed\n", target="t") == []


def test_python_stack_sampler_reads_another_threads_frames():
    stop = threading.Event()

    def _marker_fn():
        while not stop.is_set():
            time.sleep(0.005)            # sleeping releases the GIL so the sampler can run

    t = threading.Thread(target=_marker_fn, daemon=True)
    t.start()
    try:
        time.sleep(0.05)
        frames = sample_python_stack(t.ident)
    finally:
        stop.set()
        t.join(timeout=2)
    assert any(fr.symbol == "_marker_fn" for fr in frames)


def test_run_under_budget_flags_an_overrun_and_clears_a_quick_return():
    quick = run_under_budget(lambda: time.sleep(0.01), budget_seconds=1.0)
    assert not quick.killed and quick.run_seconds < 1.0
    over = run_under_budget(lambda: time.sleep(0.5), budget_seconds=0.05)
    assert over.killed                                   # still running at the budget deadline
    assert detect_hang(over.run_seconds, over.budget_seconds, over.frames, killed=over.killed) is not None


def test_redos_demo_hangs_and_is_classified_redos():
    """The ReDoS demo run under a faulthandler budget dumps the re frame and exits — CWE-1333."""
    crafted = "a" * 40 + "!"
    r = subprocess.run([sys.executable, str(DEMOS / "py-redos" / "redos.py"), crafted, "0.3"],
                       capture_output=True, text=True, timeout=20)
    assert r.returncode != 0 and "Timeout" in r.stderr        # the watchdog fired: non-return
    frames = frames_from_traceback(r.stderr)
    f = detect_hang(0.3, 0.3, frames, killed=True, target="py-redos")
    assert f.bug_class == "CWE-1333"
    # replay re-demonstrates the timeout on the same input
    again = subprocess.run([sys.executable, str(DEMOS / "py-redos" / "redos.py"), crafted, "0.3"],
                           capture_output=True, text=True, timeout=20)
    assert again.returncode != 0 and "Timeout" in again.stderr


def test_redos_demo_benign_input_returns_and_is_not_a_hang():
    r = subprocess.run([sys.executable, str(DEMOS / "py-redos" / "redos.py"), "aaa", "1.0"],
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 0 and "Timeout" not in r.stderr    # returned inside the budget


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_c_hang_demo_times_out_and_benign_returns(tmp_path):
    work = _build(DEMOS / "c-hang", tmp_path, ["src/loop.c"], ["-O0"])
    (work / "hang_in").write_bytes(b"Hello")
    (work / "ok_in").write_bytes(b"abc")

    def _runs_to_completion(name: str, budget: float) -> bool:
        try:
            subprocess.run(["./harness", name], cwd=work, capture_output=True, timeout=budget)
            return True
        except subprocess.TimeoutExpired:
            return False

    budget = 1.0
    t0 = time.monotonic()
    hung = not _runs_to_completion("hang_in", budget)
    ran = time.monotonic() - t0
    assert hung, "the 'H' path should not return within the budget"
    f = detect_hang(ran, budget, [Frame("process", "src/loop.c", 8)], killed=True,
                    target="c-hang", language="c/c++")
    assert f.bug_class == "CWE-400"
    # benign input returns promptly -> not a hang
    assert _runs_to_completion("ok_in", budget)


# ============================================================ A9: metamorphic


@pytest.fixture(scope="module")
def padparser():
    return _load(DEMOS / "py-padparser" / "padparser.py", "padparser")


def test_padding_invariance_violation_is_found_with_both_inputs(padparser):
    corpus = [b"rec-1", b"alpha", b"zz"]
    entry = Frame(symbol="checksum", uri=str(DEMOS / "py-padparser" / "padparser.py"), line=18)
    f = check_relations(padparser.checksum, corpus, [PaddingInvariance()],
                        target="py-padparser", entry_point=entry)
    assert f is not None and f.bug_class == "CWE-20" and f.status is Status.SUSPECTED
    assert f.oracle == "metamorphic:padding-invariance"
    a, b = pair_from_finding(f)
    assert b == a + b"\n"                     # the reproducer carries the exact disagreeing pair
    assert f.fix_site_set[0].uri.endswith("padparser.py")


def test_correct_parser_yields_no_metamorphic_finding(padparser):
    corpus = [b"rec-1", b"alpha", b"zz", b"", b"x"]
    assert check_relations(padparser.checksum_fixed, corpus, [PaddingInvariance()]) is None


def test_relation_library_round_trip_and_idempotence():
    bad_rt = check_relations(lambda x: x, [b"hi"],
                             [RoundTrip(encode=lambda x: x + b"X", decode=lambda e: e)])
    assert bad_rt is not None and bad_rt.oracle == "metamorphic:round-trip"
    ok_rt = check_relations(lambda x: x, [b"hi"],
                            [RoundTrip(encode=lambda x: x[::-1], decode=lambda e: e[::-1])])
    assert ok_rt is None

    assert check_relations(lambda s: s + "!", ["a"], [Idempotence()]) is not None
    assert check_relations(lambda s: s.strip(), ["  a "], [Idempotence()]) is None


def test_pair_encoding_round_trips():
    assert decode_pair(encode_pair(b"", b"\x00\x01")) == (b"", b"\x00\x01")
    assert decode_pair(encode_pair(b"abc", b"abc\n")) == (b"abc", b"abc\n")


def test_metamorphic_oracle_claims_only_its_signal():
    raw = "=== RAKSHA METAMORPHIC ===\nrelation: padding-invariance\ncwe: CWE-20\ndetail: mismatch\n"
    (f,) = MetamorphicOracle().parse(raw, target="t")
    assert f.bug_class == "CWE-20" and f.oracle == "metamorphic:padding-invariance"
    assert MetamorphicOracle().parse("2 tests passed\n", target="t") == []


# ============================================================ routing / co-claims


def _claimants(raw: str) -> set[str]:
    return {type(o).__name__ for o in ROUTED if o.parse(raw, target="t")}


def test_exactly_one_oracle_claims_each_new_signal():
    # UBSan / LeakSanitizer are co-claimed by AsanOracle, as a Go race is co-claimed by GoOracle —
    # the flavour-specific oracle is the dedicated reader.
    assert _claimants(UBSAN_REPORT) == {"AsanOracle", "UbsanOracle"}
    assert _claimants(LSAN_REPORT) == {"AsanOracle", "LeakOracle"}
    # hang and metamorphic signals are claimed by their own oracle alone
    assert _claimants(HangSignal(2.0, 1.0, True, []).as_text()) == {"HangOracle"}
    meta = "=== RAKSHA METAMORPHIC ===\nrelation: idempotence\ncwe: CWE-noinfo\ndetail: x\n"
    assert _claimants(meta) == {"MetamorphicOracle"}
    # a clean run is claimed by nobody
    assert _claimants("2 tests passed\n") == set()
