"""The TSan oracle and the concurrency demo target.

Parsing is always-on and runs against three report shapes: gcc's libtsan (captured from this box),
clang's compiler-rt layout, and Go's race detector. The end-to-end run — build c-race with
`-fsanitize=thread`, let the oracle read the real race, prove the mutex fix through all five gate
checks — measured ~6 s on the build box (two sanitizer builds, the corpus, 24 reproducer variants
and a 2 s fresh campaign), so it stays always-on; RAKSHA_SKIP_TSAN=1 skips it on a slow box.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from raksha.finding import Reproducer, ReplayResult, Status, utcnow
from raksha.oracles import ALL_ORACLES, KEYSTONE_ORACLES, AsanOracle, GoOracle, TsanOracle

REPO = Path(__file__).parents[1]
C_RACE = REPO / "demo-targets" / "c-race"
HAVE_GCC = shutil.which("gcc") is not None

GCC_TSAN = """==================
WARNING: ThreadSanitizer: data race (pid=1007)
  Read of size 8 at 0x55f704af3040 by thread T2:
    #0 worker src/worker.c:25 (harness+0x14f5) (BuildId: f0f10c85ea516724447750bbd548d2fc528079b8)

  Previous write of size 8 at 0x55f704af3040 by thread T1:
    #0 worker src/worker.c:25 (harness+0x1558) (BuildId: f0f10c85ea516724447750bbd548d2fc528079b8)

  Location is global 'g_total' of size 8 at 0x55f704af3040 (harness+0x14040)

  Thread T2 (tid=1010, running) created by main thread at:
    #0 pthread_create ../../../../src/libsanitizer/tsan/tsan_interceptors_posix.cpp:1022 (libtsan.so.2+0x5ac1a)
    #1 process src/worker.c:47 (harness+0x16d1)
    #2 main /tmp/raksha-vulnerable-33inqnf5/harness.c:15 (harness+0x13cc)

SUMMARY: ThreadSanitizer: data race src/worker.c:25 in worker
==================
ThreadSanitizer: reported 1 warnings
"""

CLANG_TSAN = """==================
WARNING: ThreadSanitizer: data race (pid=4242)
  Write of size 4 at 0x7b0400000f00 by thread T1:
    #0 0x4a1b2c in bump_index /src/app/src/ring.c:88:9
    #1 0x4a0f10 in producer /src/app/src/ring.c:120:5
    #2 0x7f3c1e2b in __tsan_thread_start_func /build/llvm/compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp:1001

  Previous read of size 4 at 0x7b0400000f00 by main thread:
    #0 0x4a1d40 in drain /src/app/src/ring.c:140:12
    #1 0x4a2000 in main /src/app/main.c:30:3

  Location is heap block of size 64 at 0x7b0400000f00 allocated by main thread:
    #0 0x7f3c1a00 in malloc /build/llvm/compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp:666

SUMMARY: ThreadSanitizer: data race /src/app/src/ring.c:88:9 in bump_index
==================
"""

GO_RACE = """==================
WARNING: DATA RACE
Write at 0x00c000012345 by goroutine 7:
  main.(*Counter).Inc()
      /home/u/proj/counter.go:12 +0x44
  main.worker()
      /home/u/proj/main.go:30 +0x5c

Previous read at 0x00c000012345 by main goroutine:
  main.(*Counter).Value()
      /home/u/proj/counter.go:18 +0x30
  main.main()
      /home/u/proj/main.go:44 +0x1f0
  testing.tRunner()
      /usr/local/go/src/testing/testing.go:1690 +0x1b0

Goroutine 7 (running) created at:
  main.main()
      /home/u/proj/main.go:28 +0x1a4
==================
--- FAIL: TestRace (0.01s)
    testing.go:1465: race detected during execution of test
"""

ASAN_NOT_TSAN = """==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118 at pc 0x4f1b2d
WRITE of size 8 at 0x602000000118 thread T0
    #0 0x4f1b2c in parse_header /src/target/src/parser.c:142:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/target/src/parser.c:142:9 in parse_header
"""


# ------------------------------------------------------------------------ parsing


def test_gcc_report_becomes_a_cwe_362_record_with_both_stacks():
    fs = TsanOracle().parse(GCC_TSAN, target="c-race")
    assert len(fs) == 1
    f = fs[0]
    assert f.bug_class == "CWE-362" and f.severity == "high" and f.language == "c/c++"
    assert f.oracle == "tsan:ThreadSanitizer" and f.status is Status.SUSPECTED
    assert "data race" in f.message and "read vs write" in f.message
    assert [(fr.symbol, fr.uri, fr.line) for fr in f.frames] == [("worker", "src/worker.c", 25)]
    assert f.fix_site_set and f.fix_site_set[0].uri == "src/worker.c" and f.fix_site_set[0].start_line == 25
    assert f.abort_signature and f.dedup_key()
    # the thread-creation stack is context, not an access site: pthread_create / main are not frames
    assert all(fr.symbol not in ("pthread_create", "main") for fr in f.frames)


def test_clang_report_reads_the_current_and_previous_access_stacks():
    f = TsanOracle().parse(CLANG_TSAN, target="ring")[0]
    syms = [fr.symbol for fr in f.frames]
    assert syms == ["bump_index", "producer", "drain", "main"]
    assert f.frames[0].line == 88 and f.frames[0].column == 9
    assert f.fix_site_set[0].symbol == "bump_index"
    assert "write vs read" in f.message
    # runtime frames are dropped
    assert "__tsan_thread_start_func" not in syms


def test_signature_is_the_pair_of_sites_not_one_endpoint():
    a = TsanOracle().parse(CLANG_TSAN, target="t")[0]
    other = CLANG_TSAN.replace("drain /src/app/src/ring.c:140:12", "peek /src/app/src/ring.c:160:4")
    b = TsanOracle().parse(other, target="t")[0]
    assert a.abort_signature != b.abort_signature        # same writer, different reader: two bugs
    again = TsanOracle().parse(CLANG_TSAN.replace("pid=4242", "pid=9"), target="t")[0]
    assert again.abort_signature == a.abort_signature     # pids and addresses do not change identity


def test_go_race_report_is_recognised_with_its_frame_shape():
    f = TsanOracle().parse(GO_RACE, target="proj")[0]
    assert f.bug_class == "CWE-362" and f.language == "go" and f.severity == "high"
    frames = [(fr.symbol, fr.uri.rsplit("/", 1)[-1], fr.line) for fr in f.frames]
    assert frames == [("main.(*Counter).Inc", "counter.go", 12), ("main.worker", "main.go", 30),
                      ("main.(*Counter).Value", "counter.go", 18), ("main.main", "main.go", 44)]
    assert f.fix_site_set[0].start_line == 12


def test_negative_controls_do_not_fire():
    o = TsanOracle()
    assert o.parse(ASAN_NOT_TSAN, target="t") == []
    assert o.parse("all 12 tests passed\nThreadSanitizer: reported 0 warnings\n", target="t") == []
    assert o.parse("", target="t") == []


def test_exactly_one_oracle_claims_each_report():
    def claimants(raw):
        return [type(o).__name__ for o in ALL_ORACLES if o.parse(raw, target="t")]
    assert claimants(GCC_TSAN) == ["TsanOracle"]
    assert claimants(CLANG_TSAN) == ["TsanOracle"]
    # Go's own oracle also reads DATA RACE (the Go lane routes to it); TSan is the shared parser
    assert set(claimants(GO_RACE)) == {"GoOracle", "TsanOracle"}
    assert claimants(ASAN_NOT_TSAN) == ["AsanOracle"]
    # the keystone stays three oracles; TSan is registered alongside, not inside it
    assert len(KEYSTONE_ORACLES) == 3 and not any(isinstance(o, TsanOracle) for o in KEYSTONE_ORACLES)
    assert any(isinstance(o, TsanOracle) for o in ALL_ORACLES) and any(isinstance(o, GoOracle) for o in ALL_ORACLES)
    assert AsanOracle().parse(GCC_TSAN, target="t") == []   # gcc's banner has no ==pid== prefix


def test_go_oracle_and_tsan_agree_on_the_class():
    assert GoOracle().parse(GO_RACE, target="t")[0].bug_class == "CWE-362"


# ------------------------------------------------------------------- the demo target


def test_c_target_sanitizer_option():
    from raksha.adapters.c_asan import c_target
    t = c_target(C_RACE, sanitizer="thread", sources="harness.c src/worker.c")
    assert "-fsanitize=thread" in t.build_cmd and "-lpthread" in t.build_cmd and "src/worker.c" in t.build_cmd
    a = c_target(C_RACE)
    assert "-fsanitize=address" in a.build_cmd and "thread" not in a.build_cmd
    with pytest.raises(ValueError):
        c_target(C_RACE, sanitizer="memory")


def test_the_fix_diff_applies_to_the_demo_source():
    import subprocess
    diff = (C_RACE / "fix.diff").read_text()
    assert "pthread_mutex_lock" in diff and diff.startswith("--- a/src/worker.c")
    r = subprocess.run(["git", "apply", "--check", "-p1", "fix.diff"], cwd=C_RACE, capture_output=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
@pytest.mark.skipif(os.environ.get("RAKSHA_SKIP_TSAN") == "1", reason="RAKSHA_SKIP_TSAN=1")
def test_race_found_by_tsan_and_mutex_fix_proven_through_all_five_checks():
    from raksha.adapters.c_asan import c_target
    from raksha.gate import decide, run_gate
    from raksha.finding import GateCheck

    target = c_target(C_RACE, sanitizer="thread", sources="harness.c src/worker.c")
    pov = b"\x7fABCDEFGHIJ"                       # first byte > 0x40: the parallel path
    vulnerable = target.build(None)
    assert vulnerable.ok, vulnerable.log
    try:
        raw = target.run(vulnerable, pov).text
    finally:
        target.discard(vulnerable)
    findings = TsanOracle().parse(raw, target="c-race")
    assert findings, raw
    f = findings[0]
    assert f.bug_class == "CWE-362" and f.fix_site_set[0].uri.endswith("worker.c")
    f.attach_reproducer(Reproducer.from_bytes(pov, ["./harness", "{input}"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=f.abort_signature, exit_code=66))
    f.confirm()

    from raksha.finding import RepairLane
    f.mark_patched((C_RACE / "fix.diff").read_text(), RepairLane.TEMPLATE)
    corpus = [b"\x01abc", b"\x02\x02\x02\x02", b"\x40zzzz", b"", b"\x10"]
    v = run_gate(f, target, reproducer=pov, corpus=corpus, refuzz_seconds=2, oracles=(TsanOracle(),))
    assert v.passed, f"{v.failed_check}: {v.detail}"
    assert all(f.gate[c].passed for c in GateCheck)
    assert f.replay_after is not None and not f.replay_after.oracle_fired
    assert f.perf_delta is not None
    decide(f, v)
    assert f.status is Status.VERIFIED
