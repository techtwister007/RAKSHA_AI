"""The Go deep lane: native `go test -fuzz`, oracle, and find→fix→prove with no hand-written harness.

The end-to-end test needs the Go toolchain and is slow (a fuzzing campaign), so it is opt-in behind
RAKSHA_RUN_GO=1; the oracle and discovery tests always run.
"""

from __future__ import annotations

import os
import shutil

import pytest

from raksha.finding import Status
from raksha.harness.entrypoints import discover
from raksha.oracles.go_panic import GoOracle

HAVE_GO = shutil.which("go") is not None
RUN_GO = os.environ.get("RAKSHA_RUN_GO") == "1"
REPO = __import__("pathlib").Path(__file__).parents[1]
GO_TARGET = REPO / "demo-targets" / "go-decoder"

PANIC = """--- FAIL: FuzzRaksha (0.00s)
    panic: runtime error: slice bounds out of range [:49] with length 1 [recovered]
        panic: runtime error: slice bounds out of range [:49] with length 1

goroutine 23 [running]:
raksha.example/decoder.Decode(...)
\t/tmp/x/decoder.go:12 +0x1d
raksha.example/decoder.FuzzRaksha.func1(0x0?, {0xc000100000, 0x1, 0x1})
\t/tmp/x/raksha_fuzz_test.go:8 +0x3c
testing.(*F).Fuzz.func1.1(0xc000003a00?)
\t/usr/local/go/src/testing/fuzz.go:340 +0x2f5
"""


def test_go_oracle_classifies_a_slice_panic_and_localises_to_the_target():
    (f,) = GoOracle().parse(PANIC, target="go-decoder")
    assert f.bug_class == "CWE-125" and f.language == "go"
    # localised to the target's own code, not the runtime / testing / synthesized harness frames
    assert f.fix_site_set[0].uri.endswith("decoder.go") and f.fix_site_set[0].start_line == 12


@pytest.mark.parametrize("msg,cwe", [
    ("panic: runtime error: integer divide by zero", "CWE-369"),
    ("panic: runtime error: invalid memory address or nil pointer dereference", "CWE-476"),
    ("panic: runtime error: index out of range [5] with length 3", "CWE-125"),
])
def test_go_oracle_cwe_mapping(msg, cwe):
    (f,) = GoOracle().parse(msg + "\n\ngoroutine 1 [running]:\nx.Y(...)\n\t/tmp/x/y.go:4 +0x1\n", target="t")
    assert f.bug_class == cwe


def test_go_oracle_ignores_non_panic_output():
    assert GoOracle().parse("ok  \traksha.example/decoder\t0.2s\n", target="t") == []


def test_discovers_go_entry_point():
    (ep,) = [e for e in discover(GO_TARGET) if e.symbol == "Decode"]
    assert ep.language == "go" and ep.kind == "go_bytes"


@pytest.mark.skipif(not (HAVE_GO and RUN_GO), reason="slow; set RAKSHA_RUN_GO=1 with the go toolchain")
def test_go_autofuzz_finds_fixes_and_proves_with_no_harness():
    from raksha.adapters.go_fuzz import go_autofuzz
    from raksha.autorepair import repair
    r = go_autofuzz(GO_TARGET, fuzztime_s=10)
    assert r.found and r.finding.bug_class == "CWE-125"
    out = repair(r.finding, r.target, root=GO_TARGET, reproducer=r.crashing_input,
                 corpus=[b"\x02ab", b"\x00", b"\x01z"], use_model=False, refuzz_seconds=5)
    assert out.verified and r.finding.status is Status.VERIFIED
