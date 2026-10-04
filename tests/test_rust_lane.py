"""The Rust deep lane: stable `cargo test` as the runner, RAKSHA's mutation as the engine, oracle,
and find→fix→prove with no hand-written harness.

The oracle, discovery and template tests always run (pure Python, no toolchain). The end-to-end test
builds the crate three times and runs a fuzzing campaign, so it is opt-in behind RAKSHA_RUN_RUST=1
(measured ~7.4 s warm; a cold cargo build can exceed that), mirroring RAKSHA_RUN_GO.
"""

from __future__ import annotations

import os
import pathlib
import shutil

import pytest

from raksha.adapters.rust_fuzz import (discover_rust, rust_autofuzz, rust_bound_index,
                                       synthesize_rust_harness)
from raksha.finding import RepairLane, Status
from raksha.oracles.rust_panic import RustPanicOracle

HAVE_CARGO = shutil.which("cargo") is not None
RUN_RUST = os.environ.get("RAKSHA_RUN_RUST") == "1"
REPO = pathlib.Path(__file__).parents[1]
RUST_TARGET = REPO / "demo-targets" / "rust-nolibfuzzer"

# The new (1.65+) panic layout rustc 1.97 prints: location on the `panicked at` line, message on the
# next, with libtest's short backtrace. The crate's own frame is src/lib.rs; std/core/harness frames
# must be skipped when localising.
PANIC_NEW = """running 1 test
test raksha_fuzz ... FAILED

---- raksha_fuzz stdout ----

thread 'raksha_fuzz' (12803) panicked at src/lib.rs:18:21:
range end index 257 out of range for slice of length 2
stack backtrace:
   0: __rustc::rust_begin_unwind
             at /rustc/2d8144b7/library/std/src/panicking.rs:689:5
   5: rust_nolibfuzzer::parse_record
             at ./src/lib.rs:18:21
   6: raksha_fuzz::raksha_fuzz
             at ./tests/raksha_fuzz.rs:10:9

test result: FAILED. 0 passed; 1 failed; 0 ignored
"""

# The old (pre-1.65) single-line layout, kept parseable for logs captured from earlier toolchains.
PANIC_OLD = """thread 'main' panicked at 'index out of bounds: the len is 3 but the index is 9', src/parser.rs:42:13
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
"""


def test_rust_oracle_parses_the_new_panic_format_and_localises_to_the_crate():
    (f,) = RustPanicOracle().parse(PANIC_NEW, target="rust-nolibfuzzer")
    assert f.language == "rust" and f.oracle == "rust:panic"
    assert f.bug_class == "CWE-125" and f.severity == "high"
    assert "range end index" in f.message
    assert f.status is Status.SUSPECTED            # oracles never confirm
    # localised to the crate's own code, not std / the synthesized harness
    site = f.fix_site_set[0]
    assert site.uri == "src/lib.rs" and site.start_line == 18
    assert site.symbol == "rust_nolibfuzzer::parse_record"
    assert "panicking.rs" not in " ".join(fr.uri or "" for fr in f.frames)
    assert "raksha_fuzz.rs" not in " ".join(fr.uri or "" for fr in f.frames)


def test_rust_oracle_parses_the_old_panic_format():
    (f,) = RustPanicOracle().parse(PANIC_OLD, target="t")
    assert f.bug_class == "CWE-125" and f.language == "rust"
    assert f.fix_site_set[0].uri == "src/parser.rs" and f.fix_site_set[0].start_line == 42


@pytest.mark.parametrize("msg,cwe", [
    ("range end index 257 out of range for slice of length 2", "CWE-125"),
    ("index out of bounds: the len is 3 but the index is 9", "CWE-125"),
    ("attempt to add with overflow", "CWE-190"),
    ("attempt to multiply with overflow", "CWE-190"),
    ("attempt to divide by zero", "CWE-369"),
    ("called `Option::unwrap()` on a `None` value", "CWE-476"),
    ("called `Result::unwrap()` on an `Err` value: Oops", "CWE-476"),
])
def test_rust_oracle_cwe_mapping(msg, cwe):
    raw = f"thread 'main' (1) panicked at src/x.rs:4:9:\n{msg}\n"
    (f,) = RustPanicOracle().parse(raw, target="t")
    assert f.bug_class == cwe


def test_rust_oracle_emits_exactly_one_claim_per_panic():
    """The 'exactly one oracle claims this output' rule the keystone tests assert: one panic in,
    one record out."""
    assert len(RustPanicOracle().parse(PANIC_NEW, target="t")) == 1


def test_rust_oracle_is_silent_on_a_clean_run():
    assert RustPanicOracle().parse(
        "running 1 test\ntest raksha_fuzz ... ok\n\ntest result: ok. 1 passed; 0 failed\n",
        target="t") == []


def test_discovers_rust_entry_point():
    (ep,) = [e for e in discover_rust(RUST_TARGET) if e.symbol == "parse_record"]
    assert ep.language == "rust" and ep.kind == "rust_bytes"
    assert synthesize_rust_harness(ep, "rust_nolibfuzzer").count("rust_nolibfuzzer::parse_record") == 2


def test_rust_template_produces_an_applying_bound_for_the_demo_bug(tmp_path):
    """rust_bound_index clamps the unbounded slice at the fix site and the diff applies to the
    pristine crate source (git apply --check), with no toolchain needed."""
    (f,) = RustPanicOracle().parse(PANIC_NEW, target="rust-nolibfuzzer")
    diff = rust_bound_index(f, RUST_TARGET)
    assert diff and "usize::min(2 + n, data.len())" in diff
    # prove it applies against a fresh copy of the crate
    copy = tmp_path / "crate"
    shutil.copytree(RUST_TARGET, copy)
    (copy / ".raksha.patch").write_text(diff)
    import subprocess
    subprocess.run(["git", "init", "-q"], cwd=copy, check=True)
    r = subprocess.run(["git", "apply", "--check", "-p1", ".raksha.patch"], cwd=copy,
                       capture_output=True)
    assert r.returncode == 0, r.stderr.decode()


@pytest.mark.skipif(not (HAVE_CARGO and RUN_RUST),
                    reason="slow; set RAKSHA_RUN_RUST=1 with the cargo toolchain")
def test_rust_autofuzz_finds_fixes_and_proves_with_no_harness():
    from raksha.gate.runner import decide, run_gate
    r = rust_autofuzz(RUST_TARGET, fuzztime_s=10)
    assert r.found and r.finding.bug_class == "CWE-125"
    assert r.finding.status is Status.CONFIRMED

    # a short benign input does not panic — the oracle stays silent on the harness run
    before = r.target.build(None)
    try:
        benign = r.target.run(before, b"\x01\x01\x05")
        assert not RustPanicOracle().parse(benign.text, target="t")
        assert benign.exit_code == 0
    finally:
        r.target.discard(before)

    diff = rust_bound_index(r.finding, RUST_TARGET)
    assert diff
    r.finding.mark_patched(diff, RepairLane.TEMPLATE)
    verdict = run_gate(r.finding, r.target, reproducer=r.crashing_input,
                       corpus=[b"\x01\x01\x05", b"\x02ab", b"\x00", b""],
                       oracles=(RustPanicOracle(),), refuzz_seconds=5)
    assert verdict.passed, (verdict.failed_check, verdict.detail)
    assert decide(r.finding, verdict) is Status.VERIFIED
    assert r.finding.gate_passed
