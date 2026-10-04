"""Automatic harness generation: find a bug in a target that ships no fuzz harness.

These run the real toolchain (gcc / python) end to end — discover the entry point, synthesize the
harness, prove the harness with its two-check quality gate, fuzz it, and confirm the crash through
an oracle. A clean target must yield nothing (the mutation fuzzer does not invent crashes).
"""

from __future__ import annotations

import shutil

import pytest

from raksha.finding import Status
from raksha.harness import autofuzz, discover, synthesize
from raksha.harness.forkserver import ForkClient, asan_env
from raksha.harness.mutator import Fuzzer
from raksha.harness.synth import quality_gate

HAVE_GCC = shutil.which("gcc") is not None
REPO = __import__("pathlib").Path(__file__).parents[1]
C_TARGET = REPO / "demo-targets" / "c-nolibfuzzer"
PY_TARGET = REPO / "demo-targets" / "py-noharness"


# ---------------------------------------------------------------- discovery

def test_discovery_finds_the_buffer_entry_point():
    (ep,) = [e for e in discover(C_TARGET) if e.symbol == "parse_record"]
    assert ep.kind == "buf_len" and ep.language == "c/c++" and ep.score >= 5.0


def test_discovery_finds_the_python_entry_point_and_skips_methods(tmp_path):
    (tmp_path / "m.py").write_text(
        "def parse(data):\n    return data\n"
        "class X:\n    def method(self, data):\n        return data\n"
        "def _private(x):\n    return x\n")
    names = {e.symbol for e in discover(tmp_path)}
    assert names == {"parse"}            # top-level one-arg only; method and _private excluded


def test_discovery_reads_source_only_no_execution(tmp_path):
    (tmp_path / "boom.py").write_text("import os\nos.system('touch PWNED')\ndef f(x):\n    return x\n")
    discover(tmp_path)
    assert not (tmp_path / "PWNED").exists()


# ---------------------------------------------------------------- mutator

def test_mutator_is_deterministic():
    def run_one(data):
        return b"\xff\xff\xff\xff" in data
    a = Fuzzer(run_one=run_one, seed=7, max_execs=5000).run()
    b = Fuzzer(run_one=run_one, seed=7, max_execs=5000).run()
    assert a.crashes == b.crashes and a.found


def test_mutator_finds_nothing_in_a_safe_predicate():
    res = Fuzzer(run_one=lambda d: False, max_execs=3000).run()
    assert not res.found and res.executions >= 3000


# ---------------------------------------------------------------- synthesis quality gate

@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_synthesized_c_harness_passes_the_quality_gate():
    (ep,) = [e for e in discover(C_TARGET) if e.symbol == "parse_record"]
    q, built = quality_gate(synthesize(ep), C_TARGET)
    assert q.ok and q.compiles and q.exercises and built.get("binary")


def test_synthesized_python_harness_passes_the_quality_gate():
    (ep,) = [e for e in discover(PY_TARGET) if e.symbol == "convert"]
    q, _ = quality_gate(synthesize(ep), PY_TARGET, benign=b"10 m to ft")
    assert q.ok and q.exercises


def test_a_harness_that_cannot_reach_the_target_is_rejected(tmp_path):
    (tmp_path / "s.py").write_text("def parse(x):\n    raise RuntimeError('always')\n")
    (ep,) = discover(tmp_path)
    q, _ = quality_gate(synthesize(ep), tmp_path, benign=b"anything")
    assert not q.ok           # benign input crashes the harness -> template rejected


# ---------------------------------------------------------------- end to end

@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_autofuzz_finds_and_confirms_a_c_overflow_with_no_harness():
    r = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    assert r.found and r.finding.status is Status.CONFIRMED
    assert r.finding.bug_class in ("CWE-121", "CWE-122", "CWE-787")
    assert r.entrypoint.symbol == "parse_record" and "tlv.c" in r.finding.fix_site_set[0].uri
    # the confirmed finding carries the exact bytes that crash it
    assert r.crashing_input and r.finding.reproducer.artifact_sha256


def test_autofuzz_finds_and_confirms_a_python_command_injection_with_no_harness():
    r = autofuzz(PY_TARGET, max_execs=6000, use_model=False)
    assert r.found and r.finding.bug_class == "CWE-78"
    assert r.finding.status is Status.CONFIRMED and "converter.py" in r.finding.fix_site_set[0].uri


def test_autofuzz_reports_nothing_on_a_clean_target(tmp_path):
    (tmp_path / "ok.py").write_text(
        "def normalise(s):\n"
        "    s = s.decode('utf-8','replace') if isinstance(s, bytes) else s\n"
        "    return s.strip().lower()\n")
    r = autofuzz(tmp_path, max_execs=4000, use_model=False)
    assert not r.found and r.finding is None


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_fork_server_detects_crash_and_clean_and_survives():
    (ep,) = [e for e in discover(C_TARGET) if e.symbol == "parse_record"]
    q, built = quality_gate(synthesize(ep), C_TARGET)
    with ForkClient([str(built["root"] / "raksha_harness")], built["root"], env=asan_env()) as c:
        crash = bytes([0x01, 0x80]) + b"u" * 40      # length 128 into value[32]
        assert c.run_one(crash) is True              # crash detected
        assert c.run_one(b"\x01\x04abcd") is False   # clean input, same live server
        assert c.run_one(crash) is True              # server survived the crash (child died, not it)
        assert c.restarts == 0
