"""Oracle precision on realistic tool output.

A wrong CWE is a scoring miss; a status line mistaken for a crash breaks the gate (POV_DEAD asks the
oracles "did the attack still fire?"). Each case here is an output shape the tools really print.
"""

from __future__ import annotations

import pytest

from raksha.finding import Finding, Frame, Reproducer
from raksha.oracles import AsanOracle, JazzerOracle, PySecSanOracle


def _asan(raw: str):
    found = AsanOracle().parse(raw, target="t")
    return found[0] if found else None


# ---------------------------------------------------------------- native

def test_msan_warning_banner_is_a_finding():
    f = _asan("==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n    #0 0x1 in f /s/a.c:3:1\n")
    assert f and f.bug_class == "CWE-457"


def test_leak_sanitizer_reports_a_leak_not_a_byte_count():
    raw = ("==1==ERROR: LeakSanitizer: detected memory leaks\n"
           "Direct leak of 24 byte(s) in 1 object(s) allocated from:\n    #0 0x1 in malloc x\n"
           "    #1 0x2 in make /s/a.c:9:3\n"
           "SUMMARY: AddressSanitizer: 24 byte(s) leaked in 1 allocation(s).\n")
    f = _asan(raw)
    assert f.bug_class == "CWE-401" and "memory-leaks" in f.message


@pytest.mark.parametrize("kind,cwe", [
    ("bad-free", "CWE-590"), ("stack-use-after-return", "CWE-562"), ("stack-use-after-scope", "CWE-416"),
    ("stack-buffer-underflow", "CWE-124"), ("allocation-size-too-big", "CWE-789"),
])
def test_asan_kinds_map_to_a_cwe(kind, cwe):
    f = _asan(f"==1==ERROR: AddressSanitizer: {kind} on address 0x1\n    #0 0x1 in f /s/a.c:3:1\n"
              f"SUMMARY: AddressSanitizer: {kind} /s/a.c:3:1 in f\n")
    assert f.bug_class == cwe


def test_out_of_bounds_read_is_cwe_125_not_a_write():
    f = _asan("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff8\n"
              "READ of size 8 at 0x60200000eff8 thread T0\n    #0 0x1 in f /s/a.c:3:1\n")
    assert f.bug_class == "CWE-125"


@pytest.mark.parametrize("raw,cwe", [
    ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x1)\n"
     "==1==The signal is caused by a READ memory access.\n", "CWE-476"),
    ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x602000ffff00 (pc 0x1)\n"
     "==1==The signal is caused by a WRITE memory access.\n", "CWE-787"),
])
def test_segv_is_classified_by_address_and_access(raw, cwe):
    assert _asan(raw + "    #0 0x1 in f /s/a.c:3:1\n").bug_class == cwe


@pytest.mark.parametrize("kind,cwe", [("timeout", "CWE-400"), ("out-of-memory", "CWE-789")])
def test_libfuzzer_aborts_are_findings(kind, cwe):
    f = _asan(f"==9== ERROR: libFuzzer: {kind} (malloc(1234))\n")
    assert f and f.bug_class == cwe


def test_ubsan_needs_native_source():
    assert _asan("app.py:12:3: runtime error: retrying connection\n") is None
    assert _asan("src/a.c:12:3: runtime error: index 9 out of bounds for type 'int [4]'\n").bug_class == "CWE-129"


# ---------------------------------------------------------------- JVM

def test_jazzer_multiline_title_resolves_the_specific_cwe():
    raw = ("== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution\n"
           "Deserialization of arbitrary classes is a security issue.\n"
           "\tat com.example.Loader.load(Loader.java:10)\n")
    (f,) = JazzerOracle().parse(raw, target="t")
    assert f.bug_class == "CWE-502"


def test_jazzer_timeout_is_not_redos():
    (f,) = JazzerOracle().parse("== Java Exception: com.code_intelligence.jazzer.api."
                                "FuzzerSecurityIssueLow: Timeout\n\tat a.B.c(B.java:1)\n", target="t")
    assert f.bug_class == "CWE-400"


def test_two_command_injections_in_different_callers_stay_distinct():
    def log(caller: str) -> str:
        return ("== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: "
                "OS Command Injection\n"
                "\tat com.code_intelligence.jazzer.sanitizers.OsCommandInjection.hook(X.java:1)\n"
                "\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1107)\n"
                f"\tat com.example.{caller}(Svc.java:42)\n")
    (a,) = JazzerOracle().parse(log("Runner.runA"), target="t")
    (b,) = JazzerOracle().parse(log("Other.runB"), target="t")
    assert a.abort_signature != b.abort_signature


def test_jazzer_reports_every_banner_and_root_causes():
    raw = ("== Java Exception: java.lang.RuntimeException: wrapped\n\tat a.B.c(B.java:1)\n"
           "Caused by: java.lang.ArrayIndexOutOfBoundsException: 5\n\tat a.B.d(B.java:9)\n"
           "== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: SQL Injection\n"
           "\tat a.Dao.q(Dao.java:3)\n")
    first, second = JazzerOracle().parse(raw, target="t")
    assert first.bug_class == "CWE-125" and second.bug_class == "CWE-89"


# ---------------------------------------------------------------- Python

@pytest.mark.parametrize("line", ["PySecSan: enabled", "PySecSan: hooks installed",
                                  "[INFO] PySecSan: instrumenting sinks: subprocess, eval"])
def test_pysecsan_status_lines_are_not_findings(line):
    assert PySecSanOracle().parse(line + "\nok\n", target="t") == []


@pytest.mark.parametrize("raw", [
    "PySecSan: command injection detected in subprocess.run\n",
    "===BUG DETECTED: PySecSan: Command injection ===\n",
    "PySecSanSinkException: command injection\n",
])
def test_pysecsan_detection_shapes_are_findings(raw):
    (f,) = PySecSanOracle().parse(raw, target="t")
    assert f.bug_class == "CWE-78"


# ---------------------------------------------------------------- crash dedup

def test_two_overflows_in_one_function_are_two_bugs():
    def finding(line: int) -> Finding:
        f = Finding(oracle="asan", bug_class="CWE-122", language="c/c++", target="t", message="m",
                    frames=[Frame(symbol="parse", uri="/s/parse.c", line=line),
                            Frame(symbol="main", uri="/s/main.c", line=4)])
        f.attach_reproducer(Reproducer.from_bytes(b"x", ["./h"]))
        return f
    assert finding(20).dedup_key() != finding(55).dedup_key()
