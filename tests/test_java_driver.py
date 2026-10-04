"""B5: Java with no hand-written harness — discover, synthesize a driver, fuzz, fix, prove."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from raksha.adapters.java_driver import (discover_java, java_autofuzz, java_bound_index,
                                         method_span, synthesize_driver)
from raksha.finding import RepairLane, Status

DEMO = Path(__file__).parents[1] / "demo-targets" / "java-noharness"
HAVE_JDK = shutil.which("javac") is not None and shutil.which("java") is not None


def test_discovers_public_static_entry_point():
    eps = discover_java(DEMO)
    assert eps and eps[0].ep.symbol == "parse"
    assert eps[0].fqcn == "com.example.noharness.Parser" and eps[0].arg == "bytes"


def test_driver_reports_in_jazzer_format_and_skips_declared(tmp_path):
    src = tmp_path / "src/main/java/p"; src.mkdir(parents=True)
    (src / "Q.java").write_text("package p;\npublic class Q {\n"
                                "  public static int run(String s) throws IllegalStateException {\n"
                                "    return s.length();\n  }\n}\n")
    je = discover_java(tmp_path)[0]
    assert je.throws == ("IllegalStateException",) and je.arg == "string"
    drv = synthesize_driver(je)
    assert "== Java Exception: " in drv and '"IllegalStateException"' in drv
    assert "p.Q.run(new String(d" in drv


def test_method_span():
    start = discover_java(DEMO)[0].ep.line
    a, b = method_span(DEMO / discover_java(DEMO)[0].ep.path, start)
    assert a == start and b > a + 5


@pytest.mark.skipif(not HAVE_JDK, reason="no JDK")
def test_find_fix_prove_java_noharness():
    from raksha.gate.runner import decide, run_gate
    from raksha.oracles.jazzer import JazzerOracle
    r = java_autofuzz(DEMO)
    assert r.found, r.note
    f = r.finding
    assert f.status is Status.CONFIRMED and f.bug_class == "CWE-125"
    assert f.fix_site_set[0].uri.startswith("src/main/java/")      # resolved to a patchable path
    diff = java_bound_index(f, r.target.source_root)
    assert diff and "data.length" in diff
    f.mark_patched(diff, RepairLane.TEMPLATE)
    corpus = [b"\x02ab", b"\x00xy", b"\x03abc", b"", b"\x01z"] + r.benign_corpus
    v = run_gate(f, r.target, reproducer=r.crashing_input, corpus=corpus, refuzz_seconds=3.0,
                 oracles=(JazzerOracle(),))
    assert decide(f, v) is Status.VERIFIED, v.detail
