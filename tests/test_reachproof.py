"""G1: solver evidence that the patched guard makes the bad index unreachable (never a decider)."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from raksha.reachproof import ask, guards_at, reach_proof

z3 = pytest.importorskip("z3")
REPO = Path(__file__).parents[1]


def test_loop_guard_before_and_after():
    assert ask(["i < count", "i >= 0"], "data", "i + 1")["status"] == "reachable"
    assert ask(["i < count && (i + 1) < data.length", "i >= 0"], "data", "i + 1")["status"] == "unreachable"


def test_off_by_one_guard_is_caught():
    r = ask(["i >= 0", "i + 1 <= data.length"], "data", "i + 1")
    assert r["status"] == "reachable" and r["witness"]          # i + 1 == length slips through


def test_unmodelled_expression_is_said_so():
    assert ask(["obj.ok()"], "data", "i")["status"] == "not-modelled"


def test_guards_read_from_code():
    src = ["static int f(byte[] d, int n) {", "    if (d.length == 0) {", "        return 0;", "    }",
           "    for (int i = 0; i < n; i++) {", "        s += d[i];", "    }", "}"]
    conds, notes = guards_at(src, 5)
    assert "i < n" in [c.strip() for c in conds] and "i >= 0" in conds
    assert any(c.startswith("not (d.length == 0") for c in conds)


@pytest.mark.skipif(shutil.which("javac") is None, reason="no JDK")
def test_java_demo_fix_carries_unreachability():
    from raksha.adapters.java_driver import java_autofuzz, java_bound_index
    r = java_autofuzz(REPO / "demo-targets" / "java-noharness")
    rec = reach_proof(r.finding, r.target.source_root, java_bound_index(r.finding, r.target.source_root))
    assert rec["before"]["status"] == "reachable" and rec["after"]["status"] == "unreachable"
    assert "overflow not modelled" in rec["premises"][0]


@pytest.mark.skipif(shutil.which("javac") is None, reason="no JDK")
def test_a_wrong_fix_is_seen_through(tmp_path):
    from raksha.adapters.java_driver import java_autofuzz, java_bound_index
    r = java_autofuzz(REPO / "demo-targets" / "java-noharness")
    good = java_bound_index(r.finding, r.target.source_root)
    bad = good.replace("(i + 1) < data.length", "(i + 1) <= data.length")
    assert reach_proof(r.finding, r.target.source_root, bad)["after"]["status"] == "reachable"
