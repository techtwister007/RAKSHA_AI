"""The JavaScript deep lane: a Node target with no hand-written harness, find -> fix -> prove.

The oracle-parse test always runs (no toolchain). The rest need `node`; node is fast, so the
end-to-end test is always-on when node is present (it runs in a few seconds), not env-gated.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from raksha.adapters.js_sink import discover_js, js_autofuzz, js_shell_safe
from raksha.finding import GATE_ORDER, RepairLane, Status
from raksha.gate.runner import decide, run_gate
from raksha.oracles.js_sink import JsSinkOracle

HAVE_NODE = shutil.which("node") is not None
# The clean-target test runs a FULL fuzz budget with a node process per execution (no fork server),
# which takes ~90s — the one test over the ~10s bar — so it is env-gated. The find->fix->prove
# end-to-end test is only ~4s (one injection fires in the first handful of execs) and stays always-on.
RUN_JS = os.environ.get("RAKSHA_RUN_JS") == "1"
REPO = Path(__file__).parents[1]
JS_TARGET = REPO / "demo-targets" / "js-noharness"

_BANNER = (
    "converting: ok\n"
    "=== BUG DETECTED: JsSec: command injection ===\n"
    "JsSec: command injection detected in child_process.execSync\n"
    "  at convert (converter.js:11)\n"
)


# ---------------------------------------------------------------- oracle (always on)

def test_js_oracle_parses_the_injection_banner():
    (f,) = JsSinkOracle().parse(_BANNER, target="js-noharness")
    assert f.language == "javascript"
    assert f.bug_class == "CWE-78"
    assert f.severity == "high"
    assert f.oracle == "jssec:command-injection"
    assert f.status is Status.SUSPECTED                 # oracles never confirm
    assert "command injection" in f.message
    assert f.frames[0].symbol == "convert"
    assert f.frames[0].uri == "converter.js"
    assert f.frames[0].line == 11
    assert f.fix_site_set[0].uri == "converter.js"      # localised to target code, not the guard


def test_js_oracle_is_silent_on_clean_output():
    assert JsSinkOracle().parse("converting: 10m\n", target="x") == []
    assert JsSinkOracle().parse("", target="x") == []


# ---------------------------------------------------------------- discovery (always on)

def test_discovery_finds_the_js_entry_point():
    (ep,) = [e for e in discover_js(JS_TARGET) if e.symbol == "convert"]
    assert ep.language == "javascript" and ep.kind == "one_arg"


# ---------------------------------------------------------------- repair template (always on)

def test_js_shell_safe_yields_an_applying_diff(tmp_path):
    (f,) = JsSinkOracle().parse(_BANNER, target="js-noharness")
    diff = js_shell_safe(f, JS_TARGET)
    assert diff is not None
    assert "execFileSync('echo', ['converting:', spec])" in diff
    assert "+++ b/converter.js" in diff

    # it applies to a fresh copy of the demo target
    work = tmp_path / "t"
    shutil.copytree(JS_TARGET, work)
    (work / ".p.diff").write_text(diff)
    r = subprocess.run("git apply -p1 .p.diff 2>/dev/null || patch -p1 < .p.diff",
                       cwd=work, shell=True, capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    patched = (work / "converter.js").read_text()
    assert "execFileSync" in patched and "execSync('echo converting: '" not in patched


@pytest.mark.skipif(not HAVE_NODE, reason="needs node")
def test_patched_converter_is_safe_and_keeps_benign_output(tmp_path):
    (f,) = JsSinkOracle().parse(_BANNER, target="js-noharness")
    diff = js_shell_safe(f, JS_TARGET)
    work = tmp_path / "t"
    shutil.copytree(JS_TARGET, work)
    shutil.copy2(REPO / "raksha" / "harness" / "jssinkguard.js", work / "jssinkguard.js")
    (work / ".p.diff").write_text(diff)
    subprocess.run("git apply -p1 .p.diff 2>/dev/null || patch -p1 < .p.diff",
                   cwd=work, shell=True, check=True)
    env = {"RAKSHA_JS_MODULE": "./converter.js", "RAKSHA_JS_SYMBOL": "convert"}
    env = {**os.environ, **env}

    def run(spec: str):
        (work / "in").write_text(spec)
        return subprocess.run(["node", "jssinkguard.js", "in"], cwd=work,
                              capture_output=True, env=env)

    benign = run("10m")
    assert benign.returncode == 0 and benign.stdout == b"converting: 10m\n"
    inj = run("x; id")                                  # the injection no longer fires the guard
    assert inj.returncode == 0 and b"BUG DETECTED" not in inj.stderr


# ---------------------------------------------------------------- benign input does not fire

@pytest.mark.skipif(not HAVE_NODE, reason="needs node")
def test_benign_input_does_not_fire_the_guard(tmp_path):
    work = tmp_path / "t"
    shutil.copytree(JS_TARGET, work)
    shutil.copy2(REPO / "raksha" / "harness" / "jssinkguard.js", work / "jssinkguard.js")
    env = {**os.environ, "RAKSHA_JS_MODULE": "./converter.js", "RAKSHA_JS_SYMBOL": "convert"}
    (work / "in").write_text("10m")
    p = subprocess.run(["node", "jssinkguard.js", "in"], cwd=work, capture_output=True, env=env)
    assert p.returncode == 0
    assert JsSinkOracle().parse((p.stdout + b"\n" + p.stderr).decode(), target="x") == []


# ---------------------------------------------------------------- end to end (always on with node)

@pytest.mark.skipif(not HAVE_NODE, reason="needs node")
def test_js_autofuzz_finds_and_confirms_a_command_injection_with_no_harness():
    r = js_autofuzz(JS_TARGET, max_execs=6000)
    assert r.found and r.finding.bug_class == "CWE-78"
    assert r.finding.status is Status.CONFIRMED
    assert "converter.js" in r.finding.fix_site_set[0].uri
    assert r.entrypoint.symbol == "convert"
    assert r.crashing_input and r.finding.reproducer.artifact_sha256


@pytest.mark.skipif(not HAVE_NODE, reason="needs node")
def test_js_lane_fixes_and_proves_through_all_five_gate_checks():
    r = js_autofuzz(JS_TARGET, max_execs=6000)
    assert r.found
    f = r.finding
    diff = js_shell_safe(f, r.target.source_root)
    assert diff
    f.mark_patched(diff, RepairLane.TEMPLATE)
    verdict = run_gate(f, r.target, reproducer=r.crashing_input,
                       corpus=[b"10m", b"5 kg", b"warm", b"status"],
                       refuzz_seconds=4.0, oracles=(JsSinkOracle(),))
    assert verdict.passed, f"{verdict.failed_check}: {verdict.detail}"
    assert all(f.gate[c].passed for c in GATE_ORDER)
    assert decide(f, verdict) is Status.VERIFIED
    assert f.replay_after is not None and not f.replay_after.oracle_fired


@pytest.mark.skipif(not (HAVE_NODE and RUN_JS),
                    reason="needs node; full-budget clean-target fuzz is ~90s — set RAKSHA_RUN_JS=1")
def test_js_autofuzz_reports_nothing_on_a_clean_target(tmp_path):
    (tmp_path / "safe.js").write_text(
        "'use strict';\n"
        "function normalise(spec) { return String(spec).trim().toLowerCase(); }\n"
        "module.exports = { normalise };\n")
    r = js_autofuzz(tmp_path, max_execs=2000)
    assert not r.found and r.finding is None
