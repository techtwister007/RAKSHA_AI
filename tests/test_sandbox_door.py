"""Every spawn of target code — gate commands AND hot loops — goes through the sandbox door."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from raksha import sandbox
from raksha.sandbox import Sandbox, SandboxPolicy, SandboxRequired, _sandboxed_argv, popen_target, run_target

REPO = Path(__file__).parents[1]


def test_sandboxed_argv_remaps_paths_and_passes_only_added_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTONLY", "secret-host-value")
    box = Sandbox(SandboxPolicy(image="img:1"))
    env = {"HOSTONLY": "secret-host-value", "LD_PRELOAD": f"{tmp_path}/x.so"}
    argv = _sandboxed_argv(box, ["./bin", f"{tmp_path}/in"], str(tmp_path), env, False)
    assert "--network=none" in argv and argv[argv.index("img:1") - 1] == "LD_PRELOAD=/work/x.so"
    assert not any("HOSTONLY" in a for a in argv)              # the host env never enters
    assert argv[-1] == "./bin /work/in"


def test_required_sandbox_refuses_hot_loops(tmp_path, monkeypatch):
    monkeypatch.delenv("RAKSHA_SANDBOX_IMAGE", raising=False)
    monkeypatch.setenv("RAKSHA_REQUIRE_SANDBOX", "1")
    r = run_target(["true"], str(tmp_path))
    assert r.returncode == 126 and b"SANDBOX REQUIRED" in r.stderr
    with pytest.raises(SandboxRequired):
        popen_target(["cat"], str(tmp_path))


def test_dev_box_runs_and_counts(tmp_path, monkeypatch):
    monkeypatch.delenv("RAKSHA_SANDBOX_IMAGE", raising=False)
    monkeypatch.delenv("RAKSHA_REQUIRE_SANDBOX", raising=False)
    before = sandbox.execution_counts()["unsandboxed_runs"]
    assert run_target(["sh", "-c", "echo hi"], str(tmp_path)).stdout.strip() == b"hi"
    assert sandbox.execution_counts()["unsandboxed_runs"] == before + 1


# Files that spawn TARGET code. Each must do so only through run_untrusted / run_target /
# popen_target — a direct subprocess call here is a sandbox bypass.
TARGET_SPAWNERS = [
    "raksha/harness/forkserver.py", "raksha/harness/autofuzz.py", "raksha/harness/synth.py",
    "raksha/harness/interpose.py", "raksha/behaviour.py", "raksha/adapters/js_sink.py",
    "raksha/adapters/go_fuzz.py", "raksha/adapters/rust_fuzz.py", "raksha/adapters/java_driver.py",
    "raksha/adapters/java.py", "raksha/gate/target.py", "raksha/lanes/reprobuild.py",
]


@pytest.mark.parametrize("rel", TARGET_SPAWNERS)
def test_no_direct_spawn_of_target_code(rel):
    tree = ast.parse((REPO / rel).read_text())
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" \
                and node.func.attr in {"run", "Popen", "call", "check_output", "check_call"}:
            src = (REPO / rel).read_text().splitlines()[node.lineno - 1]
            if "raksha-own" not in src:      # RAKSHA's own code (compiling a shim, copying a tree)
                bad.append(node.lineno)
    assert not bad, f"{rel} spawns directly at lines {bad}"


def test_run_untrusted_carries_target_env_into_sandbox(tmp_path, monkeypatch):
    seen = {}

    class FakeBox(Sandbox):
        def available(self):
            return True

    def fake_run(argv, **kw):
        seen["argv"] = argv
        import subprocess
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    import os
    sandbox.run_untrusted("node g.js", str(tmp_path), env={**os.environ, "RAKSHA_JS_MODULE": "./m.js"},
                          sandbox=FakeBox(SandboxPolicy(image="img:1")))
    assert "RAKSHA_JS_MODULE=./m.js" in seen["argv"]
