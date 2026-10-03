"""The build agent: detection, the remedy loop, and — the point — clean degradation to build-free."""

from __future__ import annotations

from pathlib import Path

from raksha.buildagent import BuildAgent, BuildSystem, detect_build_system


class ScriptedRunner:
    """Returns queued (exit, output) results per call, so we can script a build's behaviour."""

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def run(self, cmd, cwd):
        self.calls.append(cmd)
        return self.results.pop(0) if self.results else (0, "ok")


def _mk(tmp_path: Path, filename: str) -> Path:
    (tmp_path / filename).write_text("x")
    return tmp_path


def test_detects_build_systems(tmp_path):
    (tmp_path / "mvn").mkdir(); (tmp_path / "mvn" / "pom.xml").write_text("x")
    (tmp_path / "go").mkdir(); (tmp_path / "go" / "go.mod").write_text("x")
    assert detect_build_system(tmp_path / "mvn") is BuildSystem.MAVEN
    assert detect_build_system(tmp_path / "go") is BuildSystem.GO


def test_detects_most_specific_marker_first(tmp_path):
    (tmp_path / "pom.xml").write_text("x")
    (tmp_path / "Makefile").write_text("x")
    assert detect_build_system(tmp_path) is BuildSystem.MAVEN


def test_unknown_build_system_degrades_immediately(tmp_path):
    (tmp_path / "README").write_text("x")
    agent = BuildAgent(ScriptedRunner([]))
    out = agent.build(tmp_path)
    assert not out.ok and out.degraded
    assert "build-free" in out.log


def test_builds_first_try(tmp_path):
    _mk(tmp_path, "go.mod")
    out = BuildAgent(ScriptedRunner([(0, "ok")])).build(tmp_path)
    assert out.ok and not out.degraded and out.attempts == 1 and out.remedies_applied == []


def test_applies_a_known_remedy_then_succeeds(tmp_path):
    _mk(tmp_path, "pom.xml")
    runner = ScriptedRunner([
        (1, "Could not resolve artifact com.example:lib:1.0"),  # known error
        (0, "ok"),                                              # retry succeeds
    ])
    out = BuildAgent(runner).build(tmp_path)
    assert out.ok
    assert out.remedies_applied == ["maven-missing-artifact"]


def test_npm_lockfile_mismatch_triggers_install_fallback(tmp_path):
    _mk(tmp_path, "package.json")
    runner = ScriptedRunner([
        (1, "npm ci can only install packages when your package.json and package-lock.json are in sync"),
        (0, "added 10 packages"),   # the remedy command (npm install) succeeds
        (0, "ok"),                  # retry build
    ])
    out = BuildAgent(runner).build(tmp_path)
    assert out.ok and "npm-lockfile-mismatch" in out.remedies_applied
    assert any("npm install" in c for c in runner.calls)


def test_unknown_error_degrades_to_build_free(tmp_path):
    _mk(tmp_path, "pom.xml")
    runner = ScriptedRunner([(1, "BUILD FAILURE: something we have never seen")])
    out = BuildAgent(runner).build(tmp_path)
    assert not out.ok and out.degraded
    assert "unknown build error" in out.log
    assert "build-free" in out.summary


def test_persistent_known_error_gives_up_after_max_attempts(tmp_path):
    _mk(tmp_path, "pom.xml")
    runner = ScriptedRunner([(1, "Could not resolve artifact x:y:1")] * 10)
    out = BuildAgent(runner, max_attempts=3).build(tmp_path)
    assert not out.ok and out.degraded and out.attempts == 3
