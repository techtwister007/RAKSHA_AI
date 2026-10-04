"""Phase 4: the air-gap guard, the inference interface, the sandbox, the bundle, the repair ladder.

Docker and a GPU are not needed for these: they test the contracts that make the sealed deployment
true — nothing touches the network outside inference.py, the model endpoint is refused unless local
in sealed mode, the sandbox never runs untrusted code unisolated, and the pipeline runs model-free.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from raksha import airgap
from raksha.finding import Finding, FixSite, Frame, RepairLane
from raksha.inference import InferenceConfig, InferenceError, get_client
from raksha.repair import ladder, llm_candidates, template_candidates
from raksha.sandbox import Sandbox, SandboxPolicy

REPO = Path(__file__).parents[1]


# ---------------------------------------------------------------- the air-gap guard

def test_no_network_imports_outside_inference():
    """The headline guarantee: only inference.py may touch the network."""
    violations = airgap.check_python()
    assert violations == [], "network-capable import outside inference.py:\n" + \
        "\n".join(f"{v.file}:{v.line} {v.text.strip()}" for v in violations)


def test_shipped_console_has_no_external_assets():
    # No console yet (Phase 5); when it exists this guards it. Scratch artifacts are not shipped.
    assert airgap.check_shipped_html([REPO / "console"]) == []


def test_airgap_guard_detects_a_planted_violation(tmp_path):
    (tmp_path / "bad.py").write_text("import requests\n")
    (tmp_path / "inference.py").write_text("import urllib.request\n")  # the allowlisted name, but
    # in a different dir it is not the real allowlisted path, so it is still flagged:
    violations = airgap.check_python(tmp_path)
    assert any(v.file.endswith("bad.py") for v in violations)


def test_airgap_runs_as_a_module():
    r = subprocess.run([sys.executable, "-m", "raksha.airgap"], cwd=REPO, capture_output=True)
    assert r.returncode == 0, r.stdout + r.stderr


# ---------------------------------------------------------------- inference interface

def test_no_endpoint_means_model_free():
    assert get_client(InferenceConfig(base_url=None)) is None


def test_sealed_mode_refuses_a_remote_endpoint():
    cfg = InferenceConfig(base_url="https://api.openai.com/v1", sealed=True)
    with pytest.raises(InferenceError, match="non-local"):
        get_client(cfg)


def test_sealed_mode_allows_loopback_and_internal():
    for url in ["http://127.0.0.1:8000/v1", "http://localhost:8000/v1", "http://vllm:8000/v1"]:
        assert get_client(InferenceConfig(base_url=url, sealed=True)) is not None


def test_dev_mode_allows_a_remote_endpoint():
    assert get_client(InferenceConfig(base_url="https://api.example.com/v1", sealed=False)) is not None


def test_config_from_env_roundtrip():
    cfg = InferenceConfig.from_env({"RAKSHA_INFERENCE_BASE_URL": "http://vllm:8000/v1",
                                    "RAKSHA_REPAIR_MODEL": "m32", "RAKSHA_SEALED": "1"})
    assert cfg.base_url == "http://vllm:8000/v1" and cfg.repair_model == "m32" and cfg.sealed
    assert cfg.model_for("repair") == "m32"


# ---------------------------------------------------------------- the repair ladder

def _finding():
    f = Finding(oracle="x", bug_class="CWE-917", language="java", target="svc", message="m",
                frames=[Frame(symbol="A.b", uri="A.java", line=1)])
    f.add_fix_site(FixSite(uri="A.java", rank=0, start_line=1))
    return f


def test_template_lane_is_zero_inference():
    tmpl = lambda f: "--- a/x\n+++ b/x\n"
    cands = template_candidates(_finding(), [tmpl])
    assert len(cands) == 1 and cands[0].lane is RepairLane.TEMPLATE


def test_llm_lane_yields_nothing_without_an_endpoint():
    # the degrade path: model-free box -> no LLM candidates, ladder still works
    assert llm_candidates(_finding(), client=None) == []


def test_ladder_runs_model_free_in_cost_order():
    tmpl = lambda f: "--- a/x\n+++ b/x\n(template)\n"
    floor = lambda f: "--- a/x\n+++ b/x\n(mitigation)\n"
    cands = ladder(_finding(), templates=[tmpl], client=None, floors=[floor])
    assert [c.lane for c in cands] == [RepairLane.TEMPLATE, RepairLane.MITIGATION]


def test_llm_lane_parses_a_fenced_diff():
    from raksha.repair import _extract_diff
    assert _extract_diff("here:\n```diff\n--- a/x\n+++ b/x\n@@\n-bad\n+good\n```") is not None
    assert _extract_diff("no diff here") is None


# ---------------------------------------------------------------- the sandbox

def test_sandbox_wraps_with_no_network():
    argv = Sandbox().wrap("mvn test", mount="/host/target")
    joined = " ".join(argv)
    assert "--network=none" in joined
    assert "--cap-drop=ALL" in joined
    assert "--read-only" in joined             # the image root is immutable
    assert "/host/target:/work:rw" in joined   # the per-build scratch copy is writable (builds write)
    assert "seccomp=default" not in joined     # not a docker keyword; the default profile is implicit
    assert argv[0] == "docker" and "mvn test" in argv[-1]


def test_untrusted_runs_are_counted_and_unsandboxed_runs_are_visible(monkeypatch, tmp_path):
    from raksha import sandbox
    monkeypatch.delenv("RAKSHA_SANDBOX_IMAGE", raising=False)
    monkeypatch.delenv("RAKSHA_REQUIRE_SANDBOX", raising=False)
    before = sandbox.execution_counts()["unsandboxed_runs"]
    code, out, _, _ = sandbox.run_untrusted("echo hi", str(tmp_path))
    assert code == 0 and out.strip() == b"hi"
    assert sandbox.execution_counts()["unsandboxed_runs"] == before + 1


def test_required_sandbox_refuses_to_run_unsandboxed(monkeypatch, tmp_path):
    from raksha import sandbox
    monkeypatch.delenv("RAKSHA_SANDBOX_IMAGE", raising=False)
    monkeypatch.setenv("RAKSHA_REQUIRE_SANDBOX", "1")
    code, _, err, _ = sandbox.run_untrusted("touch ran", str(tmp_path))
    assert code == 126 and b"SANDBOX REQUIRED" in err and not (tmp_path / "ran").exists()


def test_provisioned_sandbox_remaps_paths_into_the_jail(monkeypatch, tmp_path):
    from raksha import sandbox
    box = sandbox.Sandbox.from_env({"RAKSHA_SANDBOX_IMAGE": "raksha-tools:1"})
    argv = box.wrap(f"./harness {tmp_path}/in".replace(str(tmp_path), "/work"), mount=str(tmp_path))
    assert "raksha-tools:1" in argv and argv[-1].endswith("./harness /work/in")


def test_network_interfaces_badge_is_zero():
    assert Sandbox().network_interfaces_claim() == 0
    assert Sandbox(SandboxPolicy(network="bridge")).network_interfaces_claim() == -1


def test_sandbox_refuses_to_run_unisolated_when_runtime_absent():
    s = Sandbox(SandboxPolicy(runtime="definitely-not-a-real-runtime"))
    code, out = s.run("echo hi")
    assert code == 127 and "refusing to run" in out


def test_gvisor_flag():
    argv = Sandbox(SandboxPolicy(runsc=True)).wrap("x")
    assert "--runtime=runsc" in " ".join(argv)


# ---------------------------------------------------------------- the offline bundle

def test_bundle_build_and_verify_roundtrip(tmp_path):
    sys.path.insert(0, str(REPO / "deploy"))
    import bundle_manifest as bm

    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(b"\x00\x01\x02")
    bm.build(tmp_path)
    assert bm.verify(tmp_path) == []           # intact

    (tmp_path / "a.txt").write_text("tampered")
    assert any("CHANGED a.txt" in p for p in bm.verify(tmp_path))

    (tmp_path / "a.txt").unlink()
    (tmp_path / "a.txt").write_text("alpha")   # restore content -> back to intact for a.txt
    (tmp_path / "c.new").write_text("surprise")
    assert any("UNEXPECTED c.new" in p for p in bm.verify(tmp_path))


def test_bundle_verify_fails_without_manifest(tmp_path):
    sys.path.insert(0, str(REPO / "deploy"))
    import bundle_manifest as bm
    assert bm.verify(tmp_path) == ["missing manifest.json"]


def test_deploy_artifacts_exist():
    d = REPO / "deploy"
    for name in ["Dockerfile", "docker-compose.gpu.yml", "docker-compose.cpu.yml",
                 "install.sh", "bundle_manifest.py"]:
        assert (d / name).exists(), name
    # the sealed network must be internal in both compose profiles
    for prof in ["gpu", "cpu"]:
        assert "internal: true" in (d / f"docker-compose.{prof}.yml").read_text()
