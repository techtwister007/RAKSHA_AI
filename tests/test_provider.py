"""The model provider is a saved choice the operator changes at will; env vars always win."""

from __future__ import annotations

import io
import json
import os
import stat

import pytest

from raksha import inference, provider
from raksha.inference import InferenceConfig, InferenceError, get_client


def test_no_choice_means_model_free():
    assert provider.saved() == {} and get_client() is None
    assert "model-free" in provider.describe()


def test_local_provider_is_used_and_stays_sealed(monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: None)
    provider.choose("lmstudio", model="qwen2.5-coder-7b-instruct")
    cfg = InferenceConfig.from_env()
    assert cfg.base_url == "http://127.0.0.1:1234/v1" and cfg.repair_model == "qwen2.5-coder-7b-instruct"
    assert cfg.advisor_model == "qwen2.5-coder-7b-instruct" and cfg.sealed
    provider.choose("vllm", model="Qwen/Qwen2.5-Coder-32B-Instruct", advisor_model="small")
    cfg = InferenceConfig.from_env()
    assert cfg.base_url.endswith(":8000/v1") and cfg.advisor_model == "small"


def test_environment_wins_over_the_saved_choice(monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: None)
    provider.choose("ollama", model="qwen2.5-coder:7b")
    monkeypatch.setenv("RAKSHA_REPAIR_MODEL", "other")
    assert InferenceConfig.from_env().repair_model == "other"
    monkeypatch.setenv("RAKSHA_INFERENCE_BASE_URL", "http://vllm:8000/v1")
    cfg = InferenceConfig.from_env()
    assert cfg.base_url == "http://vllm:8000/v1"


def test_hosted_provider_key_is_private_and_sealed_mode_still_refuses(monkeypatch):
    s = provider.choose("openai", model="gpt-4.1", key="sk-test")
    assert s["local"] is False and s["sealed"] is False and "sk-test" not in json.dumps(s)
    mode = stat.S_IMODE(os.stat(provider.keys_path()).st_mode)
    assert mode == 0o600
    cfg = InferenceConfig.from_env()
    assert cfg.api_key == "sk-test" and not cfg.sealed and get_client(cfg) is not None
    assert "HOSTED" in provider.describe()
    monkeypatch.setenv("RAKSHA_SEALED", "1")            # the sealed node sets this; it always wins
    with pytest.raises(InferenceError, match="non-local"):
        get_client()


def test_key_from_the_presets_environment_variable(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-env")
    provider.choose("deepseek", model="deepseek-chat")
    assert InferenceConfig.from_env().api_key == "ds-env"


def test_ollama_cloud_model_is_recorded_as_hosted():
    s = provider.choose("ollama", model="gpt-oss:120b-cloud")
    assert s["local"] is False and s["sealed"] is False


def test_bad_choices_are_refused():
    with pytest.raises(ValueError, match="--url"):
        provider.choose("custom", model="m")
    with pytest.raises(ValueError, match="unknown provider"):
        provider.choose("nope", model="m")
    with pytest.raises(ValueError, match="model"):
        provider.choose("ollama", model="")


def test_off_returns_to_model_free(monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: None)
    provider.choose("ollama", model="qwen2.5-coder:7b")
    provider.off()
    assert get_client() is None


def test_server_on_windows_is_found_from_wsl(monkeypatch):
    """With WSL in NAT mode, 127.0.0.1 is WSL itself; the Windows host is the default gateway."""
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: "172.20.0.1")
    monkeypatch.setattr(inference, "model_server_alive", lambda cfg, timeout=3.0: "172.20.0.1" in cfg.base_url)
    provider.choose("ollama", model="qwen2.5-coder:7b")
    assert InferenceConfig.from_env().base_url == "http://172.20.0.1:11434/v1"


def test_list_models_sends_the_key_and_reads_both_shapes(monkeypatch):
    seen = {}

    def fake(req, timeout=0):
        seen["auth"] = req.get_header("Authorization")
        return io.BytesIO(json.dumps({"data": [{"id": "b"}, {"id": "a"}]}).encode())
    monkeypatch.setattr(inference.urllib.request, "urlopen", fake)
    cfg = InferenceConfig(base_url="https://api.example.com/v1", api_key="k", sealed=False)
    assert inference.list_models(cfg) == ["a", "b"] and seen["auth"] == "Bearer k"
    monkeypatch.setattr(inference.urllib.request, "urlopen",
                        lambda req, timeout=0: io.BytesIO(b'{"models": [{"name": "qwen2.5-coder:7b"}]}'))
    assert inference.list_models(cfg) == ["qwen2.5-coder:7b"]


def test_cli_set_show_off(capsys, monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: None)
    assert provider.main(["set", "deepseek", "--model", "deepseek-chat", "--key", "x"]) == 0
    out = capsys.readouterr().out
    assert "DeepSeek" in out and "WARNING" in out and "x" not in out.split("api key:")[1].split("\n")[0]
    assert provider.main(["off"]) == 0 and provider.saved() == {}


def test_cli_model_changes_only_the_model(monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: None)
    provider.choose("lmstudio", model="a", url="http://127.0.0.1:4321/v1")
    assert provider.main(["model", "b"]) == 0
    s = provider.saved()
    assert s["provider"] == "lmstudio" and s["base_url"] == "http://127.0.0.1:4321/v1" and s["model"] == "b"


def test_provider_off_for_one_command(monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: None)
    provider.choose("ollama", model="qwen2.5-coder:7b")
    monkeypatch.setenv("RAKSHA_PROVIDER", "off")
    assert get_client() is None


def test_failed_test_call_explains_what_to_do(monkeypatch):
    monkeypatch.setattr(provider, "_wsl_gateway", lambda: "172.20.0.1")
    assert "Firewall" in provider._failure_hint("http://172.20.0.1:11434/v1", "connection refused")
    assert "--key" in provider._failure_hint("https://api.openai.com/v1", "HTTP Error 401: Unauthorized")
