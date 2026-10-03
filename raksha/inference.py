"""The one interface every model call goes through.

This is the only module in RAKSHA permitted to perform network I/O, and the air-gap guard
(`raksha/airgap.py`, enforced by a test) proves nothing else does. That is what lets the same code
run against a cloud endpoint during development and a local vLLM server at the finale with zero code
change: only `RAKSHA_INFERENCE_BASE_URL` changes.

The air-gap claim is "no egress at runtime", not "no model". The model server is part of the sealed
deployment — vLLM on the same box, reachable on loopback — so calling it is not egress. In `sealed`
mode this module refuses any base URL that is not loopback / an allowlisted internal host, so a
misconfiguration cannot silently phone out.

The transport is stdlib `urllib` against the OpenAI-compatible `/chat/completions` route that vLLM
serves, so there is no third-party dependency to audit. If no endpoint is configured, `get_client()`
returns None and the pipeline runs model-free (template + retrieval lanes, then the mitigation
floor) — the degrade ladder, all the way down to zero model.
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

# Two roles, one transport. Defaults match the dossier's two-model split; override via env.
REPAIR = "repair"      # the 32B coding agent that writes patches and tests
ADVISOR = "advisor"    # the 8B security specialist that judges CWE / exploitability / depth

_DEFAULT_MODELS = {
    REPAIR: "qwen3-coder-next-32b",
    ADVISOR: "foundation-sec-8b-reasoning",
}


class InferenceError(RuntimeError):
    pass


def _is_local(host: str) -> bool:
    if host in ("localhost", "", "host.docker.internal"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_private
    except ValueError:
        # a bare service name (e.g. "vllm" in a compose network) is treated as internal
        return "." not in host


@dataclass(frozen=True)
class InferenceConfig:
    base_url: str | None
    api_key: str | None = None
    repair_model: str = _DEFAULT_MODELS[REPAIR]
    advisor_model: str = _DEFAULT_MODELS[ADVISOR]
    timeout: float = 120.0
    sealed: bool = True  # at the finale: refuse any non-local endpoint

    @classmethod
    def from_env(cls, env: dict | None = None) -> "InferenceConfig":
        env = env if env is not None else os.environ
        return cls(
            base_url=env.get("RAKSHA_INFERENCE_BASE_URL") or None,
            api_key=env.get("RAKSHA_INFERENCE_API_KEY") or None,
            repair_model=env.get("RAKSHA_REPAIR_MODEL", _DEFAULT_MODELS[REPAIR]),
            advisor_model=env.get("RAKSHA_ADVISOR_MODEL", _DEFAULT_MODELS[ADVISOR]),
            timeout=float(env.get("RAKSHA_INFERENCE_TIMEOUT", "120")),
            sealed=env.get("RAKSHA_SEALED", "1") != "0",
        )

    def model_for(self, role: str) -> str:
        return self.repair_model if role == REPAIR else self.advisor_model

    def validate(self) -> None:
        if not self.base_url:
            return
        host = urlparse(self.base_url).hostname or ""
        if self.sealed and not _is_local(host):
            raise InferenceError(
                f"sealed mode refuses a non-local inference endpoint: {self.base_url!r}. "
                "The model server must be on the sealed deployment (loopback / internal). "
                "Set RAKSHA_SEALED=0 only for development against a remote endpoint."
            )


class InferenceClient:
    """Minimal OpenAI-compatible chat client over stdlib urllib."""

    def __init__(self, config: InferenceConfig) -> None:
        config.validate()
        self.config = config

    def complete(self, messages: list[dict], *, role: str = REPAIR,
                 temperature: float = 0.2, max_tokens: int = 1024, n: int = 1) -> list[str]:
        """Return up to `n` candidate completions. Raises InferenceError on transport failure."""
        if not self.config.base_url:
            raise InferenceError("no inference endpoint configured")
        payload = json.dumps({
            "model": self.config.model_for(role),
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "n": n,
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:  # noqa: S310 (allowlisted module)
                data = json.loads(resp.read())
        except Exception as e:  # noqa: BLE001 — any transport error degrades the lane, never crashes the run
            raise InferenceError(f"inference call failed: {e}") from e
        return [c["message"]["content"] for c in data.get("choices", [])]


def get_client(config: InferenceConfig | None = None) -> InferenceClient | None:
    """The client, or None when no endpoint is configured so the pipeline runs model-free."""
    config = config or InferenceConfig.from_env()
    if not config.base_url:
        return None
    return InferenceClient(config)
