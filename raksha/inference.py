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

# Roles, one transport. The dossier's two-model split (repair + advisor) is the floor; the other
# roles default to one of those two models and are overridden per role via env, so a deployment
# with a third weight (a small fast decision model, an independent attacker) plugs it in by name.
REPAIR = "repair"      # the 32B coding agent that writes patches and tests
ADVISOR = "advisor"    # the 8B security specialist that judges CWE / exploitability / depth
TRIAGE = "triage"      # fast structured decisions: is this site worth deeper work? (score only)
RED = "red"            # the independent attacker that tries to defeat a verified patch
JUDGE = "judge"        # a second opinion for the parliament; never decides, only votes

_DEFAULT_MODELS = {
    REPAIR: "qwen3-coder-next-32b",
    ADVISOR: "foundation-sec-8b-reasoning",
}
_ROLE_ENV = {REPAIR: "RAKSHA_REPAIR_MODEL", ADVISOR: "RAKSHA_ADVISOR_MODEL",
             TRIAGE: "RAKSHA_TRIAGE_MODEL", RED: "RAKSHA_RED_MODEL", JUDGE: "RAKSHA_JUDGE_MODEL"}


class InferenceError(RuntimeError):
    pass


# ---- live counters, so the posture badge and the token metric are measured, not asserted ----
# Every actual call increments these. An egress call (one to a non-loopback host) would make
# `cloud_calls` non-zero on the Scorecard — which is how the air-gap badge detects a breach
# instead of merely claiming zero. In sealed mode `validate()` refuses non-local endpoints, so
# the egress counter stays 0 by construction; if it ever isn't, the badge shows it.
_INFERENCE_CALLS = 0
_EGRESS_CALLS = 0
_COMPLETION_TOKENS = 0


def inference_call_count() -> int:
    return _INFERENCE_CALLS


def egress_call_count() -> int:
    """Calls that left the box (non-loopback host). The cloud-calls badge reads this."""
    return _EGRESS_CALLS


def completion_tokens_used() -> int:
    """Total model completion tokens spent this run. Feeds tokens-per-validated-patch."""
    return _COMPLETION_TOKENS


def counters() -> dict[str, int]:
    """A snapshot of the live counters. A session records one at start and reports the difference,
    so two sessions in one process (or a test) never see each other's calls or tokens."""
    return {"inference_calls": _INFERENCE_CALLS, "egress_calls": _EGRESS_CALLS,
            "completion_tokens": _COMPLETION_TOKENS}


def reset_counters() -> None:
    """Zero the live counters (used by tests and at the start of a fresh run)."""
    global _INFERENCE_CALLS, _EGRESS_CALLS, _COMPLETION_TOKENS
    _INFERENCE_CALLS = _EGRESS_CALLS = _COMPLETION_TOKENS = 0


def _is_loopback(host: str) -> bool:
    """A loopback / same-box host. The model server at the finale is here (not egress)."""
    if host in ("localhost", "", "host.docker.internal"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # a bare service name (e.g. "vllm" in a compose network) is same-network, not egress
        return "." not in host


def _is_local(host: str, allowlist: tuple[str, ...] = ()) -> bool:
    """Whether a host is inside the sealed deployment (and so not egress).

    Loopback / dotless service names always. Private-range (RFC-1918) addresses and hosts the
    operator explicitly allowlisted (RAKSHA_INFERENCE_ALLOWLIST) too — a sealed deployment may serve
    the model on an internal host. Everything else (any public host) is outside. Sealed mode refuses
    to talk to an outside host, and the egress counter counts calls to one, so the two agree: a
    legitimate internal model server never shows up as a cloud call.
    """
    if _is_loopback(host) or host in allowlist:
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _offbox_model(model: str) -> bool:
    """A model served from someone else's machine even though the endpoint is local. Ollama's cloud
    models (`gpt-oss:120b-cloud`, `qwen3-coder:480b-cloud`, `…:cloud`) are reached through the local
    Ollama at 127.0.0.1:11434, which forwards the prompt (and the target's source in it) to
    ollama.com. Judged by host alone they would look local; they are egress."""
    m = (model or "").strip().lower()
    return m.endswith("-cloud") or m.endswith(":cloud") or "-cloud:" in m


@dataclass(frozen=True)
class InferenceConfig:
    base_url: str | None
    api_key: str | None = None
    repair_model: str = _DEFAULT_MODELS[REPAIR]
    advisor_model: str = _DEFAULT_MODELS[ADVISOR]
    timeout: float = 120.0
    sealed: bool = True  # at the finale: refuse any non-local endpoint
    allowlist: tuple[str, ...] = ()  # named internal model hosts (RAKSHA_INFERENCE_ALLOWLIST)
    #: Per-role model overrides for the extra roles (triage / red / judge). Unset roles fall back:
    #: triage → advisor (small, fast); red → repair (it must write inputs); judge → advisor.
    role_models: tuple[tuple[str, str], ...] = ()
    #: G2: guided-decoding request style the endpoint supports: json_schema | vllm | off.
    guided: str = "off"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "InferenceConfig":
        if env is None:
            env = os.environ
            if not env.get("RAKSHA_INFERENCE_BASE_URL") and env.get("RAKSHA_PROVIDER", "") != "off":
                # no endpoint in the environment: use the provider saved with `python -m raksha.provider`
                # (environment variables still win one by one, e.g. RAKSHA_SEALED=1 on the sealed node;
                # RAKSHA_PROVIDER=off ignores the saved choice for one command)
                from .provider import env_settings
                env = {**env_settings(), **env}
        return cls(
            base_url=env.get("RAKSHA_INFERENCE_BASE_URL") or None,
            api_key=env.get("RAKSHA_INFERENCE_API_KEY") or None,
            repair_model=env.get("RAKSHA_REPAIR_MODEL", _DEFAULT_MODELS[REPAIR]),
            advisor_model=env.get("RAKSHA_ADVISOR_MODEL", _DEFAULT_MODELS[ADVISOR]),
            timeout=float(env.get("RAKSHA_INFERENCE_TIMEOUT", "120")),
            sealed=env.get("RAKSHA_SEALED", "1") != "0",
            allowlist=tuple(h.strip() for h in env.get("RAKSHA_INFERENCE_ALLOWLIST", "").split(",") if h.strip()),
            role_models=tuple((r, env[v]) for r, v in _ROLE_ENV.items()
                              if r not in (REPAIR, ADVISOR) and env.get(v)),
            guided=_guided_style(env),
        )

    def model_for(self, role: str) -> str:
        over = dict(self.role_models)
        if role in over:
            return over[role]
        if role in (REPAIR, RED):
            return self.repair_model
        return self.advisor_model

    def validate(self) -> None:
        if not self.base_url:
            return
        host = urlparse(self.base_url).hostname or ""
        if self.sealed and not _is_local(host, self.allowlist):
            raise InferenceError(
                f"sealed mode refuses a non-local inference endpoint: {self.base_url!r}. "
                "The model server must be on the sealed deployment (loopback / internal). "
                "Set RAKSHA_SEALED=0 only for development against a remote endpoint."
            )
        cloud = sorted({m for m in (self.repair_model, self.advisor_model, *dict(self.role_models).values())
                        if _offbox_model(m)})
        if self.sealed and cloud:
            raise InferenceError(
                f"sealed mode refuses cloud-hosted models behind a local endpoint: {', '.join(cloud)}. "
                "The local server forwards the prompt, and the source in it, off this machine. "
                "Set RAKSHA_SEALED=0 only for development on code you may send out."
            )


def _guided_style(env) -> str:
    from .guided import style
    return style(env)


class InferenceClient:
    """Minimal OpenAI-compatible chat client over stdlib urllib."""

    def __init__(self, config: InferenceConfig) -> None:
        config.validate()
        self.config = config

    def complete(self, messages: list[dict], *, role: str = REPAIR,
                 temperature: float = 0.2, max_tokens: int = 1024, n: int = 1,
                 extra: dict | None = None) -> list[str]:
        """Return up to `n` candidate completions. Raises InferenceError on transport failure."""
        if not self.config.base_url:
            raise InferenceError("no inference endpoint configured")
        payload = json.dumps({
            "model": self.config.model_for(role),
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "n": n,
            **(extra or {}),          # G2: guided-decoding fields, when the endpoint supports them
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        # Count the call before making it, and flag it as egress if the host is not same-box.
        # This is what turns the cloud-calls badge into a measurement.
        global _INFERENCE_CALLS, _EGRESS_CALLS, _COMPLETION_TOKENS
        host = urlparse(self.config.base_url).hostname or ""
        _INFERENCE_CALLS += 1
        if not _is_local(host, self.config.allowlist) or _offbox_model(self.config.model_for(role)):
            _EGRESS_CALLS += 1
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:  # noqa: S310 (allowlisted module)
                data = json.loads(resp.read())
        except Exception as e:  # noqa: BLE001 — any transport error degrades the lane, never crashes the run
            raise InferenceError(f"inference call failed: {e}") from e
        usage = data.get("usage") or {}
        try:
            _COMPLETION_TOKENS += int(usage.get("completion_tokens", 0) or 0)
        except (TypeError, ValueError):
            pass
        return [c["message"]["content"] for c in data.get("choices", [])]


    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        """G3: vectors from a local embedding model (`/embeddings`). Raises InferenceError."""
        if not self.config.base_url:
            raise InferenceError("no inference endpoint configured")
        global _INFERENCE_CALLS, _EGRESS_CALLS
        host = urlparse(self.config.base_url).hostname or ""
        _INFERENCE_CALLS += 1
        if not _is_local(host, self.config.allowlist) or _offbox_model(model):
            _EGRESS_CALLS += 1
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        req = urllib.request.Request(self.config.base_url.rstrip("/") + "/embeddings",
                                     data=json.dumps({"model": model, "input": texts}).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:  # noqa: S310
                data = json.loads(resp.read())
        except Exception as e:  # noqa: BLE001
            raise InferenceError(f"embedding call failed: {e}") from e
        return [d["embedding"] for d in sorted(data.get("data", []), key=lambda d: d.get("index", 0))]

def model_server_alive(config: InferenceConfig | None = None, timeout: float = 3.0) -> bool | None:
    """Liveness of the configured model server (GET /models), or None when none is configured —
    a model-free run has no server to be dead. Lives here because this is the only module allowed
    to touch the network."""
    config = config or InferenceConfig.from_env()
    if not config.base_url:
        return None
    try:
        config.validate()
        url = config.base_url.rstrip("/") + "/models"
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (allowlisted module)
            return 200 <= resp.status < 300
    except Exception:  # noqa: BLE001 — any failure is "not alive"
        return False


def list_models(config: InferenceConfig | None = None, timeout: float = 10.0) -> list[str]:
    """Model ids the configured server offers (GET /models), [] when it cannot say. Sends the API
    key when there is one (hosted providers require it). Does not count as an inference call."""
    config = config or InferenceConfig.from_env()
    if not config.base_url:
        return []
    try:
        config.validate()
        req = urllib.request.Request(config.base_url.rstrip("/") + "/models",
                                     headers={"Authorization": f"Bearer {config.api_key}"} if config.api_key else {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (allowlisted module)
            data = json.loads(resp.read())
    except Exception:  # noqa: BLE001 — "cannot list" is an answer, not a crash
        return []
    items = data.get("data", data.get("models", [])) if isinstance(data, dict) else []
    return sorted({(m.get("id") or m.get("name")) for m in items if isinstance(m, dict) and (m.get("id") or m.get("name"))})


def get_client(config: InferenceConfig | None = None) -> InferenceClient | None:
    """The client, or None when no endpoint is configured so the pipeline runs model-free."""
    config = config or InferenceConfig.from_env()
    if not config.base_url:
        return None
    return InferenceClient(config)
