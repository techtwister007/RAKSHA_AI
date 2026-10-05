"""Choose the model provider and model, and change them at any time.

Every provider RAKSHA supports speaks the OpenAI-compatible `/chat/completions` API, so switching
provider changes only three things: the base URL, the API key (for hosted services) and the model
name. This module keeps that choice in `~/.raksha/provider.json` (`RAKSHA_HOME` moves it), and
`inference.InferenceConfig.from_env` reads it when no `RAKSHA_INFERENCE_*` variables are set.
Environment variables always win, so a deployment (the sealed compose files) is never overridden
by a file left on the box.

    python -m raksha.provider                     # interactive: pick provider, URL, model, key
    python -m raksha.provider list                # the presets
    python -m raksha.provider set lmstudio --model qwen2.5-coder-7b-instruct
    python -m raksha.provider set openai --model gpt-4.1 --key sk-...
    python -m raksha.provider set custom --url http://10.0.0.5:8000/v1 --model my-model
    python -m raksha.provider model qwen3-coder:30b   # change only the model, same provider
    python -m raksha.provider show | models | test | off

API keys go to `~/.raksha/keys.json` (mode 0600), never to the repository, or are read from the
environment variable named by the preset (OPENAI_API_KEY, DEEPSEEK_API_KEY, ...). A hosted
provider sends the prompt, which contains the source being fixed, off this machine: choosing one
turns sealed mode off in the saved settings and says so; the CLOUD badge counts every such call.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Preset:
    name: str
    label: str
    base_url: str
    key_env: str | None = None      # env var holding the API key (hosted services)
    local: bool = True              # runs on this machine / LAN: no source leaves it
    example_model: str = ""
    note: str = ""


PRESETS: dict[str, Preset] = {p.name: p for p in [
    Preset("ollama", "Ollama", "http://127.0.0.1:11434/v1", example_model="qwen2.5-coder:7b",
           note="`…-cloud` models are hosted by ollama.com: counted as cloud calls"),
    Preset("lmstudio", "LM Studio", "http://127.0.0.1:1234/v1", example_model="qwen2.5-coder-7b-instruct",
           note="start the server in LM Studio (Developer tab)"),
    Preset("vllm", "vLLM", "http://127.0.0.1:8000/v1", example_model="Qwen/Qwen2.5-Coder-32B-Instruct",
           note="the finale configuration"),
    Preset("llamacpp", "llama.cpp server", "http://127.0.0.1:8081/v1", example_model="local",
           note="run llama-server --port 8081 (8080 is the RAKSHA console)"),
    Preset("openai", "OpenAI", "https://api.openai.com/v1", key_env="OPENAI_API_KEY", local=False,
           example_model="gpt-4.1"),
    Preset("deepseek", "DeepSeek", "https://api.deepseek.com/v1", key_env="DEEPSEEK_API_KEY", local=False,
           example_model="deepseek-chat"),
    Preset("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", key_env="OPENROUTER_API_KEY",
           local=False, example_model="qwen/qwen-2.5-coder-32b-instruct"),
    Preset("groq", "Groq", "https://api.groq.com/openai/v1", key_env="GROQ_API_KEY", local=False,
           example_model="llama-3.3-70b-versatile"),
    Preset("mistral", "Mistral", "https://api.mistral.ai/v1", key_env="MISTRAL_API_KEY", local=False,
           example_model="codestral-latest"),
    Preset("custom", "Any OpenAI-compatible server", "", key_env="RAKSHA_INFERENCE_API_KEY",
           example_model=""),
]}


def _home() -> Path:
    return Path(os.environ.get("RAKSHA_HOME") or Path.home() / ".raksha")


def settings_path() -> Path:
    return _home() / "provider.json"


def keys_path() -> Path:
    return _home() / "keys.json"


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _write_private(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def saved() -> dict:
    """The saved choice, or {} when none (the pipeline then runs model-free)."""
    return _read(settings_path())


def _key_for(s: dict) -> str | None:
    env = s.get("key_env")
    if env and os.environ.get(env):
        return os.environ[env]
    return _read(keys_path()).get(env or s.get("provider", "")) or None


def _wsl_gateway() -> str | None:
    """The Windows host as seen from WSL2 (NAT mode), read from the routing table — no network."""
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 2 and f[1] == "00000000":
                g = int(f[2], 16)
                return ".".join(str((g >> s) & 255) for s in (0, 8, 16, 24))
    except (OSError, ValueError):
        pass
    return None


_RESOLVED: dict[tuple, str] = {}


def _resolve_local(url: str, timeout: float = 1.5) -> str:
    """A model server on Windows (Ollama, LM Studio) is reached from WSL at 127.0.0.1 with mirrored
    networking, else at the Windows host. Probe once per process and keep the one that answers."""
    if "127.0.0.1" not in url and "localhost" not in url:
        return url
    gw = _wsl_gateway()
    key = (url, gw)
    if key in _RESOLVED:
        return _RESOLVED[key]
    from .inference import InferenceConfig, model_server_alive
    chosen = url
    if gw and not model_server_alive(InferenceConfig(base_url=url), timeout=timeout):
        alt = url.replace("127.0.0.1", gw).replace("localhost", gw)
        if model_server_alive(InferenceConfig(base_url=alt), timeout=timeout):
            chosen = alt
    _RESOLVED[key] = chosen
    return chosen


def env_settings() -> dict[str, str]:
    """The saved choice as RAKSHA_* settings (what `InferenceConfig.from_env` consumes)."""
    s = saved()
    if not s.get("base_url") or not s.get("model"):
        return {}
    out = {"RAKSHA_INFERENCE_BASE_URL": _resolve_local(s["base_url"]) if s.get("local", True) else s["base_url"],
           "RAKSHA_REPAIR_MODEL": s["model"],
           "RAKSHA_ADVISOR_MODEL": s.get("advisor_model") or s["model"],
           "RAKSHA_INFERENCE_TIMEOUT": str(s.get("timeout", 300))}
    key = _key_for(s)
    if key:
        out["RAKSHA_INFERENCE_API_KEY"] = key
    if "sealed" in s:
        out["RAKSHA_SEALED"] = "1" if s["sealed"] else "0"
    return out


def choose(provider: str, *, model: str, url: str | None = None, key: str | None = None,
           advisor_model: str | None = None, timeout: int = 300) -> dict:
    """Save a provider + model. Returns the saved settings (without the key)."""
    if provider not in PRESETS:
        raise ValueError(f"unknown provider {provider!r}; one of: {', '.join(PRESETS)}")
    p = PRESETS[provider]
    base = (url or p.base_url).rstrip("/")
    if not base:
        raise ValueError("this provider needs --url (the server's OpenAI-compatible /v1 address)")
    if not model:
        raise ValueError("a model name is required")
    from .inference import _is_local, _offbox_model
    from urllib.parse import urlparse
    local = _is_local(urlparse(base).hostname or "") and not _offbox_model(model)
    s = {"provider": provider, "base_url": base, "model": model, "timeout": timeout,
         "local": local, "key_env": p.key_env or "RAKSHA_INFERENCE_API_KEY",
         # a hosted provider is a deliberate choice to send prompts out; record it as such
         "sealed": local}
    if advisor_model:
        s["advisor_model"] = advisor_model
    _write_private(settings_path(), s)
    if key:
        keys = _read(keys_path())
        keys[s["key_env"]] = key
        _write_private(keys_path(), keys)
    _RESOLVED.clear()
    return s


def off() -> None:
    """Forget the saved choice: the pipeline runs model-free (templates, fix memory, mitigation)."""
    try:
        settings_path().unlink()
    except FileNotFoundError:
        pass
    _RESOLVED.clear()


def describe() -> str:
    s = saved()
    if not s:
        return "model: none (model-free: templates, fix memory and the mitigation floor)"
    where = "this machine / LAN" if s.get("local") else "HOSTED — prompts and the source in them leave this machine"
    key = "set" if _key_for(s) else "not set"
    lines = [f"provider: {PRESETS.get(s['provider'], Preset(s['provider'], s['provider'], '')).label}",
             f"url:      {s['base_url']}", f"model:    {s['model']}"]
    if s.get("advisor_model"):
        lines.append(f"advisor:  {s['advisor_model']}")
    lines += [f"api key:  {key} ({s.get('key_env')})", f"where:    {where}",
              f"sealed:   {'on' if s.get('sealed') else 'off'}"]
    if os.environ.get("RAKSHA_INFERENCE_BASE_URL"):
        lines.append("note:     RAKSHA_INFERENCE_BASE_URL is set in this shell and overrides the saved choice")
    return "\n".join(lines)


# ---- CLI -----------------------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    got = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return got or default


def _wizard() -> int:
    names = list(PRESETS)
    print("Model provider for RAKSHA (every one speaks the OpenAI-compatible API):")
    for i, n in enumerate(names, 1):
        p = PRESETS[n]
        print(f"  {i:2}. {p.label:<32} {'local' if p.local else 'hosted'}  {p.note}")
    print("   0. none (run model-free)")
    pick = _ask("Choose", "1")
    if pick == "0":
        off(); print(describe()); return 0
    try:
        p = PRESETS[names[int(pick) - 1]] if pick.isdigit() else PRESETS[pick]
    except (IndexError, KeyError):
        print("not a choice"); return 2
    url = _ask("Server URL", p.base_url)
    key = None
    if not p.local or p.name == "custom":
        if p.key_env and os.environ.get(p.key_env):
            print(f"Using the API key from ${p.key_env}.")
        else:
            key = getpass.getpass(f"API key for {p.label} (input hidden; empty for none): ").strip() or None
    from .inference import InferenceConfig, list_models
    models = list_models(InferenceConfig(base_url=url, api_key=key or os.environ.get(p.key_env or ""), sealed=False))
    if models:
        print("Models this server offers:", ", ".join(models[:30]) + (" …" if len(models) > 30 else ""))
    model = _ask("Model", models[0] if models else p.example_model)
    s = choose(p.name, model=model, url=url, key=key)
    print("\nSaved.\n" + describe())
    if not s["local"]:
        print("\nWARNING: this provider receives the prompts, including the source code being fixed. "
              "Use it only on code you may send out; never at the finale (sealed mode refuses it).")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m raksha.provider", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="the provider presets")
    st = sub.add_parser("set", help="save a provider and model")
    st.add_argument("provider", choices=list(PRESETS))
    st.add_argument("--model", required=True)
    st.add_argument("--url", help="override the preset URL (another host or port)")
    st.add_argument("--key", help="API key; stored in ~/.raksha/keys.json, mode 0600")
    st.add_argument("--advisor-model", help="a second, smaller model for judging (default: same model)")
    st.add_argument("--timeout", type=int, default=300)
    md = sub.add_parser("model", help="change only the model (keeps provider, URL and key)")
    md.add_argument("name")
    sub.add_parser("show", help="the current choice")
    sub.add_parser("models", help="models the configured server offers")
    sub.add_parser("test", help="one tiny request to the configured model")
    sub.add_parser("off", help="forget the choice: run model-free")
    a = ap.parse_args(argv)

    if a.cmd is None:
        return _wizard()
    if a.cmd == "list":
        for p in PRESETS.values():
            print(f"{p.name:<11} {p.label:<30} {p.base_url or '(give --url)':<38} "
                  f"{'local' if p.local else 'hosted, key: $' + str(p.key_env)}  e.g. {p.example_model}")
        return 0
    if a.cmd == "set":
        try:
            s = choose(a.provider, model=a.model, url=a.url, key=a.key, advisor_model=a.advisor_model,
                       timeout=a.timeout)
        except ValueError as e:
            print(e); return 2
        print(describe())
        if not s["local"]:
            print("WARNING: hosted provider — prompts (with the source being fixed) leave this machine.")
        return 0
    if a.cmd == "off":
        off(); print(describe()); return 0
    if a.cmd == "model":
        cur = saved()
        try:
            choose(cur.get("provider", "ollama"), model=a.name, url=cur.get("base_url"),
                   advisor_model=cur.get("advisor_model"), timeout=cur.get("timeout", 300))
        except ValueError as e:
            print(e); return 2
        print(describe()); return 0
    if a.cmd == "show":
        print(describe()); return 0
    from .inference import InferenceConfig, InferenceError, get_client, list_models
    cfg = InferenceConfig.from_env()
    if not cfg.base_url:
        print("no provider configured — run: python -m raksha.provider"); return 1
    if a.cmd == "models":
        got = list_models(cfg)
        print("\n".join(got) if got else "(the server did not list models)"); return 0 if got else 1
    try:                                              # test
        out = get_client(cfg).complete([{"role": "user", "content": "Reply with the single word: ready"}],
                                       max_tokens=8, temperature=0)
    except InferenceError as e:
        print(f"FAILED: {e}"); return 1
    print(f"OK — {cfg.repair_model} at {cfg.base_url} replied: {(out[0] if out else '').strip()[:60]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
