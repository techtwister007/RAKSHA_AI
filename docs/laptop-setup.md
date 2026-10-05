# Running RAKSHA AI on your laptop

Written for: a Windows laptop with **no GPU**, little space on C:, room on **D: or E:**, and
**Ollama** installed (local or cloud models). Any other OpenAI-compatible provider works too (§2). Linux and macOS instructions are at the end.

## 1. One click (Windows)

1. Download **`deploy/windows/RAKSHA-Setup.bat`** from the repository (on GitHub, open the file
   and click *Download raw file*), or from a clone.
2. Double-click it.
3. At the end, pick a model provider and model from the menu (Ollama, LM Studio, vLLM, OpenAI,
   DeepSeek, …), or 0 for model-free. Examples for Ollama: `gpt-oss:120b-cloud`,
   `qwen3-coder:480b-cloud`, or a local `qwen2.5-coder:7b`. Leave it empty to run model-free.

What it does, in order:

| Step | What happens | Where it goes |
|---|---|---|
| 1 | picks D: or E:, whichever has more space (`-Drive E` overrides) | `<drive>:\RAKSHA` |
| 2 | checks WSL2. If missing, asks for Administrator once, enables it, and asks you to **restart and double-click again** | Windows feature |
| 3 | downloads Ubuntu 24.04 (~350 MB) and creates a private Linux system called **RAKSHA** | its disk: `<drive>:\RAKSHA\wsl\ext4.vhdx` |
| 4 | Windows 11: turns on WSL *mirrored networking* so Linux reaches Ollama at `127.0.0.1:11434`. Windows 10: sets `OLLAMA_HOST=0.0.0.0:11434` (restart Ollama once) | `%USERPROFILE%\.wslconfig` |
| 5 | points Ollama's local model folder to the big drive, in case you ever pull a local model | `OLLAMA_MODELS=<drive>:\RAKSHA\ollama-models` |
| 6 | inside Linux: gcc, Python 3.12, JDK 17 + Maven, Go 1.22, cargo, Node; semgrep, checkov, gitleaks, osv-scanner (with its offline database), opa, cosign, z3; clones the repo; creates the virtualenv | all inside the vhdx on D:/E: |
| 7 | runs the checks: air-gap guard, model-lane check, find → fix → prove slice, full test suite | — |
| 8 | writes double-click launchers and a desktop shortcut | `<drive>:\RAKSHA\*.bat` |

**Time:** 20–40 minutes the first time (mostly downloads and the test suite; add `-SkipTests` to
skip the suite).
**Space:** about 5 GB on D:/E:. Keep 10 GB free to be comfortable. Nothing large lands on C:.

### The launchers in `<drive>:\RAKSHA`

| File | What it does |
|---|---|
| `RAKSHA Console.bat` | starts the console and opens http://127.0.0.1:8080 |
| `RAKSHA Shell.bat` | a terminal inside the RAKSHA system, in the repo, with everything set up |
| `RAKSHA Checks.bat` | air-gap guard, model-lane check, find → fix → prove slice, full tests |
| `RAKSHA Set Model.bat` | choose or change the provider and model (menu + test call) |
| `RAKSHA Files.bat` | open the code in Explorer (`\\wsl.localhost\RAKSHA\root\RAKSHA_AI`) |
| `RAKSHA Update.bat` | pull the latest branch and re-verify |

## 2. Choosing and changing the model provider

Every provider RAKSHA supports speaks the OpenAI-compatible API, so a switch changes only the
URL, the model name and, for hosted services, an API key. The choice is saved in
`~/.raksha/provider.json` inside the RAKSHA system, and every RAKSHA command and the console use
it. Change it as often as you like:

- double-click **`RAKSHA Set Model.bat`**: a menu of providers, then the models that server
  offers, then a one-line test; or
- from `RAKSHA Shell.bat`:

```sh
raksha_provider                                   # the same menu
raksha_provider list                              # the presets below
raksha_provider set ollama   --model qwen2.5-coder:7b
raksha_provider set ollama   --model gpt-oss:120b-cloud
raksha_provider set lmstudio --model qwen2.5-coder-7b-instruct
raksha_provider set vllm     --model Qwen/Qwen2.5-Coder-32B-Instruct
raksha_provider set llamacpp --model local
raksha_provider set openai   --model gpt-4.1        --key sk-...
raksha_provider set deepseek --model deepseek-chat  --key sk-...
raksha_provider set custom   --url http://192.168.1.20:8000/v1 --model my-model
raksha_model <name>                               # change only the model, same provider
raksha_provider show | models | test | off        # what is in use / list models / one test call / model-free
```

| Provider | Default URL | Where the code goes | Key |
|---|---|---|---|
| Ollama | `http://127.0.0.1:11434/v1` | stays on the laptop (`…-cloud` models: ollama.com) | — (cloud: `ollama signin`) |
| LM Studio | `http://127.0.0.1:1234/v1` | stays on the laptop | — |
| vLLM | `http://127.0.0.1:8000/v1` | stays on the machine (the finale setup) | — |
| llama.cpp server | `http://127.0.0.1:8081/v1` | stays on the laptop (start it on 8081; 8080 is the console) | — |
| OpenAI | `https://api.openai.com/v1` | **OpenAI** | `OPENAI_API_KEY` or `--key` |
| DeepSeek | `https://api.deepseek.com/v1` | **DeepSeek** | `DEEPSEEK_API_KEY` or `--key` |
| OpenRouter / Groq / Mistral | their `/v1` URLs | **that service** | `OPENROUTER_API_KEY` / `GROQ_API_KEY` / `MISTRAL_API_KEY` |
| custom | any `--url` | wherever that URL is | `RAKSHA_INFERENCE_API_KEY` or `--key` |

How the details work:
- **Keys** given with `--key` or typed into the menu go to `~/.raksha/keys.json` (readable only
  by you, never in the repository). A key in the provider's environment variable is used instead
  when set.
- **Servers on Windows** (Ollama, LM Studio) are found automatically from the RAKSHA system: at
  `127.0.0.1` with mirrored networking (Windows 11), otherwise at the Windows host address. On
  Windows 10, make the server listen on the network: `OLLAMA_HOST=0.0.0.0` (the installer sets
  it), or "Serve on Local Network" in LM Studio.
- **Hosted providers and Ollama `-cloud` models receive the prompt, which includes the source
  code being fixed.**
  - Choosing one switches sealed mode off in the saved settings and prints a warning.
  - Every call is counted on the CLOUD badge.
  - The sealed finale node (`RAKSHA_SEALED=1` in its environment) refuses them whatever is saved.

  Use them only on the demo targets or code you are allowed to send out.
- **Environment variables win** over the saved choice (`RAKSHA_INFERENCE_BASE_URL`,
  `RAKSHA_REPAIR_MODEL`, …). `RAKSHA_PROVIDER=off` ignores the saved choice for one command; the
  install checks use it. Tests always run model-free.
- **No model at all** is a fully supported mode. Templates, fix memory and the mitigation floor
  fixed every demo bug in the benchmark with zero model calls. On a CPU-only laptop a local 7B
  model takes about a minute per answer (`docs/model-benchmark.md`).

Measure any provider on the same 8 benchmark bugs:
```sh
raksha_provider test
python scripts/model_benchmark.py      # model-free vs with the model, table of results
```

## 3. Running it on your own code

From `RAKSHA Shell.bat`:
```sh
mkdir -p ~/targets && cp -r /mnt/d/path/to/your-project ~/targets/
RAKSHA_TARGETS=~/targets RAKSHA_OUT=~/raksha-out python -m raksha.orchestrator
```
Every folder under `~/targets` is scanned: built where a toolchain exists, build-free always. The
console opens with the results, and `~/raksha-out` gets the submission files and a signed evidence
bundle per finding. You can also use the console's *Demo Beats → Bring your own target* from an
allowed folder.

Before trusting results on a new codebase, compare RAKSHA's output with what you already know about
that code: known bugs it should find, and clean files it must not flag. Report both numbers.

## 4. Do I need `claude --teleport`?

**No, not to run RAKSHA.** `--teleport` moves a *Claude Code conversation* from the web into a
terminal Claude Code on your laptop: the chat history plus a checkout of the session's branch. It
does not install tools, copy the Ubuntu system, or set up Ollama. The installer above does all
that from git.

Use teleport only if you want to *continue this exact conversation* on the laptop. To do that:
1. install Claude Code;
2. open `RAKSHA Shell.bat` and `cd /root/RAKSHA_AI`;
3. make sure `git status` is clean;
4. run `claude --teleport` and pick this session.

It needs the same claude.ai account and the branch pushed (it is). Otherwise just start a fresh
session in that folder; `CLAUDE.md` and `HANDOFF.md` give it the full picture.

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| "WSL has been enabled. RESTART…" | restart Windows, double-click `RAKSHA-Setup.bat` again |
| `raksha_provider test` fails: connection refused | start the model server (Ollama / LM Studio); on Windows 10 make it listen on the network (§2), restart it |
| `raksha_provider test` fails: 401 | wrong or missing API key: `raksha_provider set <provider> --model <m> --key <key>` (Ollama cloud: `ollama signin`) |
| Cloud model replies 401 / unauthorised | run `ollama signin` in a Windows terminal |
| Very slow tests | normal on a laptop: the suite is about 880 tests, 7–15 minutes. Use `-SkipTests` for setup and `RAKSHA Checks.bat` later |
| Java demo skipped | the Maven warm-up needs internet once; run `RAKSHA Update.bat` |
| Out of space | `wsl --shutdown`, free space on D:/E:, re-run setup (it resumes) |
| Start over | `wsl --unregister RAKSHA` (deletes the Linux system), delete `<drive>:\RAKSHA`, run setup again |

## 6. Linux, macOS, or an existing WSL

```sh
curl -fsSL https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/claude/magical-mayer-gs2xno/deploy/laptop-bootstrap.sh \
  | RAKSHA_OLLAMA_MODEL=gpt-oss:120b-cloud sh -s -- ~/RAKSHA_AI
```
The script is the same one the Windows installer runs inside WSL. Knobs:
- `RAKSHA_OLLAMA_MODEL`: the model to use;
- `RAKSHA_SKIP_TESTS=1`: skip the test suite;
- `RAKSHA_MINIMAL=1`: core only, no scanners or extra toolchains.

On macOS the apt steps are skipped. Install Python 3.11+, git and gcc yourself.

## 7. What differs from the sealed finale node

| | Laptop | Sealed node |
|---|---|---|
| Network isolation of target code | none (`NET IF: unenforced`, shown honestly) | Docker sandbox, `NET IF: 0` (`RAKSHA_SANDBOX_IMAGE`, `RAKSHA_REQUIRE_SANDBOX=1`) |
| Model | any provider (`raksha_provider`) | vLLM serving a ~32B model on the GPU, sealed mode on |
| GPU numbers | `null` on the scorecard (never a fake zero) | measured |
| Signing key | generate one with `python -m raksha.keys init ~/.raksha-bundle.key` and set `RAKSHA_BUNDLE_KEY_FILE` to it | generated at install by `deploy/install.sh`, read-only mount |
