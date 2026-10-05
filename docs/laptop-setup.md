# Running RAKSHA AI on your laptop

Written for: a Windows laptop with **no GPU**, little space on C:, room on **D: or E:**, and
**Ollama** installed (local or cloud models). Linux and macOS instructions are at the end.

## 1. One click (Windows)

1. Download **`deploy/windows/RAKSHA-Setup.bat`** from the repository (on GitHub, open the file
   and click *Download raw file*), or from a clone.
2. Double-click it.
3. Answer the one question: which Ollama model to use. Examples: `gpt-oss:120b-cloud`,
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
| `RAKSHA Set Model.bat` | change the Ollama model |
| `RAKSHA Files.bat` | open the code in Explorer (`\\wsl.localhost\RAKSHA\root\RAKSHA_AI`) |
| `RAKSHA Update.bat` | pull the latest branch and re-verify |

## 2. Ollama: local or cloud

RAKSHA talks to Ollama's OpenAI-compatible endpoint (`/v1/chat/completions`). The shell settings
live in `~/.raksha-env` inside the RAKSHA system, and the model name in `~/.raksha-model`.
Change the model from `RAKSHA Shell.bat` with `raksha_model <name>`, or with
`RAKSHA Set Model.bat`.

- **Cloud models** are names ending in `-cloud` or `:cloud`. Run `ollama signin` once on Windows.
  These are fast and need no GPU, but **the prompt, including the source code being fixed, goes to
  ollama.com**. RAKSHA knows this:
  - it counts every such call as a cloud call (the CLOUD badge stops reading 0);
  - in sealed mode it refuses them;
  - the launcher sets `RAKSHA_SEALED=0` for cloud models.

  Use cloud models only on the demo targets or code you are allowed to send out. Never at the
  finale.
- **Local models** (for example `ollama pull qwen2.5-coder:7b`) keep everything on the laptop. On
  a CPU-only laptop a 7B model takes about a minute per answer. See `docs/model-benchmark.md`.
- **No model at all** is a fully supported mode. Templates, fix memory and the mitigation floor
  fixed every demo bug in the benchmark with zero model calls.

Check that the model is reachable, from `RAKSHA Shell.bat`:
```sh
echo $RAKSHA_INFERENCE_BASE_URL $RAKSHA_REPAIR_MODEL
python -m raksha.slice_autofuzz          # model lane available as a fallback
python scripts/model_benchmark.py        # measure the model on the 8 benchmark variants
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
| "Ollama not reachable on 11434" | start Ollama on Windows; on Windows 10 quit and restart it after setup (it must pick up `OLLAMA_HOST`); open a new shell |
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
| Model | Ollama, local or cloud | vLLM serving a ~32B model on the GPU, sealed mode on |
| GPU numbers | `null` on the scorecard (never a fake zero) | measured |
| Signing key | generate one with `python -m raksha.keys init ~/.raksha-bundle.key` and set `RAKSHA_BUNDLE_KEY_FILE` to it | generated at install by `deploy/install.sh`, read-only mount |
