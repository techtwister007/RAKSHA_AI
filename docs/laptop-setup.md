# Running the full system on a laptop

Everything is in this repository. The runtime has **no third-party Python dependencies** (stdlib
only, by design — see `pyproject.toml`); every lane drives an ordinary toolchain as a subprocess.
Linux or macOS natively; on Windows use WSL2 (the gate relies on `fork`, `sh`, `gcc`).

## 1. Toolchains

| Needed for | Install | Required? |
|---|---|---|
| everything | Python **3.11+**, git | yes |
| C lane (ASan) + autofuzz for C | `gcc` (we use gcc's ASan; clang's runtime is often missing) | yes for C |
| Java lane (Log4Shell demo) | JDK **17+**, Maven 3.9+ | optional |
| Go lane (native fuzzing) | Go **1.21+** (builtin `min` in the repair template) | optional |
| Python lane | nothing extra | — |
| sandbox (optional, for the honest `NETWORK INTERFACES: 0` badge) | Docker | optional |
| model lane (optional) | any OpenAI-compatible `/chat/completions` endpoint: local vLLM/Ollama, or a cloud provider | optional |

Debian/Ubuntu in one line:
```sh
sudo apt-get install -y python3 python3-venv git gcc libc6-dev openjdk-17-jdk-headless maven golang-go
```

## 2. Get the code

```sh
git clone https://github.com/techtwister007/RAKSHA_AI.git
cd RAKSHA_AI
git checkout claude/magical-mayer-gs2xno      # the branch everything was built on
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'                        # dev extras = pytest + jsonschema only
```

## 3. One-time, with network: warm the Maven cache (Java lane only)

The gate runs Maven **offline** (`-o`), so both log4j versions, JUnit, the Jazzer API and the
build plugins must be in `~/.m2` before the first run. Once:

```sh
./deploy/warm-maven.sh
```

Skip this if you do not care about the Java demo; the other lanes never touch Maven.

## 4. Verify

```sh
pytest -q                     # ~370 tests, ~20 s; needs gcc + python; Java/Go e2e are opt-in
python -m raksha.airgap       # must print "air-gap clean"
python -m raksha.slice_three  # C, Python (+ Java if Maven is warm) VERIFIED through the one gate
python -m raksha.slice_autofuzz  # find→fix→prove on targets with NO hand-written harness
python -m raksha.slice_go     # Go deep lane (skips cleanly if `go` is absent)
RAKSHA_RUN_GO=1 pytest -q tests/test_go_lane.py   # the slow Go end-to-end test, opt-in
python -m raksha.benchmark    # regenerates docs/benchmark-report.md from YOUR machine's run
```

Everything a judge will see — the demo slices, the console, the bundles — is produced by these.

## 5. The console

```sh
python -m raksha.orchestrator           # http://127.0.0.1:8080 — the bundled demo estate
RAKSHA_TARGETS=/path/to/targets RAKSHA_OUT=./out python -m raksha.orchestrator
```
With `RAKSHA_TARGETS` set, every directory under it is ingested (build attempted, build-free lanes
always) and the jury submission plus a sealed evidence bundle per finding are written to `RAKSHA_OUT`.

## 6. The model lane (optional)

Every model call goes through `raksha/inference.py`. With nothing configured the pipeline is
model-free (templates + retrieval + mitigation floor) and still reaches VERIFIED on the demos.

**Local (sealed, the finale shape):**
```sh
export RAKSHA_INFERENCE_BASE_URL=http://127.0.0.1:8000/v1       # vLLM / Ollama OpenAI-compatible
export RAKSHA_REPAIR_MODEL=<served model name>
```

**Cloud, for development only.** Sealed mode *refuses* a non-local host by design, so you must
turn it off explicitly — and remember the air-gap badges then reflect real egress:
```sh
export RAKSHA_SEALED=0
export RAKSHA_INFERENCE_BASE_URL=https://<provider>/v1              # OpenAI-compatible chat/completions
export RAKSHA_INFERENCE_API_KEY=<your key>                          # read from env, never committed
export RAKSHA_REPAIR_MODEL=<model id>  RAKSHA_ADVISOR_MODEL=<model id>
```
Then re-run `python -m raksha.slice_autofuzz`: patches the model proposes are labelled `LLM` on the
record and go through the same gate; the Scorecard's `cloud_calls` and token counters become non-zero.

## 7. What differs from the sealed deployment

- **No Docker** → target code runs on the host and the posture badge honestly reads
  `NETWORK INTERFACES: unenforced`. To get `0`, build the sandbox image from `deploy/Dockerfile`
  and set `RAKSHA_SANDBOX_IMAGE=raksha-sandbox:latest` (`RAKSHA_REQUIRE_SANDBOX=1` to refuse
  running without it).
- **No GPU** → `vram` on the Scorecard is `null`, not a faked zero.
- **The 36-hour rehearsal** (`python -m raksha.rehearse 129600`) and the sealed `docker compose`
  stack in `deploy/` are for the finale node; `python -m raksha.rehearse 30` is the self-test.

## Troubleshooting

- `clang: cannot find libclang_rt.asan` → expected; the C lane uses **gcc**. Install `gcc`.
- Java slice says the target did not build → run `./deploy/warm-maven.sh` once with network.
- Go template fix fails to compile → Go < 1.21 (no builtin `min`); upgrade.
- Tests leave nothing behind: scratch builds go to pytest's temp dir and are deleted; the gate
  discards its own builds. If `/tmp/raksha-*` ever accumulates, it is safe to delete.
