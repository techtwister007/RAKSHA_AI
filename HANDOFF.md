# RAKSHA AI — handoff for the laptop session (5 October 2026)

Start here on the new laptop. This page covers what the project is, where it stands today, how to
run it, what changed in the last session, and what is left. `HANDOVER.md` has the full build
history and the long work list. `PLAN_V2.md` has per-item status.

## 1. What RAKSHA AI is

An offline system for the Indian Army's AI Kavach Grand Finale that **finds, fixes and proves**
software weaknesses. A weakness is reported only with evidence that replays: an input that triggers
it, or an exact match against a known-vulnerable version. A fix is accepted only after the
**five-check gate**:
1. COMPILES;
2. POV_DEAD (the original attack is dead);
3. DIFFERENTIAL_CORPUS (normal inputs behave identically);
4. COVERAGE_HELD (the fixed code is still reached);
5. CLEAN_REFUZZ (fresh attacks fail).

After the gate, an independent red team re-attacks the fix. Fixes come from a repair ladder:
TEMPLATE → RETRIEVAL (fix memory) → LLM → MITIGATION. A model only *proposes*; the gate decides.

## 2. Where things are

| | |
|---|---|
| Code | `raksha/` (stdlib-only Python), console in `console/`, demo targets in `demo-targets/` |
| Repo / branch | `github.com/techtwister007/RAKSHA_AI`, branch `claude/magical-mayer-gs2xno` (everything is on it) |
| Laptop install | `deploy/windows/RAKSHA-Setup.bat` (double-click) → guide `docs/laptop-setup.md` |
| What the app shows | `docs/app-walkthrough.md` (21 screenshots, every screen explained) |
| Measured numbers | `docs/benchmark-report.md`, `docs/model-benchmark.md` |
| The book (web + PDF) | `docs/raksha-book.html`, `docs/RAKSHA-Book.pdf` |
| UI redesign brief | `docs/ui-design-brief.md` (for Claude Design) |
| What is not built | `docs/missing-pieces.md` |
| Claims vs evidence | `docs/claim-audit.md` |
| Finale procedures | `docs/rehearsal-runbook.md`, `docs/campaign-plan.html` |

## 3. Run it

On Windows, after setup, everything is in `<D: or E:>\RAKSHA`:
- `RAKSHA Console.bat` opens the console at http://127.0.0.1:8080.
- `RAKSHA Shell.bat` opens a terminal in the repo with everything set up.

From that shell:
```sh
python -m raksha.airgap              # must print "air-gap clean"
python scripts/model_lane_check.py   # gate accepts 8/8 correct model fixes, rejects 8/8 wrong ones
python -m raksha.slice_autofuzz      # no-harness C + Python: find → fix → prove
python -m raksha.slice_three         # C, Python, Java through one gate
python -m raksha.benchmark           # regenerate docs/benchmark-report.md on this machine
python -m pytest -q                  # ~880 tests; 7–15 min on a laptop
RAKSHA_TARGETS=~/targets RAKSHA_OUT=~/out python -m raksha.orchestrator   # your own code
```

Model: Ollama, set by `raksha_model <name>` or `RAKSHA Set Model.bat`.
- **Cloud models** (`…-cloud`) send source code to ollama.com. RAKSHA counts those calls as cloud
  calls and refuses them in sealed mode. Use them on demo targets only.
- **No model** is a supported mode.

## 4. State today

- **Tests:** 873 passed / 10 skipped on 5 October, before this session's additions. This session
  added 6 tests; re-run with `python -m pytest -q`.
- **Deep find → fix → prove, with no hand-written harness:** C, Python, Go, Rust, JavaScript. Java
  uses its shipped driver.
- **Build-free lanes on any language:** dependencies, secrets, crypto / post-quantum, OpenAPI
  exposure, structural.
- **External scanners wired in** (each optional, offline): semgrep (bundled rules), gitleaks,
  osv-scanner (offline database), checkov; plus OPA as a second opinion on the rules of engagement
  and cosign for sealing.
- **Console:** 14 screens, English/Hindi, projector mode, keyboard, phone width.
- **Project memory:** versioned signed reports, learning on probation.
- **Benchmark:** 8/8 benchmark variants fixed with zero model calls. 0 false positives on 11
  negative controls.

## 5. What this session found and fixed

1. **The model lane dropped correct C fixes.** A model copies a code line but leaves off its
   trailing comment, and the edit matcher needed the comment. Every correct C fix was discarded
   before the gate. Found by `scripts/model_lane_check.py`: templates switched off, then
   hand-written good and bad model answers fed in. Fixed in `raksha/repair.py::_locate`. Now 8/8
   good fixes are accepted and 0/8 bad ones (too-loose bound, blocklist filter, shell quoting,
   `eval`).
2. **Why the local Qwen 7B failed.** Its replies mostly restated the vulnerable code unchanged (see
   `docs/model-benchmark.md`). That is a model-quality limit on CPU, not a pipeline fault. The
   pipeline is now proven to accept a correct model fix end to end.
3. **Ollama cloud models looked local.** They are reached through `localhost:11434`, so the
   CLOUD badge would have read 0. They now count as cloud calls, and sealed mode refuses them
   (`raksha/inference.py::_offbox_model`).
4. **The osv-scanner offline flag was wrong for v1.x.** The lane passed `--offline`, which v1
   rejects, so the lane errored. The lane now reads the tool's own help and picks the right flag.
   Verified: 81 findings offline on the demo estate.
5. **Tests picked up the operator's shell settings.** With a model or scanners configured,
   `pytest` would have called them. Now every test starts from the model-free, scanner-off default
   (`tests/conftest.py`).
6. **Console fixes from the walkthrough:**
   - attack-graph nodes for deep findings showed no service name;
   - targets whose only finding was fixed read "fixing", now "fixed";
   - "0s" for a sub-second measurement now reads "<1s";
   - the console now serves its own CSS/JS/font files (safely), so a redesign can drop in.
7. **One-click Windows install that keeps everything on D:/E:.** It creates a private WSL Ubuntu
   whose disk lives on the big drive, sets up mirrored networking for Ollama, installs every
   toolchain and scanner, adds double-click launchers, and runs the checks. The Linux half was
   tested end to end in a fresh home directory: all 14 tools installed, every check passed.

## 6. What is left

See `HANDOVER.md` §4 for the full list. In short:
- **Before the finale (needs finale hardware):**
  - run the model benchmark with the GPU model;
  - build the sandbox image with all toolchains (`docs/missing-pieces.md`);
  - run the 36-hour rehearsal (`python -m raksha.rehearse 129600`).
- **Not built:** J3 real-ARVO numbers (the runner exists; it needs data), K21 explainer, K24 ask,
  K30 drill. Specs and "done when" are in `docs/missing-pieces.md`.
- **UI redesign:** optional, from `docs/ui-design-brief.md`.

## 7. Rules that do not bend

- The five-check gate decides; a model never does.
- No reproducer, no report.
- Presence, never absence: never call a target "secure".
- The runtime stays offline and stdlib-only. Optional tools are imported with a fallback.
- Every number is measured, or shown as null.
- Target code never leaves the machine and is never committed. Never commit a signing key or a
  credential.
- Negative controls stay at 0 false positives.
- Tests are never skipped or weakened to get green.
