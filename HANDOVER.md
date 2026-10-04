# RAKSHA AI — Handover and remaining work

**Read this first when resuming on a new machine.** It says exactly where the project stands,
how to pick it up, what is left, and what is honestly *not* done. Everything else in the repo is
either the product (`raksha/`), its proof (`tests/`), or the brief (`RAKSHA_AI_Dossier/`).

## 1. Where everything is

| | |
|---|---|
| Repository | `https://github.com/techtwister007/RAKSHA_AI` |
| Branch | `claude/magical-mayer-gs2xno` (all 35+ commits; nothing lives anywhere else) |
| Get it on a laptop | `docs/laptop-setup.md` — one pasteable command for Windows (WSL2) or Linux/macOS |
| Execution plan + scoring ledger | `BUILD_PLAN.md` |
| The settled brief | `RAKSHA_AI_Dossier/` (start with `EXECUTIVE_SUMMARY.md`) |
| Our own measured numbers | `docs/benchmark-report.md` (regenerate with `python -m raksha.benchmark`) |
| Finale-day procedures | `docs/rehearsal-runbook.md`, `docs/campaign-plan.html` (Parts 2–3) |

Nothing from the cloud build container is needed: it was ephemeral and every artifact was
regenerated from the repository as the last step.

## 2. State of the build — what is real and verified

Verified on the last run (Linux, gcc 13, Python 3.11, JDK 21/Maven 3.9, Go 1.24):

- **371 tests pass**, 6 skipped (opt-in slow/hardware tests), `pyflakes` clean, air-gap guard clean.
- **Four deep languages through one five-check gate**, each find → fix → prove to `VERIFIED` live:
  C (gcc+ASan), Java (Jazzer/Maven, real Log4Shell), Python (sink sanitizer), Go (native `go test -fuzz`).
- **Automatic harness generation** (`raksha/harness/`): on a target that ships **no fuzz harness**,
  RAKSHA discovers the entry point, synthesizes a driver, proves the driver, fuzzes it (fork-server),
  confirms the crash, and the repair ladder proves a fix. 2/2 demo targets `VERIFIED`, ~3.5 s total.
- **Build-free lanes on any language**: supply-chain (Maven/npm/PyPI/Go, multi-range OSV-shaped DB),
  secrets (format + assignment rules, literal-only in code), OpenAPI spec exposure; 10 proven
  findings on the demo estate in 0.003 s; **0 false positives on 11 negative controls**.
- **Evidence a judge can run**: shell-safe `replay.sh` (quoted, injection tests pass), reproducer
  bytes shipped, `python -m raksha match|secret-match|spec-check` replays deterministic findings
  (exit 1 = reproduced), HMAC-signed bundle that detects any changed or slipped file, rollback script
  that is executed by a test, JSSD Commander's Brief with ROE-consistent recommendation.
- **Honest scoring interface**: every BUILD_PLAN ledger row is emitted on the Scorecard; counters are
  per run; the posture badge reads `0` only when all target code ran in the sandbox, else
  `unenforced`; VRAM is `null` without a GPU, never a faked zero.
- **Deployable**: `deploy/` image carries the console and targets, ingests `/targets`, writes the
  submission and sealed bundles to `/out`; console published on the host loopback only; sandbox
  required in both compose profiles.

Per-language matrix today:

| Language | Build-free (deps / secrets / spec) | Deep find (fuzz) | Fix + prove | Harness needed? |
|---|---|---|---|---|
| C / C++ | secrets | gcc+ASan, own mutation engine | yes (template, model) | **no — synthesized** |
| Python | deps, secrets | sink sanitizer + mutation engine | yes | **no — synthesized** |
| Go | deps, secrets | native `go test -fuzz` | yes | **no — synthesized** |
| Java / Kotlin | deps (Maven), secrets | Jazzer replay driver | yes (dependency bump) | shipped with demo target |
| JavaScript / TypeScript | deps (npm), secrets, OpenAPI | — | — | — |
| Rust | secrets | — | — | — |
| anything else | secrets, OpenAPI | — | — | — |

## 3. How to resume

**On the laptop:** follow `docs/laptop-setup.md` §0 (one command). Then the smoke test that proves
the install is whole:
```sh
pytest -q && python -m raksha.airgap && python -m raksha.slice_autofuzz && python -m raksha.slice_three
```

**With a model:** set `RAKSHA_INFERENCE_BASE_URL` (+ `RAKSHA_INFERENCE_API_KEY`, and
`RAKSHA_SEALED=0` for a cloud host) — `docs/laptop-setup.md` §6. The model lane is already wired;
it has only ever been exercised with a mock client in CI, so the first real run is itself a task
(see P1-1 below).

**With a fresh Claude Code session**, paste:
> Read `HANDOVER.md`, then `BUILD_PLAN.md`. Run `pytest -q` and `python -m raksha.slice_autofuzz`
> to confirm the install. Then take the next unticked item in HANDOVER §4, in order, keeping the
> standing constraints in BUILD_PLAN ("no reproducer, no report"; nothing unproven ships; no
> network egress at runtime; every number measured, never typed). Commit each item with tests.

## 4. Remaining work, in priority order

Tick items off here as they land. Effort is a solo-builder estimate.

### P0 — must happen before the finale (needs the finale hardware or a real model endpoint)

- [ ] **P0-1 · Two full 36-hour dress rehearsals** on the finale node, per `docs/rehearsal-runbook.md`.
  The harness, watchdog, probes and caps exist and are tested; the long run has never happened.
  Exit: the second run ends `survived == True` with no manual intervention. *~2 × 36 h wall-clock, little labour.*
- [ ] **P0-2 · Sandbox under real Docker.** Build the image from `deploy/Dockerfile`, set
  `RAKSHA_SANDBOX_IMAGE` + `RAKSHA_REQUIRE_SANDBOX=1`, run every slice. Exit: all slices still
  `VERIFIED` and the posture badge reads `NETWORK INTERFACES: 0` (measured). The `docker run` flags
  were fixed from reading, not from execution — expect one round of fixes. *~half a day.*
- [ ] **P0-3 · Local vLLM, the two-model split, offline.** `docker-compose.gpu.yml` has never been
  started. Exit: `slice_autofuzz` and `slice_three` run with the model lane live, air-gapped
  (cable out), and the Scorecard shows tokens-per-validated-patch. *~1 day incl. weight staging.*
- [ ] **P0-4 · The bundle on removable media**, end to end: `bundle_manifest.py build`, carry,
  `install.sh` on a clean node, verify the manifest hash against the transfer record. *~half a day.*
- [ ] **P0-5 · Record the 7-minute demo** on a controlled target to two devices (the last rung of
  the fallback ladder). *~2 h.*
- [ ] **P0-6 · Freeze.** No pipeline change after hour 27 of the finale (standing constraint).

### P1 — raises the score; buildable on the laptop now

- [ ] **P1-1 · First real model-lane run.** Point at any OpenAI-compatible endpoint, run
  `slice_autofuzz` with templates disabled (see `tests/test_autorepair.py` for the mock pattern), read
  what the model actually proposes, tune `autorepair._llm_candidates`'s prompt. Exit: a model patch
  reaches `VERIFIED` on a demo target and a bad one is rejected. *~half a day.*
- [ ] **P1-2 · Rust deep lane** (cargo-fuzz / `cargo test` panics). Same shape as
  `raksha/adapters/go_fuzz.py` + `raksha/oracles/go_panic.py`: entry-point regex for
  `fn name(data: &[u8])`, a synthesized fuzz target, a panic oracle, a `Target` adapter, a template
  that bounds an index. `cargo`/`rustc` were present on the build box. Exit: a no-harness Rust demo
  target `VERIFIED`. *~1 day.*
- [ ] **P1-3 · JavaScript/TypeScript deep lane** via Jazzer.js (node was present). Exit: a demo
  Express handler with an injection found and fixed. *~1–2 days.*
- [ ] **P1-4 · Real OSV offline mirror.** `raksha/data/vulndb.json` is a curated 9-advisory slice
  (ranges cross-checked against OSV). Ingest a full OSV export for the four ecosystems into the same
  multi-range schema; keep the negative-control test green. Exit: `benchmark` precision unchanged on
  the controls; a real-world lockfile yields plausible findings. *~1 day.*
- [ ] **P1-5 · Autofuzz breadth.** Entry points with structured arguments (two-arg C functions,
  Python functions taking `str` only, Go `string`), C++ free functions, and a model-proposed wrapper
  that decodes bytes into the structured argument (the hook exists; only the template wrapper is
  used today). Exit: autofuzz finds a bug in a target whose entry point is not `(buf, len)`. *~2 days.*
- [ ] **P1-6 · Model-written regression tests.** `gate.verify_regression_test` (fail-before /
  pass-after) exists; nothing produces a test for it. Have the model lane emit one with each patch;
  ship it in the bundle only when it verifies. *~half a day.*
- [ ] **P1-7 · Retrieval lane source.** `repair.retrieval_candidates` takes a source that is always
  `None`. Seed it from verified fixes (the vaccine already mines shapes) so the second occurrence of
  a bug class is fixed at zero inference. *~half a day.*
- [ ] **P1-8 · Benchmark on ARVO cases.** `benchmark.run_cases` takes any case list; add an ARVO
  loader on a networked prep machine and publish the honest numbers (losses listed). *~1–2 days.*

### P2 — polish and the sealed-deployment extras

- [ ] **P2-1 · Asset registry** as data (`roe.Asset` objects are built ad hoc in slices): a file the
  console loads, tiers per codebase, used by ROE and the vaccine sweep. *~half a day.*
- [ ] **P2-2 · cosign / in-toto signing** replacing the HMAC demo key (`RAKSHA_BUNDLE_KEY_FILE`
  already exists as the provisioning seam). *~half a day on the finale node.*
- [ ] **P2-3 · "Take" lanes behind flags** — Semgrep (static → cross-confirmation), Gitleaks,
  OSV-Scanner, Checkov — when their binaries are carried in the bundle; our own lanes stay the floor.
- [ ] **P2-4 · Console**: Hindi headline from the glossary in the Commander's Brief; a diff view per
  repair round; keyboard-only operation for the demo.
- [ ] **P2-5 · Housekeeping**: `autofuzz` leaves one scratch dir per target in `/tmp` (the gate cleans
  its own builds); delete it after `repair()` completes.
- [ ] **P2-6 · Deck v2** in `RAKSHA_AI_Dossier/` — the submission deck is still v1 and predates the
  two-model split, ROE, the vaccine and autofuzz.

## 5. Honest limitations — say these before a judge does

- **"100% precision" is on *reports* (every report carries a replaying reproducer), not on patch
  semantic correctness.** False positives are measured separately (0 on 11 negative controls).
- **Fix templates are generic but few**: C memcpy/strcpy bound, Python `shell=True` → argv, Go slice
  bound. Everything else needs the model lane, which has not yet run against a real endpoint.
- **The Go differential only observes "panics or not"** (the synthesized fuzz test discards the
  function's return); C and Python compare real output.
- **Autofuzz's mutation engine is coverage-blind**; AFL++/libFuzzer are far stronger and plug in
  behind `harness.mutator.Fuzzer` when their runtime is present (it was not on the build box).
- **The bundle signature uses a published demo key** unless `RAKSHA_BUNDLE_KEY_FILE` is provisioned;
  verification says so explicitly.
- **Deep coverage is four languages**; JS/TS and Rust are build-free only today (§2 table).
- **Untested paths**: the Windows PowerShell wrapper (no Windows available), the old-Ubuntu
  (22.04) fallback branches in `deploy/laptop-bootstrap.sh`, and everything in P0.

## 6. Finale-day pointers

The hour-by-hour plan, the nine demo beats, the question bank and the pre-mortem are in
`docs/campaign-plan.html`; the fallback ladder (every rung is still a result) is in
`docs/plan-map.html` §8. The night-before checklist is the last section of the campaign plan.
Standing constraints are the last section of `BUILD_PLAN.md` — the one that matters most on the
day: **their code never leaves the machine and is never committed here.**
