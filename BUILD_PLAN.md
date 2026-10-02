# RAKSHA AI — Build Plan

**The dossier (`RAKSHA_AI_Dossier/`) is the settled brief. This file is the execution
plan.** It changes as checkpoints pass or fail; the dossier does not.

## Constraints this plan is built for

| Constraint | Value | What it forces |
|---|---|---|
| Prep time | Several weeks before the 36-hour finale | CORE + HIGH-VALUE + 3 WOW beats are reachable. Two dress rehearsals are affordable — and mandatory. |
| Builder | Solo | Strict sequencing, no parallel tracks. Every piece must be independently testable so work can be put down and picked up without re-deriving context. |
| Deepest adapter | **Java** (Jazzer) | Autofuzz writes the harness, detectors catch security bugs out of the box, JUnit is a native regression suite. Highest capability per hour, and it is where the Log4Shell demo lives. |
| Dev hardware | Low-capability laptop; cloud GPU for now | Inference must sit behind one swappable interface from day one (see below). |

## The one rule

Shortlisting is banked. **Every remaining point comes from the finale five:**
performance, speed, precision, functionality, scalability.

> **A criterion you cannot measure is a criterion you cannot score.**
> No component is "done" until it emits the metric that proves it.

Telemetry is not a reporting layer bolted on at hour 30. Each stage writes its own
metric as it runs, and the Scorecard screen just reads them. This is why the finding
record carries its own transition timestamps and repair-lane tag.

## The scoring ledger

Every component must appear in this table before it is worth building. If a component
feeds no criterion, it is STORY-ONLY — describe it, do not build it.

| Component | Criterion it feeds | Metric it emits |
|---|---|---|
| Unified finding record (`raksha/finding.py`) | **Precision**, Scalability | `% findings with a replaying reproducer` (100% by construction); language coverage |
| Status state machine | **Precision**, Functionality | stage-transition log; `SUSPECTED→CONFIRMED→PATCHED→VERIFIED` counts |
| Transition timestamps | **Speed** | median time-to-PoV, median time-to-validated-patch |
| Repair-lane tag | Resource utilisation | `% of fixes with zero inference` (template lane) |
| Five-check gate | **Precision** | `% patches surviving the differential corpus` |
| Oracle adapters (ASan / Jazzer / PySecSan) | **Scalability**, Performance | one record shape across 3+ languages |
| Build agent + build-free lanes | **Performance** | findings produced when the build fails (the 36%→85% lever) |
| Dedup / minimise | **Speed**, Precision | raw crashes → distinct bugs ratio |
| ROE policy layer | **Functionality** | authority level in force per action; zero-human-input count |
| Sandbox | Trust (jury question, not a scored row) | `network interfaces: 0` |

## Cloud dev without breaking the air-gap claim

You are developing against cloud inference. The product must *prove* it needs none.
Both are true only if the boundary is explicit and enforced:

1. **One interface.** All model calls go through a single OpenAI-compatible client
   configured by `RAKSHA_INFERENCE_BASE_URL`. Cloud endpoint now, local vLLM later,
   **zero code change**.
2. **No model call anywhere else.** No SDK imported outside that module. This is
   checkable in CI with a grep, and it must stay checkable.
3. **The offline profile gets benchmarked before the finale, not discovered live.**
   Measure the 32B+8B profile on real hardware, and measure the CPU-only degraded
   profile too (`14_open_questions.md` item 10). Bring your own machine regardless.
4. **The demo runs offline or it does not run.** A console that pulls a CDN font
   contradicts the entire pitch. Self-contained assets only.

## Phases

Each phase ends in a checkpoint with a kill-switch. Obey the kill-switches — they were
decided calm, and hour 30 is not calm.

### Phase 0 — The keystone  ← *in progress*
Prove three oracles → one record → one gate on trivial targets, **before anything
clever** (`14_open_questions.md` item 1, `15_build_priorities.md` item 1).

- [x] Unified finding record: SARIF 2.1 + `raksha/proof` property bag
- [x] Status state machine with the precision invariant enforced mechanically
- [x] Oracle adapters: ASan (C/C++), Jazzer (Java), PySecSan (Python)
- [x] Dedup key (stack hash) for the Normalise stage
- [x] Scorecard derived from the records (`raksha/metrics.py`)
- [x] Output validated against the vendored OASIS SARIF 2.1.0 schema
- [ ] The five-check gate consuming the record (Phase 1)
- [ ] End-to-end: one real Java bug through the whole slice (Phase 2)

**Checkpoint:** a Java reproducer, a C trace and a Python abort all become valid records
that one gate consumes.
**Kill-switch:** if they cannot, the "one pipeline, every language" claim is false and
the architecture needs rework *now* — not at the finale.

### Phase 1 — The gate
Five checks, cheapest first. The differential-corpus check with its determinism
pre-flight (run 3×) + canonicaliser + printed quarantine list.

**Checkpoint:** the gate rejects a deliberately-planted overfitting patch.
**Kill-switch:** if the determinism pre-flight throws false rejections on a noisy
service, patch success craters silently — fix it before trusting any patch number.

### Phase 2 — The Java vertical slice
Ingest → Jazzer autofuzz → localise → repair (template lane first) → gate → signed
bundle, on a deliberately vulnerable Java service. Log4Shell is the demo target.

**Checkpoint:** one real bug found, fixed and proven with no human input.
**Kill-switch:** if repair stalls, demo the template lane as primary and the LLM as
fallback. Still impressive, still honest.

### Phase 3 — The weakest link
Build agent (OSS-Fuzz recipe retrieval + known-error remedy table, model only as a
bounded last resort) + offline mirror of the high-probability dependency set +
**build-free lanes**: OSV-Scanner, Gitleaks, Checkov.

**Checkpoint:** a target that will not build still produces verified findings.
This single capability is what turns ~36% into ~85%. Do not skip it because it is
unglamorous — it is the highest-value engineering in the project.

### Phase 4 — Sandbox and offline bundle
No-network containers, cgroups, seccomp. One `docker compose`, installable from
removable media. Non-negotiable: we execute untrusted code on an Army box.

### Phase 5 — Console screens 1, 3, 5
Mission Board, Finding Detail (split-screen replay), Scorecard. These three carry the
demo; 2, 4 and 6 are built only if the first three are flawless.

### Phase 6 — WOW, exactly three
Solo builder, so three done perfectly beats five done badly:
1. Cable-pull offline install — lowest effort, largest effect
2. Live Log4Shell + split-screen proof
3. Public rejection of a bad patch — the gate refusing an overfitting fix

ROE slider and the Vaccine sweep are next in line **only** if CORE is untouched.

### Phase 7 — Dress rehearsal, twice, full length
Nobody has run this for 36 hours. Leaks, disk filling with corpus, stuck subprocesses
and a dying model server only appear in a long run. Record the full demo as the last
rung of the fallback ladder.

## Standing constraints

- **No reproducer, no report.** Enforced in the data model, not in review.
- **Nothing unproven ships.** Gate fails → `REPORT_ONLY`.
- **Zero network egress at runtime, ever.**
- **Degrade, don't die.** Every stage needs its fallback rung *built*, not described.
- **No pre-promised numbers.** Every figure comes from our own ARVO / AutoPatchBench
  baseline. A judge will ask where it came from.
- **Only VERIFIED findings may become vaccines.** An unproven fix would spread a wrong
  pattern across the fleet.
