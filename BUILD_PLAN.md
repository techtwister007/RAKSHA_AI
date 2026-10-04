# RAKSHA AI — Build Plan

**The dossier (`RAKSHA_AI_Dossier/`) is the settled brief. This file is the execution plan.**
**Resuming on a new machine? Read `HANDOVER.md` first** — current state, how to pick it up, and the
prioritised remaining work.
Three companion documents carry the detail; this file is the short, committed version of them:

| Document | Source | Published |
|---|---|---|
| Architecture sheet — figures, scoring ledger, deliverables, way ahead | `docs/architecture.html` | https://claude.ai/artifact/A49gWRM8tzWXH5HUTAjX4W |
| Campaign plan — phases with gates, the 36 hours, question bank, pre-mortem | `docs/campaign-plan.html` | https://claude.ai/artifact/KR4t3adRsWeqknNgXJtEV1 |
| Plan map — one diagram per decision, for vetting | `docs/plan-map.html` | https://claude.ai/artifact/25MpC9CW2MUZoQXKFfKLsp |

## What we know about the finale (answered 2026-10-03)

| | Answer | Consequence for the build |
|---|---|---|
| **Pre-built code** | Allowed | Arrive with CORE working; the 36 hours are for adapting to their target. Keep provenance history in git. |
| **How it is scored** | They provide real working code; our system runs on it; judged on **accuracy, speed, and least resources** | The evaluation on *their* code is the main event. Resource telemetry (VRAM, tokens, CPU, % zero-inference) is a **scoring asset** and must be live. Time-to-first-finding matters more than depth. The CPU-only profile and the template lane are advantages, not fallbacks. |
| **Target type** | Mixed / unknown | Repos first; lane D (service) and the binary lane are Phase 3, not later. |
| **What scores** | **Findings and patches score equally** | **Breadth-first.** Many proven findings fast; REPORT_ONLY is worth as much as a patch. Patches are opportunistic — dependency bumps first because they are free, then template fixes, then the model. Never spend the clock on a hard patch while cheap proven findings are unbanked. |

Also settled: fuzz at full rate (no rate limiting); a GPU is available; one builder, whole
product; judging format unknown — optimise for product quality and the required output; **every
language must be covered**; their code may stay on our machine.

**"All languages" is a product requirement, met in two tiers.** Tier 1, every language: the
language-agnostic lanes — dependency CVEs (OSV covers every ecosystem), secrets, config, SBOM, and
Semgrep's generic rules across 30+ languages — run on any target and produce proven findings.
Tier 2, deep (fuzz + fix): **built for C/C++, Java, Python and Go** — the first three with no
hand-written harness (synthesized, Phase 11; Java via the shipped Jazzer replay driver). JS/TS
(Jazzer.js) and Rust (cargo-fuzz) are the next adapters behind the same oracle plugin API
(`HANDOVER.md` P1-2, P1-3). No language ever yields nothing: every one gets the Tier-1 lanes.

## Settled decisions

1. **Two tracks, no shared dependency.** The 7-minute demo runs on bundled targets we own
   (Java/Log4Shell, C/ARVO, Python/shell-sink), rehearsed. The evaluation on their code runs the
   full pipeline with every fallback armed and is reported exactly as it comes out.
2. **Java is the spine** (Jazzer autofuzz, built-in detectors, JUnit). C and Python exist for the
   three-languages-one-screen beat.
3. **Build-free lanes run first, on everything.** Dependency scan, secrets, config, SBOM start the
   moment a target lands. On an unknown target they put the first proven finding on screen in
   minutes — which, given "speed" is scored, is the opening move.
4. **Dependency bumps are patches.** Bump → rebuild → suite → gate. Zero inference. The confirming
   oracle is a deterministic version match (`osv-version-match`), named as such on the record and
   ranked below exploit-proven findings.
5. **Precision is a data model, not a promise.** Shipped (`raksha/finding.py`): the invariant is
   closed at construction as well as in the transition methods, and false positives are measured
   separately against negative controls (`python -m raksha.benchmark`), not assumed.
6. **The security advisor never vetoes the gate.** Disagreement with the coding model steps ROE
   down to R1; the five mechanical checks alone decide VERIFIED.
7. **Harness synthesis is built, and it is TAKE+WRAP with a two-check quality gate** (the
   synthesized driver must compile/import and exercise the target on a benign input before it
   is trusted) — the same "nothing is trusted until it proves itself" rule applied to our own
   generated code. It is what lets the deep loop run on an unknown target with no human-written
   harness (`raksha/harness/`). "Five-gate harness synthesis" was deck-v1 language and stays retired.
8. **Lane cross-confirmation** promotes a static SUSPECTED finding when another lane's reproducer
   lands on the **same fix site with the same CWE**; the two records **merge** on the dedup key.
9. **The model's regression test must fail on the vulnerable build and pass on the patched one**
   before it enters the bundle or the target's suite.
10. **Differential check = corpus inputs + the target's own test suite.** When a target ships no
    tests, M = 0 is written into the bundle.
11. **The asset registry** (every codebase, its source, its criticality tier) is a BUILD component;
    ROE and the vaccine both depend on it.
12. **Recruit one teammate for the 36 hours**, even non-technical.
13. **Every model call goes through one interface** (`raksha/inference.py`, `RAKSHA_INFERENCE_BASE_URL`):
    cloud during development (`RAKSHA_SEALED=0`), local vLLM sealed at the finale; no model SDK
    anywhere else — the air-gap guard parses every shipped Python file to prove it. With no
    endpoint the pipeline is model-free (templates → retrieval → mitigation) and still verifies.

14. **Shallow fixes die in the gate, deterministically.** CLEAN_REFUZZ opens with 24 fixed-seed
    variants of the reproducer on the patched build before the fresh campaign; a patch that
    silences the one crashing input fails on every target, not only when a random campaign finds a
    sibling (`gate/runner.py::pov_neighbourhood`; `docs/external-review-vetting.md` §2).
15. **The target's source is untrusted input to the model, and the diff is its only exit.** The
    prompt says so; patch hygiene refuses, before any gate run, a candidate that touches a file
    outside the fix-site set, adds more than 150 lines, or introduces an execution / network /
    dynamic-load primitive the removed lines did not have (`raksha/hygiene.py`). Templates get no
    exemption. Rejections are counted on the Scorecard.
16. **Presence is never absence.** Every Scorecard, export and console carries an assurance
    boundary — languages exercised by exploit vs build-free only, targets that did not build,
    suspected-and-unreported, dependencies the code does not import — and a statement that never
    contains the word "secure". A dependency match is ranked by import-level reachability
    (imported / not-imported / unknown), because a proven-present CVE in an unused library is not
    an exploit.

17. **Breadth belongs in the pipeline, behind the gate.** Capabilities the first review pass deferred
    as "too costly" were built this session (`docs/external-review-vetting.md` §5a): the crypto/PQC
    lane, the structural CPG lane, the attack graph, the asset registry, the triage funnel, the model
    parliament, the evidence-fusion kernel, the TSan race oracle, the patch frontier + perf check, and
    the independent red team. None may decide truth — the gate does; each is a proposer, a ranker, a
    detector or an annotator. Optimisation (a real fuzzer behind triage, a full crypto catalogue, a
    GNN over the CPG) comes after breadth.
18. **No single model decides, and model influence is capped.** The parliament measures disagreement
    (an investigation signal, never a status change); evidence fusion holds model votes below the
    proven threshold so they can never manufacture proof; triage's model assist re-orders but cannot
    veto a real bug. Offline, each uses a deterministic fallback and says so.
19. **Presence, never absence; and the horizon is named.** `docs/future-technologies.md` marks every
    capability built / wired / roadmap, so what is not yet done (attestation, CHERI migration, schedule
    fuzzing, the GNN, federated assurance) is stated, not implied.

## The one rule

> **A criterion you cannot measure is a criterion you cannot score.**
> No component is "done" until it emits the metric that proves it, while it runs.

Given the finale is judged on accuracy, speed and resources, the Scorecard is not UI — it is the
scoring interface. Every stage writes its metric as it runs; the console reads them live.

## Scoring ledger

Every row below is emitted on the Scorecard (`raksha/metrics.py`, console Screen 5) and is
measured per run from the records and live counters — never typed in. Key names are the
`scorecard()` dict keys.

| Component | Criterion | Metric emitted |
|---|---|---|
| Unified finding record — no reproducer, locked at SUSPECTED | **Precision** | `reports_with_reproducer_pct` (100% by construction); `unproven_findings_suppressed`; false positives on negative controls (benchmark) |
| Status machine + transition timestamps | **Speed** | `median_time_to_pov_seconds`; `median_time_to_validated_patch_seconds`; **`time_to_first_proven_finding_seconds`** (wall-clock from session start); `proven_findings_in_first_10min` |
| Five-check gate, differential corpus + own tests | **Precision** | `patches_surviving_differential_pct`; `patches_rejected_by_gate`; `quarantined_corpus_inputs` |
| Lane cross-confirmation | **Precision** | `static_findings_promoted` |
| Build-free lanes + dependency-bump patches | **Performance · Speed** | findings in the first 10 minutes; findings produced while the build was failing |
| Repair ladder (template → retrieval → model → mitigation) | **Resource** | `zero_inference_fix_pct` (every lane but LLM); `tokens_per_validated_patch` (summed from real usage); `vram` (null off-GPU); `inference_attempts_without_a_fix` |
| CPU-only degrade profile | **Resource** | the whole pipeline running with no model |
| One adapter per language, oracle plugin API; **automatic harness generation** | **Scalability** | `languages_covered` (lanes such as secrets/API excluded); `verified_per_language`; findings from synthesized harnesses in the benchmark |
| ROE authority model | **Functionality** | authority in force per action; zero-human-input count |
| Vaccine sweep over the asset registry | **Scalability** | `vaccine_variants_found` (origin codebase excluded — no self-hits) |
| Patch hygiene (scope · size · primitives) before the gate | **Precision** | `candidate_patches_rejected_before_gate` |
| Dependency reachability (import index in the build-free walk) | **Precision** | `dependency_reachability` {imported, not-imported, unknown}; risk register weights 0.9 / 0.3 / 0.6 |
| Assurance boundary | Trust · **Precision** | `boundary.*` and `boundary.statement` on Screen 5, `summary.json`, `ASSURANCE_BOUNDARY.txt` |
| Crypto + post-quantum readiness lane | **Functionality · Scalability** | `depth.crypto_findings`; `depth.pqc_quantum_vulnerable_sites`; `depth.pqc_blast_radius` |
| Structural source→sink (CPG) lane | **Precision** | `precision.structural_hypotheses` (SUSPECTED; promoted ones count in `static_findings_promoted`) |
| Attack graph (attack economics) | **Functionality** | `depth.attack_chains`; `depth.viable_attack_chains` |
| Asset registry (mission tiers) | **Functionality** | `depth.mission_tiers`; folded into the risk score |
| Decision-funnel triage | **Speed · Resource** | `snapshot.triage` reduction stages |
| Model parliament + evidence fusion | **Precision** | `depth.median_evidence_confidence`; `depth.findings_with_2plus_independent_channels`; `depth.findings_flagged_for_investigation` |
| Independent red team | **Precision** | `depth.patches_red_team_held`; `depth.patches_red_team_broke` |
| TSan race oracle; patch frontier; perf check | **Precision · Functionality** | `depth.race_findings`; `depth.patches_with_frontier_alternatives` |
| Sandbox, no network interface | Trust | `network_interfaces` = 0 only if every target-code run went through the sandbox, else `unenforced`; `cloud_calls` = live egress counter |

## Phases

Strictly sequential (one builder). Every phase leaves a demonstrable system. Exit gates and
kill-switches are in the campaign plan, Part 2.

| # | Phase | Exit gate | Status |
|---|---|---|---|
| 0 | Keystone — one record, one gate, three oracles | C/Java/Python records all pass one gate; SARIF validates against the OASIS schema | **done** |
| 1 | The five-check gate, for real; cross-confirmation; model-test check | A planted overfitting patch is rejected; a noisy service causes no false rejection | **done** (`raksha/gate/`, 17 tests) |
| 2 | Java vertical slice + Log4Shell demo target | Log4Shell found, fixed, proven with zero human input, all five gate checks | **done** (`demo-targets/java-log4shell`, `raksha/adapters/java.py`, `raksha/slice_java.py`) |
| 3 | Build-free lanes (supply-chain + secrets, every ecosystem), dependency-bump patch lane | A target that will not build still yields proven findings in seconds, any language | **done** (`raksha/lanes/`, `raksha/slice_buildfree.py`) |
| 3b | Build agent (escalate → degrade), service lane (OpenAPI), jury exporter | build agent degrades to build-free on any failure; service findings; submission export | **done** (`raksha/buildagent.py`, `raksha/lanes/service.py`, `raksha/export.py`) |
| 4 | Sandbox, offline bundle (GPU + CPU variants), cable-pull install, inference interface, air-gap guard | air-gap guard clean; sandbox refuses to run unisolated; bundle verifies/tamper-detects; model-free degrade works | **done** (`raksha/inference.py`, `raksha/airgap.py`, `raksha/sandbox.py`, `raksha/repair.py`, `deploy/`) |
| 5 | Console screens 1, 3, 5; Scorecard live | serves live board/scorecard/detail offline; badges read 0; air-gap guard covers it | **done** (`console/`, `raksha/orchestrator.py`) |
| 6 | C and Python deep slices — three languages on one screen | C (gcc+ASan), Python (shell-injection) and Java each find→fix→prove through the one gate | **done** (`raksha/adapters/c_asan.py`, `python_sink.py`, `raksha/slice_three.py`) |
| 7 | WOW: bad-patch rejection, ROE slider, vaccine | all three real & tested: gate rejects a planted overfit; ROE tiers + two-person rule; vaccine mines→proves→sweeps | **done** (`raksha/roe.py`, `raksha/vaccine.py`, `raksha/slice_wow.py`) |
| 8 | Screens 2/4/6; signed evidence bundle; Commander's Brief (JSSD); rollback; risk register | bundle builds, signs, verifies & tamper-detects; brief + risk + pipeline live in console | **done** (`raksha/bundle.py`, `brief.py`, `risk.py`, `rollback.py`) |
| 9 | Our own numbers; negative controls; licence register | Every number we will say traces to this run | **done** (`raksha/benchmark.py`, `docs/benchmark-report.md`, `THIRD_PARTY.md`) · ARVO loader pending (`HANDOVER.md` P1-8) |
| 10 | Rehearsal harness + health watchdog + runbook (execution needs finale hardware) | harness loops & survives caps; watchdog restarts visibly; runbook ready | **scaffolding done** (`raksha/health.py`, `raksha/rehearse.py`, `docs/rehearsal-runbook.md`) · 36h execution awaits finale GPU/Docker |
| 11 | Automatic harness generation — find→fix→prove on a target with NO hand-written harness | discover entry point → synthesize harness → fuzz → confirm → repair ladder through the gate; C, Python (own mutation fuzzer + fork server) and Go (native `go test -fuzz`) | **done** (`raksha/harness/`, `raksha/autorepair.py`, `raksha/adapters/go_fuzz.py`, `raksha/slice_autofuzz.py`, `raksha/slice_go.py`) |

**The fix-score gap is closed.** The deep find→fix→prove loop no longer needs a human-written
harness: `raksha/harness/` discovers the input-boundary function, synthesizes a driver, proves the
driver with a two-check quality gate, and fuzzes it (our stdlib mutation engine behind a fork
server for C/Python; native `go test -fuzz` for Go). `autorepair.py` then runs the repair ladder —
generic templates (zero inference), the model lane through the one inference interface when
`RAKSHA_INFERENCE_BASE_URL` is set, and a mitigation floor — gating each candidate. Rust remains the
one deep language still on the build-free tier (cargo-fuzz adapter is the next addition behind the
same oracle API).

**Vetted against an external critical review on 2026-10-04** — point-by-point verdict, the five
changes it caused, and what was deliberately rejected: `docs/external-review-vetting.md`.

## Standing constraints

- **No reproducer, no report.** Enforced in the data model, not in review.
- **Nothing unproven ships.** Gate fails → `REPORT_ONLY` — which, per Q4, scores.
- **Zero network egress at runtime, ever.** A console that pulls a CDN font contradicts the pitch.
- **Degrade, don't die.** Every stage's fallback rung is *built*, not described.
- **No pre-promised numbers.** Every figure comes from our own baseline. A judge will ask.
- **Only VERIFIED findings become vaccines.**
- **Their code never leaves the machine**, is never committed here, and is wiped on request.
- **No change to the pipeline after hour 27 of the finale.**
