# RAKSHA AI — Build Plan

**The dossier (`RAKSHA_AI_Dossier/`) is the settled brief. This file is the execution plan.**
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
Tier 2, deep (fuzz + fix): C/C++, Java/Kotlin, JS/TS, Python first; Go (native fuzzing) and Rust
(cargo-fuzz) next because they are cheap to add behind the same oracle plugin API. No language
ever yields nothing.

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
5. **Precision is a data model, not a promise.** Already shipped (`raksha/finding.py`, 62 tests).
6. **The security advisor never vetoes the gate.** Disagreement with the coding model steps ROE
   down to R1; the five mechanical checks alone decide VERIFIED.
7. **Six novelty mechanisms, not seven.** Harness synthesis is TAKE+WRAP with a two-check quality
   gate (compiles, produces coverage) — an instance of "nothing is trusted until it proves itself",
   not a headline. "Five-gate harness synthesis" was deck-v1 language and is retired.
8. **Lane cross-confirmation** promotes a static SUSPECTED finding when another lane's reproducer
   lands on the **same fix site with the same CWE**; the two records **merge** on the dedup key.
9. **The model's regression test must fail on the vulnerable build and pass on the patched one**
   before it enters the bundle or the target's suite.
10. **Differential check = corpus inputs + the target's own test suite.** When a target ships no
    tests, M = 0 is written into the bundle.
11. **The asset registry** (every codebase, its source, its criticality tier) is a BUILD component;
    ROE and the vaccine both depend on it.
12. **Recruit one teammate for the 36 hours**, even non-technical.
13. **Cloud inference during development, behind one interface** (`RAKSHA_INFERENCE_BASE_URL`);
    no model SDK anywhere else; CI grep enforces it. Local vLLM from Phase 4.

## The one rule

> **A criterion you cannot measure is a criterion you cannot score.**
> No component is "done" until it emits the metric that proves it, while it runs.

Given the finale is judged on accuracy, speed and resources, the Scorecard is not UI — it is the
scoring interface. Every stage writes its metric as it runs; the console reads them live.

## Scoring ledger

| Component | Criterion | Metric emitted |
|---|---|---|
| Unified finding record — no reproducer, locked at SUSPECTED | **Precision** | % reports with a replaying reproducer (100% by construction); findings suppressed |
| Status machine + transition timestamps | **Speed** | median time-to-PoV; median time-to-validated-patch; **time to first proven finding** |
| Five-check gate, differential corpus + own tests | **Precision** | % candidate patches surviving; patches rejected; corpus inputs quarantined |
| Lane cross-confirmation | **Precision** | static findings promoted by another lane's reproducer |
| Build-free lanes + dependency-bump patches | **Performance · Speed** | findings in the first 10 minutes; findings produced while the build was failing |
| Repair ladder + calibrated router + bandit reallocation | **Resource** | % fixes at zero inference; tokens per validated patch; live VRAM; inference attempts without a fix |
| CPU-only degrade profile | **Resource** | the whole pipeline running with no model |
| One adapter per language, oracle plugin API | **Scalability** | language coverage matrix; verified per language; targets in parallel |
| ROE authority model | **Functionality** | authority in force per action; zero-human-input count |
| Vaccine sweep over the asset registry | **Scalability** | variants found per verified fix |
| Sandbox, no network interface | Trust | network interfaces: 0; cloud calls: 0 |

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
| 4 | Sandbox, offline bundle (GPU + CPU variants), cable-pull install, local vLLM | Sealed SSD → running in ≤ 20 min, cable out; CPU profile benchmarked | next |
| 5 | Console screens 1, 3, 5; Scorecard live | Beats 2–5 of the arc need no narration; badges read 0 and are true | |
| 6 | C and Python slices — three languages on one screen | One C, Java and Python bug fixed in parallel by the same core | |
| 7 | WOW: bad-patch rejection, ROE slider, vaccine (only if core untouched) | Each beat runs clean 10 times | |
| 8 | Screens 2, 4, 6; Commander's Brief; rollback; risk register | A stranger verifies a bundle signature unaided | |
| 9 | Our own numbers on ARVO / AutoPatchBench; self-score; licence register | Every number we will say traces to this run | |
| 10 | Two full 36-hour rehearsals; record the demo | Second run finishes with no manual intervention | |

## Standing constraints

- **No reproducer, no report.** Enforced in the data model, not in review.
- **Nothing unproven ships.** Gate fails → `REPORT_ONLY` — which, per Q4, scores.
- **Zero network egress at runtime, ever.** A console that pulls a CDN font contradicts the pitch.
- **Degrade, don't die.** Every stage's fallback rung is *built*, not described.
- **No pre-promised numbers.** Every figure comes from our own baseline. A judge will ask.
- **Only VERIFIED findings become vaccines.**
- **Their code never leaves the machine**, is never committed here, and is wiped on request.
- **No change to the pipeline after hour 27 of the finale.**
