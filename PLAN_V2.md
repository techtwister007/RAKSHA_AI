# RAKSHA AI — Plan V2: close every gap, add every feature

**Status:** Waves 0, 1 and 2 built (2026-10-04); Waves 3–4 not started. Per-item status, with
the evidence and the honest caveats, is in the *Wave 1 — status* and *Wave 2 — status* blocks.
**Scope rule:** every item from the two review passes is included — nothing dropped for cost.
Breadth first; optimisation after. This document is the contract we execute from and tick off.

## The six constraints that never move

1. The gate decides what is true; no model ever does. Every new component is a proposer, ranker, detector or annotator.
2. No reproducer, no report.
3. Presence, never absence — the system never says "secure"; every run states its boundary.
4. Offline by construction — stdlib at runtime; tools as subprocesses; any new library ships as a wheel and degrades to a documented fallback when absent.
5. Every number measured, or null — never a flattering zero.
6. Target code never leaves the machine and is never committed here.

## How to read this

Items carry IDs (A1, B2, F10...). Waves are the execution order; workstreams inside a wave
run in parallel on disjoint files. Every item has a **Done** line, which is its acceptance test.

---

## Wave 0 — Foundations (serial, before the parallel waves)

Cross-cutting pieces most later items depend on. Built first and alone so parallel work does not collide on them.

- **W0-1 Event bus + session journal.** An append-only, hash-chained JSONL log of every pipeline event (harness built, crash, candidate judged with its verdict, status change, operator action, red-team round, lane start/finish). `Session.emit(...)` writes it; `Session.resume(path)` rebuilds board and scorecard from it. Feeds the live log, time-lapse, audit trail and crash recovery.
  **Done:** kill the orchestrator mid-run, `resume()` restores an identical board, and the hash chain verifies.
- **W0-2 Crash-signature model.** One canonical signature (bug family + normalised target-owned top frames) shared by dedup, the multi-bug gate, the red team and the fleet roll-up.
  **Done:** two inputs for one defect share a signature; a different site or class does not.
- **W0-3 CWE family table.** Parent/child map (the memory family, the injection family, the weak-crypto family, and so on) so "same family" has one definition.
  **Done:** family lookups group the related codes; existing exact-match callers still pass.
- **W0-4 Profiles as data.** One config file with datacenter / node / edge profiles for every threshold now scattered as a default: refuzz budget, variant count, perf tolerance, hygiene caps, triage cut-offs, per-target budget, minimum-evidence floor. Selected by env.
  **Done:** datacenter reproduces today's numbers; edge runs the slices with smaller budgets.
- **W0-5 Monotonic durations.** Every elapsed-time metric from a monotonic clock; wall-clock only for display timestamps.
  **Done:** a simulated clock jump cannot produce a negative duration.
- **W0-6 Build-flavour seam.** Targets can build a sanitizer flavour or a release flavour, so the deployment twin and the reproducible-build check have a hook.
  **Done:** every adapter accepts the flavour argument with unchanged default behaviour.

**Wave 0 exit:** full suite green; journal-resume test; one profile-switch test; signature and family tests.

---

## Wave 1 — Correctness and accuracy

Five workstreams, parallel. This is where the system becomes trustworthy on real code.

### Wave 1 — status (built; each line names its proof)

All items built. Where an item is weaker than its Done line implies, the caveat is written here.

- **A1–A4, A6** ✔ gate semantics: multi-bug signatures, evidence floor, release-flavour twin, family cross-confirm, verdict feedback — `tests/test_gate.py`, `tests/test_autorepair.py`.
- **A5** ✔ rollback proven by tree hash; `rollback.sh` fails on a non-identical revert — `tests/test_rollback_proof.py`.
- **A7–A9** ✔ UBSan/LSan, hang, metamorphic oracles with demos — `tests/test_new_oracles.py`.
- **A10** ✔ with caveat: the bound claim is now read from the patch's own added lines (C ternary/strncpy, Go slice `min`, Rust `usize::min`); other shapes record `not-modelled`. z3 is not bundled on this box, so every proof here reads `unavailable` — no "proved" is claimed without a solver — `tests/test_proofcheck.py`.
- **B1–B3, B6** ✔ campaign loop, ddmin, benign-corpus harvest, harness attribution + agreement — `tests/test_campaign.py`, `tests/test_minimise.py`, `tests/test_autofuzz.py`.
- **B4** ✔ Python (`sys.settrace`) and Node (V8 block coverage) measure executed lines; Rust and Java remain a stated method-span heuristic — `tests/test_coverage_b4.py`.
- **B5** ✔ Java with no harness: discovered entry point, synthesized driver, batch fuzzing in one JVM, in-JVM refuzz, `java_bound_index` template; the demo reaches VERIFIED through all five checks — `tests/test_java_driver.py`.
- **B7** ✔ a direct-call crash is held SUSPECTED only when the function states a precondition *and* no input-facing caller reaches it; an exported API with no callers is still reported — `tests/test_contract.py`.
- **B8** ✔ every name in the target's tree is per run; helper files ship as code only; build paths mapped out of debug info — `tests/test_anti_analysis.py`.
- **B9** ✔ coverage-targeted red-team pass — `tests/test_redteam.py`.
- **B10** ✔ binary lane: Go build-info and jar `pom.properties` versions matched to advisories (verified on the real log4j-core 2.14.1 jar), native banners SBOM-only, MD5/SHA-1/DES/RC2 implementation presence at `info` — `tests/test_binary_lane.py`.
- **B11** ✔ LD_PRELOAD interposition blocks `system`/`exec*`/`popen` before they run — `tests/test_interpose.py`.
- **B12** ✔ with caveat: behavioural baseline via an LD_PRELOAD observe shim (no ptrace); flags a traversal and an exec, zero findings on the fixed build and on Python interpreter noise. A static binary or raw syscalls bypass it — `tests/test_behaviour.py`.
- **C1–C8** ✔ transitive deps, unpinned boundary, git-history secrets, VEX, fleet roll-up, KEV/EPSS, reproducible build, IaC floor — `tests/test_supplychain_v2.py`, `tests/test_wave1_core2.py`.
- **D1–D7, D9–D11** ✔ authority cap, deploy grade, large reproducers, resource metrics, signed journal, purge, model card, SBOM, PQ signature (HMAC fallback), in-toto attestation — `tests/test_phase8.py`, `tests/test_evidence.py`, `tests/test_trust.py`, `tests/test_journal.py`.
- **D8** ✔ `docs/threat-model.md`: sixteen surfaces, each mapped to a built control and its test, plus residual risks.
- **E1** ✔ campaigns checkpoint every round; a run killed mid-campaign resumes with its proven findings — `tests/test_campaign.py`.
- **E2, E4–E7** ✔ parallel ingest, change report, persistent memory, signed update path, feedback demotion — `tests/test_campaign.py`, `tests/test_wave1_core2.py`, `tests/test_trust.py`.
- **E3** ✔ the per-target budget ends a campaign with an honest note and keeps what it found — `tests/test_campaign.py`.
- **E8** ✔ scaffolding only, as specified: curates (context, diff) pairs from VERIFIED, gate-passed findings and refuses the rest; trains nothing; never called by the pipeline — `tests/test_training.py`.

**Found and fixed during close-out (not in the plan):** the fuzzing hot loops spawned target code
outside the sandbox door — in the deployed layout, inside the container that holds the
container-runtime socket. Every spawn of target code now goes through one door, enforced by an AST
test (`tests/test_sandbox_door.py`).

### Workstream A — Gate semantics that survive a real codebase

- **A1 Multi-bug gate semantics.** The clean checks pass when the fixed signature is dead and no signature appears on the patched build that was absent on the vulnerable one. Any other signature already present becomes a new confirmed finding, not a failure of this patch.
  **Done:** a three-bug demo verifies fix 1 while 2 and 3 surface as findings; a patch adding a new crash still fails.
- **A2 Minimum-evidence floor.** When stable corpus inputs after preflight fall below the profile floor, the verdict is report-only with reason "insufficient behavioural evidence"; the differential strength is recorded on every gate record and the scorecard.
  **Done:** a target that quarantines its whole corpus cannot reach verified.
- **A3 Deployment twin.** After the checks pass on the sanitizer build, re-run the kill-check and the differential once on a release-flag build; record it; fail closed if the twin diverges.
  **Done:** a target whose release build misbehaves is rejected; the C demo passes both.
- **A4 Cross-confirm on CWE family** (uses W0-3).
  **Done:** the structural memory-family hypothesis on the C demo is promoted by the sanitizer reproducer; the "promoted" metric is non-zero for C.
- **A5 Rollback proof.** Rollback records tree hashes; verification asserts the rolled-back tree equals the original; the result rides in the bundle.
  **Done:** apply, roll back, assert equality; a tampered rollback fails.
- **A6 Verdict feedback to the model.** A failed candidate's next prompt carries the failed check, its one-line reason, and one mismatching input pair; rounds become a conversation within the round cap.
  **Done:** a mock-client test shows round two's prompt contains round one's failure detail.
- **A7 Two more sanitizers.** Undefined-behaviour and leak builds, with an oracle that parses their reports to the right families, plus a demo for each.
  **Done:** each demo found and fixed through the gate.
- **A8 Hang / resource-exhaustion oracle.** An input far over the median run-time, or over the hard timeout, becomes a resource-exhaustion finding (regex-at-top-frame maps to the catastrophic-backtracking class); replay runs under a timeout.
  **Done:** a slow-regex Python demo and a C infinite-loop demo are found; a benign slow input is not.
- **A9 Metamorphic oracle.** A small set of relations per entry kind (padding-invariance, round-trip, idempotence) run during fuzzing; a violated relation is a finding carrying both inputs.
  **Done:** a padding-sensitive parser demo is found; the brief's "metamorphic" claim becomes true.
- **A10 Machine-checked bound proofs.** When the solver wheel is present, every bound-clamp template emits an obligation that the clamp stays within the buffer for all inputs, checked by the solver; recorded as proved / refuted / null when the solver is absent.
  **Done:** the C, Go and Rust bound fixes carry "proved"; a deliberately wrong clamp reads "refuted".

### Workstream B — The find loop: depth, honesty, breadth

- **B1 Campaign loop.** One target runs find → fix → prove → re-fuzz the patched tree → next finding, until clean or the per-target budget is spent; siblings are harvested by A1.
  **Done:** the three-bug demo yields three verified fixes in one campaign; budget exhaustion ends with an honest count.
- **B2 Input minimisation.** Deterministic delta-debugging shrinks every crashing input before it is confirmed; the record carries before/after sizes and marks it minimised.
  **Done:** the C reproducer shrinks to its minimal crashing length with the signature unchanged.
- **B3 Corpus harvesting.** Non-crashing inputs the fuzzer ran, the target's own test inputs where found, and minimised crashers of other signatures feed the differential corpus automatically.
  **Done:** slices run with no hand-supplied corpus and still reach a healthy stable-input count.
- **B4 Real coverage for Python and Node.** Line coverage from the language's own facility in the harness, replacing the echo heuristic; Rust stays heuristic with the limitation stated.
  **Done:** coverage-held on those lanes uses real executed lines; a delete-the-function patch fails.
- **B5 Synthesized Java driver.** Discover the public static entry points and synthesize a driver, so Java needs no hand-written harness either.
  **Done:** a no-driver Java demo reaches verified; "six languages, no harness" has no asterisk.
- **B6 Harness attribution + second-wrapper agreement.** A crash whose top owned frame is inside our harness is dropped as ours; a crash must reproduce under a second, differently-shaped wrapper before it is confirmed.
  **Done:** the buffer-mismatch false positive we hit in development is rejected automatically.
- **B7 Contract-violation demotion.** When the structural lane finds no input-facing path to the entry point and the function states a precondition, a direct-call crash stays suspected with that reason.
  **Done:** a library function guarded by a precondition, fuzzed directly, is not reported; the same bug reached from a handler is.
- **B8 Anti-analysis hygiene.** Randomised harness and file names per run; no fixed product string in the sandboxed tree.
  **Done:** a grep of the scratch tree finds no fixed marker.
- **B9 Coverage-targeted red team.** Red inputs are preferred when their coverage reaches the fix site by a path the corpus misses.
  **Done:** on the shallow-fix demo the red team wins in fewer attempts than a blind campaign.
- **B10 Binary lane (build-free).** For a compiled artifact with no source: strings, embedded version detection, crypto-constant detection, and an SBOM, each a deterministic finding with a replay.
  **Done:** a stripped demo binary yields an embedded-version finding that replays.
- **B11 Sink interposition for binaries.** A small preload shim that turns the key runtime sinks into aborts, extending the sink-invariant idea to compiled targets with no source.
  **Done:** a demo binary that reaches a dangerous sink aborts and is confirmed with a reproducer.
- **B12 Behavioural baseline.** Per-target observation of files, sockets and processes touched on benign inputs; a rare input that touches something new is an anomaly finding.
  **Done:** a demo whose odd input opens a socket is flagged; benign runs are quiet.

### Workstream C — Build-free accuracy and the supply chain

- **C1 Transitive dependencies.** Resolve the full dependency tree offline where the ecosystem allows it (lockfiles, and the package manager's own tree command against a warm cache), so a vulnerable library pulled in indirectly is found.
  **Done:** a demo whose vulnerable dependency is transitive is flagged; the direct-only path still works.
- **C2 Unpinned ranges on the boundary.** A dependency whose version is an open range is not flagged as vulnerable, but is listed in the assurance boundary as "exposure unknown: unpinned".
  **Done:** an open-range dependency shows on the boundary, not as a finding and not silently gone.
- **C3 Git-history secrets.** Scan prior commits, not only the working tree; a credential removed last commit is still found, with the commit as its location.
  **Done:** a secret deleted in the last commit is found in history; a never-committed secret is not.
- **C4 VEX statements.** Emit the standard not-exploitable / not-present / under-investigation justifications for dependency findings, from our reachability output, in the format procurement reads.
  **Done:** a "present, not imported" dependency produces a valid VEX statement in the bundle.
- **C5 Fleet roll-up.** One defect across many repositories folds into a single finding with N locations, distinct from the vaccine's variant search.
  **Done:** a vendored library duplicated across demo repos shows as one finding with a location list.
- **C6 KEV and EPSS offline snapshots.** Small carried datasets marking which dependency findings are known-exploited and their exploit-likelihood, feeding the risk ranking.
  **Done:** a known-exploited dependency outranks an equal-severity one that is not; the snapshot date is shown.
- **C7 Reproducible-build check.** Build an artifact twice and compare; non-reproducibility is a supply-chain signal.
  **Done:** a non-deterministic demo build is flagged; a deterministic one is not.
- **C8 Config / infrastructure-as-code floor.** Our own deterministic checks for the common container and service misconfigurations, independent of any external tool.
  **Done:** a demo with a root container and an open port yields findings that replay.

### Workstream D — Policy, trust and the record

- **D1 Model-patch authority cap.** Any patch from the model lane is capped at a tier that requires human sign-off; it is never deployed autonomously. Stated as a rule, enforced in the authority model, shown on the record.
  **Done:** a verified model-lane fix shows "awaiting human approval"; a template fix on a low tier may be autonomous.
- **D2 Deploy-readiness grade.** Roll the existing evidence (own-test count, stable inputs, perf ratio, red-team attempts held, twin checked, bound proved) into an A/B/C grade with the reasons listed.
  **Done:** each verified finding shows a grade and the factors behind it.
- **D3 Large-reproducer handling.** A reproducer over the inline cap is compressed or shipped as a sidecar and always replayable — never silently omitted.
  **Done:** an over-cap reproducer still replays from the bundle.
- **D4 Per-finding resource metrics.** CPU-seconds, peak memory and, where the counters are exposed, energy per verified fix, on the scorecard.
  **Done:** each verified fix shows its cost; absent counters read null.
- **D5 Audit trail of the run.** The journal (W0-1) signed and shipped: operator actions and autonomous decisions, not just findings.
  **Done:** the run's signed journal verifies and lists who/what did each action.
- **D6 Reproducer handling policy.** Reproducers at rest are encrypted or purgeable on the node by policy; the policy is stated and enforced.
  **Done:** a purge command removes reproducer bytes while leaving the signed record intact.
- **D7 Model blind-spot card.** An on-box evaluation of the carried model that produces its own weakness card before the pipeline trusts it.
  **Done:** the card is generated offline and stored with the run.
- **D8 Self threat-model document.** A one-page threat model of RAKSHA itself — untrusted targets, the model, the transfer path — each with its mitigation.
  **Done:** the document exists in the dossier and maps each surface to a built control.
- **D9 SBOM of RAKSHA itself.** A standard component bill for our own system.
  **Done:** a valid SBOM is generated and shipped.
- **D10 Post-quantum bundle signatures.** Sign evidence bundles with a quantum-safe signature where the library is present, with the current signature as fallback.
  **Done:** a bundle carries a quantum-safe signature that verifies; the fallback path still verifies.
- **D11 Standard attestation format.** Provenance expressed in the recognised supply-chain attestation format, not only our own signature.
  **Done:** the bundle carries an attestation a standard verifier accepts.

### Workstream E — Scale, endurance, continuity

- **E1 Crash recovery and resume.** Built on the journal: a killed run resumes where it stopped.
  **Done:** covered by W0-1's test, plus a mid-campaign kill-and-resume.
- **E2 Parallel ingest.** Several targets ingested at once, each in its own sandbox, bounded by a worker count in the profile.
  **Done:** a multi-target estate ingests concurrently with identical results to serial; worker count respected.
- **E3 Per-target budget with graceful stop.** A pathological target cannot consume the whole run; when its budget is spent it ends with "ran out, here is what we have".
  **Done:** a deliberately expensive demo stops at its budget and still reports what it found.
- **E4 Continuous mode.** A re-run on a schedule with a "what changed since last run" diff report.
  **Done:** a second run over an unchanged estate reports no change; a planted new bug appears in the diff.
- **E5 Persistent learning.** Fix memory and vaccine rules persist to the evidence root and reload at start, so stage nine survives a reboot.
  **Done:** a fix learned in one run is used at zero inference in a fresh process.
- **E6 Signed update path for RAKSHA itself.** A new rule set, dependency database or version reaching a sealed node arrives as a signed manifest with rollback, the same discipline as the first install.
  **Done:** an unsigned update is refused; a signed one applies and can be rolled back.
- **E7 Human feedback loop.** An operator marking a shipped fix wrong flows back into the memory and the vaccine.
  **Done:** a thumbs-down on a finding demotes its learned shape; the next identical case is not auto-fixed.
- **E8 Gated on-box fine-tuning (optional, GPU).** Training only on gate-verified (context, diff) pairs, so the data is clean by construction; off by default, behind a flag, with the blind-spot card re-run after.
  **Done:** a dry-run assembles only verified pairs and refuses any unproven data; the step is documented as optional.

---

## Wave 2 — Intelligence and reasoning upgrades

### Wave 2 — status (built; each line names its proof)

- **G1** ✔ `raksha/reachproof.py`: the guards at the fix-site access are read before and after the patch and z3 asked whether the index can leave bounds. The Java no-harness fix records before = reachable (with the solver's own witness) and after = unreachable; an off-by-one "fix" is seen through. Evidence only; premises (no overflow modelling) on the record — `tests/test_reachproof.py`. z3 is now a declared `[reasoning]` extra baked into the sealed image.
- **G2** ✔ `RAKSHA_GUIDED_DECODING=json_schema|vllm|off`: a fixed `{diff, regression_test}` schema rides the request; replies are parsed strictly and well-formedness checked; off, the tolerant parser runs; both counted on the scorecard. Caveat: tested end-to-end against a loopback stub — request shape and parsing are proven, a real constrained decoder is not exercised here — `tests/test_guided.py`.
- **G3** ✔ cross-language retrieval of a proven fix's *idea*: the C CWE-121 clamp is retrieved for the Go CWE-125 slice finding (similarity 0.58) and realised as a correct Go diff; provenance on the record, worked example to the model lane. Caveat: no embedding model is bundled — the default vector is a stated structural (non-learned) one; a served `/v1/embeddings` model is used when configured — `tests/test_crosslang_retrieval.py`.
- **G4** ✔ specialist, second opinion and attacker each vote independently; disagreement measured per axis and per pair; roles on one model flagged as not independent; offline stays unmeasured — `tests/test_parliament.py`.
- **G5** ✔ every finding's record carries its hypothesis → experiment → observation → conclusion cycles (detection, each repair round, proofs, red team), drawn only from recorded events; the brief carries a Method line — `tests/test_method.py`.
- **G6** ✔ `python -m raksha.calibrate --deep` measures each fusion channel on a labelled corpus (`raksha/data/groundtruth.json` + negative controls) and the kernel uses the posterior; the table (prior, n, TP/FP, Wilson 95%, calibrated, bands) is committed in `raksha/data/calibration.json` and on the scorecard. Parliament has no data and stays at its prior, marked uncalibrated; structural is flagged in-sample. Dependency attack steps are priced by KEV/EPSS; reachability costs stay stated priors. Caveat: small curated corpus — a measured baseline, said so in the table — `tests/test_calibration.py` (also a standing zero-false-positive guard over the corpus).
- **G7** ✔ derived, labelled CVSS 4.0 vector (score not computed: FIRST's MacroVector table is not bundled), CVSS 3.1 vector with its exact base score (checked against FIRST reference vectors), ATT&CK technique IDs and the D3FEND tactic of the fix; in the proof block, SARIF `security-severity`, the brief and the scorecard — `tests/test_cvss.py`.

**Found and fixed during Wave 2 (not in the plan):** labelling the calibration corpus exposed three
false-positive sources — the git-history lane walking the *enclosing* repository when the target is a
subdirectory, the C taint match reading string literals (a tainted `n` matched `"\n"`), and copies
into a buffer allocated for exactly that length. All fixed with regression tests.


Built after the gate is trustworthy, because each only proposes or ranks.

- **G1 SMT-backed reasoning lane.** Beyond the bound proofs (A10): a general constraint lane that, for a localised finding, asks the solver whether a guard makes the dangerous state unreachable, recorded as evidence, never as the decider.
  **Done:** one demo fix carries a solver-checked unreachability result; the gate still decides.
- **G2 Grammar-constrained model output.** When the endpoint supports guided decoding, constrain the model to emit only a well-formed diff or the expected structured object.
  **Done:** with guidance on, parse failures drop to zero on a fixed prompt set; without it, the tolerant parser still runs.
- **G3 Offline code-embedding retrieval.** A small carried embedding model lets a fix learned in one language be retrieved for its cousin in another; falls back to today's syntactic retrieval when absent.
  **Done:** a C bound fix is retrieved as a candidate for an analogous Go finding.
- **G4 Richer model parliament.** Add the independent-attacker and second-opinion roles to the vote where an endpoint serves them; disagreement still only raises scrutiny.
  **Done:** with three roles served, disagreement is measured across them; offline it stays null.
- **G5 Scientific-method loop surfaced.** Make the hypothesis → experiment → observation → conclusion cycle explicit on the record for each finding, drawn from events that already happen.
  **Done:** each finding's record shows the cycle; the brief's language matches the build.
- **G6 Calibrated fusion and attack-graph weights.** Replace the hand-picked constants with values calibrated against the benchmark, and show the calibration table.
  **Done:** the confidence bands are backed by a measured table, not asserted numbers.
- **G7 CVSS 4.0 vectors and technique mapping.** Derive, deterministically and labelled as derived, a severity vector and an attack-technique / defence mapping per finding.
  **Done:** each finding carries a vector and a technique id; a judge sees the language of a cyber cell.

---

## Wave 3 — UI / UX and the operator

The console stops being a read-only board and becomes the thing a human runs.

- **F1 Live event log.** A timestamped narrative stream from the journal: harness built, crash, candidate failed a named check with its reason, candidate verified. Autonomy made legible.
  **Done:** the demo run's story reads top to bottom on screen with no terminal.
- **F2 Attack-graph visual.** The chains drawn as a graph with the cheapest path lit, edges labelled with their rule and marked heuristic.
  **Done:** the estate's chains render; hovering an edge shows its reason.
- **F3 Side-by-side proof.** The reproducer firing on the vulnerable build next to the same input silent on the patched build, as a screen element.
  **Done:** the detail screen shows both panes for a verified finding.
- **F4 Gate strip.** The five checks (and the twin, and the bound proof) as tick/cross tiles with timings and the one-line reason each.
  **Done:** the strip renders for any gated finding.
- **F5 Assurance-boundary visual.** Bars for per-language exploit / build-free / none, targets built vs degraded, suspected vs reported.
  **Done:** the boundary renders as bars, not a paragraph.
- **F6 Post-quantum screen.** The crypto inventory and migration list shown: which file, which primitive, which replacement, the blast-radius.
  **Done:** the screen renders from the live report.
- **F7 Operator actions.** Approve, reject, re-run the red team, export the bundle, and mark a false positive with a recorded reason — each an action, each journalled.
  **Done:** each action works offline and appears in the audit trail.
- **F8 Search, filter, sort** on findings by language, status, severity, lane, asset tier.
  **Done:** usable at several hundred findings.
- **F9 Estate map.** A tier-grouped board or treemap by asset tier against status, with the top-three risks pinned.
  **Done:** the map renders and the top three are correct.
- **F10 Full bilingual brief.** The Commander's Brief switchable English / Hindi in full, not just the headline; key console labels bilingual.
  **Done:** the toggle swaps the whole brief; the glossary drives it.
- **F11 Projector / high-contrast mode.** A high-contrast theme toggle for a hall projector.
  **Done:** every screen stays legible in the high-contrast theme.
- **F12 Export and help.** Brief to PDF, findings to a spreadsheet, a shortcut-help overlay, and a guided empty state on a fresh node.
  **Done:** each export produces a valid file; the help overlay lists the real shortcuts.
- **F13 Two voices per finding.** A staff-officer rendering and an engineer rendering of the same record, both drawn from the facts.
  **Done:** both views render and agree on the facts.
- **F14 Lane trust on screen.** Beside each new finding, that lane's measured record on this estate (findings, disputed).
  **Done:** the figure accumulates live as findings land.

---

## Wave 4 — Jury, product and the edge

- **J1 The "it says no" demo beat.** A scripted sequence where, live, a shallow fix dies at the gate, an unsafe model diff is refused, and the red team breaks a weak patch — refusal as the trust-maker.
  **Done:** the sequence runs on the console, repeatably, inside a minute.
- **J2 Bring-your-own-target intake.** A judge's media goes in and time-to-first-finding ticks on screen; the intake path is bulletproof and bounded.
  **Done:** an unseen target ingests and shows a first finding without a restart.
- **J3 Real ARVO numbers.** A set of real cases run on a prep machine, published with an honest win/loss table.
  **Done:** the benchmark report carries real-case rows with losses listed.
- **J4 Baseline comparison.** The same targets through a static tool alone and a plain model alone, against RAKSHA, one table on the measure that matters: reports carrying a reproducer.
  **Done:** the comparison table is generated from a real run.
- **J5 Recall answer.** Measure recall on the mutation factory and the benchmark and state it, rather than only declining to claim it.
  **Done:** a recall figure with its method is in the report.
- **J6 Air-gap beat, rehearsed.** Pulling the cable live, with the egress counter visibly at zero, scripted into the demo.
  **Done:** the beat is in the runbook and rehearsed.
- **J7 Self-contained verifier media.** The bundle plus a portable runtime so a judge replays a finding on their own laptop in under a minute.
  **Done:** replay works on a clean machine with nothing pre-installed beyond the runtime.
- **J8 Internal-CERT advisory.** One verified fix produces a signed internal advisory with an id, affected assets and the proven patch — the product framing.
  **Done:** an advisory is generated from a verified finding and verifies.
- **J9 Time-lapse of the run.** Scrub the journal to see what the system was doing at any hour.
  **Done:** the time-lapse replays a recorded long run.
- **J10 The claim audit.** Reconcile the submitted brief with the build line by line: build what is cheap to build, reword what is not, so no sentence in the brief lacks a feature behind it.
  **Done:** every claim in the brief maps to a built, demonstrable capability, or is reworded; recorded in the dossier.
- **J11 Deck and dossier refresh.** Fold every capability above into the deck and dossier once built.
  **Done:** deck and dossier describe the system as it then stands, with no stale claim.

---

## Execution model

- **Sequence:** Wave 0 serial. Then Waves 1 and 2 by workstream in parallel, each on disjoint files, each reporting green with its own tests before its lane is wired into the orchestrator, scorecard, console, CLI and benchmark in a single integration step per lane. Wave 3 after the data it renders exists. Wave 4 last, since it presents everything else.
- **Shared files** (oracle registry, orchestrator, metrics, console, buildfree walk, CLI, benchmark) are integration-only: workstreams deliver self-contained modules; integration is done once per lane by one hand to avoid collisions.
- **Every item** lands with its tests, pyflakes clean, the air-gap guard clean, and a commit that names its ID. The full suite must stay green at each commit.
- **New dependencies** (the solver, the embedding model, a quantum-safe signer) are optional imports: present in the sealed bundle, absent on the build box, and every path that uses one degrades to a documented fallback with the metric reading null rather than failing.
- **Honesty gates:** negative controls stay at zero false positives after every data or lane change; no claim is added to any document before the capability behind it is green.

## Done, for the whole plan

Every ID above is ticked with its test passing; the submitted brief has no sentence without a
feature behind it; the console runs a full find-fix-prove campaign on an unseen target, live and
offline, with the gate visibly refusing bad fixes; and the evidence bundle replays on a judge's
own machine. What remains after that is only the P0 items that need the finale hardware itself
(the long rehearsals, Docker, a GPU-served model, physical media), tracked in HANDOVER.md.
