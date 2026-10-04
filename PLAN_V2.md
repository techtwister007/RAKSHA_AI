# RAKSHA AI — Plan V2: close every gap, add every feature

**Status:** Waves 0, 1, 2, 3 and 4 built (2026-10-04); J3 reworded (see its line). Wave 5 built except K21, K24, K30 (to be built by the team — see the Wave 5 status block). Per-item status, with the
evidence and the honest caveats, is in the *Wave 1 / 2 / 3 — status* blocks and the Wave 4 — status block below.
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

### Wave 3 — status (built; each line names its proof)

The console is served offline by `console/server.py` (stdlib http.server), one self-contained
`index.html` + `app.js`, no external asset; verified end to end in a headless browser (every screen
renders, no page errors) and by `tests/test_console_wave3.py` + `tests/test_console.py`.

- **F1** ✔ live event log: the Session keeps a bounded event stream and emits story events through the pipeline; `console_api.narrate` turns each into a line with a level; the Event Log screen reads top to bottom.
- **F2** ✔ attack graph drawn as inline SVG, cheapest path lit, each edge hovering its rule (marked heuristic).
- **F3** ✔ side-by-side vulnerable-fires / patched-dead panes on the detail screen (engineer voice).
- **F4** ✔ the five-check gate as tick/cross tiles with each check's one-line reason, plus the deployment-twin and the solver (reachability / bound) proofs as extra tiles.
- **F5** ✔ the assurance boundary as stacked bars (exploit vs build-free languages, built vs degraded targets, reported vs suspected), with the boundary statement verbatim below.
- **F6** ✔ post-quantum screen: the crypto inventory summary and the per-file / per-primitive / replacement migration table, from the live PQC report.
- **F7** ✔ operator actions — approve, reject (demotes the fix shape), mark false positive (records a dispute, never changes status), re-run the red team, export the bundle — each recorded on the finding, in the hash-chained journal and the event stream; POST routes guarded by a per-process token.
- **F8** ✔ search, and filter/sort by language, status, severity and lane, over the finding list.
- **F9** ✔ estate map grouped by asset tier against status, with the top three risks pinned.
- **F10** ✔ full bilingual Commander's Brief from a Hindi glossary (facts verbatim, prose translated); EN/HI toggle swaps the whole brief and the console labels.
- **F11** ✔ a high-contrast projector theme toggle; every screen stays legible.
- **F12** ✔ CSV / xlsx (valid Open XML, stdlib zip+XML) / PDF (hand-built, single font) exports and a keyboard-shortcut help overlay listing the real shortcuts.
- **F13** ✔ a staff-officer and an engineer rendering of the same finding, both from the record and agreeing on the facts.
- **F14** ✔ each finding shows its lane's measured record on this estate (findings / proven / disputed), accumulating live.

Caveat: the PDF export is Latin-only (a Devanagari font blob is deliberately not carried), so the
Hindi brief is offered as on-screen text, not PDF.


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

### Wave 4 — status (2026-10-04)

- **J1 ✓** `raksha/saysno.py`; the four beats run on the real C gate, hygiene and red team, as
  scripted in ~25s; console *Demo Beats* screen; test `test_saysno_beat_is_as_scripted`.
- **J2 ✓** `raksha/intake.py`; allow-listed, bounded, link-refusing staging; off-thread scan merged
  under the session lock; time-to-first-finding measured (4s on the estate in the UI check).
- **J3 — reworded.** The runner that executes real ARVO/OSS-Fuzz cases through the pipeline was not
  built in this environment. The loader seam (`raksha/benchmark_arvo.py`) and the honest offline
  state (no manifest ⇒ 0 cases, stated) stand; J4/J5 run on the bundled set and the mutation
  factory. Recorded in `docs/claim-audit.md`; the brief quotes no real-ARVO number not produced.
- **J4 ✓** `raksha/baseline.py`; static-vs-RAKSHA table on reports-with-reproducer, in the
  benchmark report. The plain-model arm is recorded as not-run, with why.
- **J5 ✓** `raksha/recall.py`; 100% on the mutation factory, 54.5% on fuzzable demo ground truth,
  misses named; in the benchmark report.
- **J6 ✓** `airgap.egress_counter`; console *Demo Beats* screen; scripted in the rehearsal runbook;
  test `test_egress_counter_reads_kernel_counters`.
- **J7 ✓** `raksha/verifiermedia.py` + `raksha/data/verify_standalone.py`; self-verified with only a
  shipped runtime; fire/dead replay; test `test_verifier_media_builds_and_self_verifies`.
- **J8 ✓** `raksha/advisory.py` + `Session.issue_advisory`; signed, sequential-id, verifies, tamper
  detected; test `test_advisory_issued_and_verifies`.
- **J9 ✓** `raksha/timelapse.py`; verified-journal scrub; shipped 16-min recording
  (`docs/runs/longrun.jsonl.gz`); console *Time-lapse* screen; tests in `test_wave4.py`.
- **J10 ✓** `docs/claim-audit.md`; every claim reconciled to a built capability or reworded.
- **J11 ✓** benchmark report (J4/J5), dossier `08_wow_factors.md` (Wave 4 additions, Hindi-PDF
  reworded), rehearsal runbook (three scripted beats).

## Wave 5 — Project memory, self-learning and the owner's view

The system already finds, fixes and proves. Wave 5 makes it *remember*: every project gets an
identity and a signed, versioned history; recurring faults become guideline proposals for ACG; new
frameworks are learned under probation; and each project owner — developer, commander or auditor —
can see their application's security, colour-coded, whenever they want.

**Ground rules that bind every item below (unchanged from the rest of the plan):**
learning may *propose*, only the gate *decides*; nothing learned is trusted until a gate-verified
case proves it; every lesson records where it came from and a human can roll it back; all learning
and reporting stays on the box; every number is measured or null; colour is never the only signal
(an icon or a word always accompanies it, for colour-blind readers and the projector theme).

### Tier 1 — project identity and versioned reports (build first: highest value, builds on the journal and bundles)

- **K1 Project identity.** A stable ID per project (name, owner unit, asset tier from the registry, a fingerprint of its code), the same across runs and paths; a project registry on the box.
  **Done:** the same project scanned twice from different paths gets the same ID; a different project never does.
- **K2 Versioned session report.** Each run of a project produces Report vN: found, fixed-and-proven, open, and a severity summary, signed and chained to v(N-1) like the journal so no finding can silently drop between versions.
  **Done:** v2 verifies against v1's hash; removing a finding from v2 by hand fails verification.
- **K3 The v(N-1) → vN diff.** 🟢 fixed since last (reproducer proven dead), 🔴 new since last (incl. anything a patch introduced), 🟠 still open (with runs-open count), 🔵 needs a human; one trend line ("Critical 3 → 1").
  **Done:** a patched re-run shows its fixes green, a newly introduced defect red, and the trend line computed from the records.
- **K4 Needs-a-human list.** Every item RAKSHA cannot or may not close itself, each with its reason (credential rotation, policy decision, gate could not certify, ROE recommend-only on a critical asset) and a checklist; marking one done triggers an automatic re-check.
  **Done:** each reason class appears with its checklist; a marked-done item is re-verified on the next run, not taken on trust.
- **K5 Owner's self-service view.** A per-project console page the owner opens any time: current state, version history, drill-down to any finding (plain-language by default, engineer view on request), colour-coded, with icons beside colour.
  **Done:** an owner reaches any past version and any finding in two clicks; the page passes the high-contrast and colour-blind check.
- **K6 One-page summary.** A print- and phone-friendly colour summary per version, in English and Hindi.
  **Done:** the summary renders on a phone width and prints to one page; Hindi matches the console glossary.

### Tier 2 — self-learning and recurring-fault analysis

- **K7 Recurring-fault analytics.** Across sessions and projects: faults by family, language, framework, component and owner unit; recurrence after fix (regressions); trends over time.
  **Done:** a seeded history yields the correct recurrence counts and flags a re-introduced fixed fault as a regression.
- **K8 Guideline proposals for ACG.** The analytics turned into ranked draft guidelines: the rule, the evidence count, anonymised real examples, and the proven fix pattern — proposed, never adopted, until a human in ACG approves.
  **Done:** a draft pack is generated from real history, each rule traceable to its findings; nothing changes RAKSHA's behaviour until approved.
- **K9 Learning for new technology.** Unknown frameworks and libraries are logged as "unfamiliar surface"; candidate lessons (a new entry point to fuzz, a new dangerous call, a new fix template) are proposed, held on probation, promoted only after gate-verified cases, and demoted automatically when they cause false alarms.
  **Done:** a probationary lesson is promoted after N verified cases and demoted after a false positive on a negative control; each step is in the record.
- **K10 Learning-health dashboard.** What has been learned, what is on probation, what was demoted and why, who approved each promotion, and a one-click rollback.
  **Done:** every lesson shows its provenance; a rollback restores prior behaviour, proven by re-running the case.
- **K11 Poisoning defence.** Learning reads only gate-verified outcomes; a lesson learned from one project is not applied to another until it proves itself there; an outlier source is quarantined.
  **Done:** a crafted project that tries to teach a bad fix pattern cannot get it promoted.

### Tier 3 — the commander's and ACG's view

- **K12 Mission-impact view.** Findings grouped by the operational function they put at risk (communications, logistics, command systems), from the asset registry, not by CWE.
  **Done:** every finding on a registered asset lands under its mission function; unregistered ones are shown as such, never guessed.
- **K13 Exposure-days.** How many days each serious weakness stayed open on each asset, by tier; fix-time against a tier-set deadline (SLA).
  **Done:** computed from the versioned history; a fix closes the clock on the run that proves it.
- **K14 Estate heat-map over time.** The estate as a grid of projects coloured by posture, with a time slider (reuses the time-lapse).
  **Done:** the slider shows the estate as it stood at any past report version.
- **K15 Readiness certificate.** A signed statement per project version ("as of v7: no open critical, all fixes proven, N items awaiting a human") fit for a deployment-approval file, verifiable with the verifier media.
  **Done:** issued only when its conditions hold from the records; verifies on a clean machine.
- **K16 Posture score.** One number per project with a trend, explained by what drives it — measured, never invented; null when there is too little evidence.
  **Done:** the score's breakdown sums to the score; it reads null below the evidence floor.

### Tier 4 — catching risk earlier

- **K17 Attack-surface drift.** Alert when a new version adds a network listener, file upload, new external dependency or new privileged call — before any bug is found.
  **Done:** a version that adds a socket listener is flagged on its first run.
- **K18 Live component inventory.** Every library in every scanned project; when the offline advisory database is updated, every affected project is re-checked and its owner told "newly affected".
  **Done:** a database update flags exactly the projects carrying the affected versions.
- **K19 Secrets hygiene tracker.** Leaked credentials found, rotated or not, and days exposed.
  **Done:** a rotated secret closes on the run that no longer matches it.
- **K20 Pre-merge mode.** A lightweight check developers run before merging, stopping known patterns (including approved ACG guidelines) before they ship.
  **Done:** a change re-introducing a known fault is stopped with the guideline that covers it.

### Tier 5 — learning, trust and usability extras

- **K21 Why-is-this-risky explainer.** For each finding: how an attacker would reach it, what they would gain, what the fix changes — plain language and Hindi, generated from the record, never speculative.
  **Done:** every explainer cites the record fields it was built from.
- **K22 Before/after fix view.** Side-by-side diff of every proven fix, so developers learn the pattern.
  **Done:** shown for every verified finding with its gate result beside it.
- **K23 Knowledge base.** Every verified fix searchable ("how did we fix this last time?").
  **Done:** a search by fault family or component returns the past proven fixes with their bundles.
- **K24 Ask-about-my-project (offline).** Questions answered only from the project's own signed reports, with the source report cited; "not in the record" when it is not.
  **Done:** every answer cites a report version; an unanswerable question says so.
- **K25 Role-based views.** Developer (code), commander (mission impact), auditor (proof chain) — the same data, three renderings.
  **Done:** each role sees its view; none sees a fact the record does not hold.
- **K26 Team scorecard.** Per team, privately: their most repeated faults and short lessons — framed as support, not blame.
  **Done:** visible only to that team and its chain; built only from the records.
- **K27 Digest and change alerts.** A weekly per-owner summary and a short notice when a new run differs from the last.
  **Done:** a run with no change sends no alert; a run with a new critical does.
- **K28 Compliance pack.** The quarter's signed versioned reports and certificates bundled for audit.
  **Done:** the pack verifies end to end on the verifier media.
- **K29 Data-handling statement.** Per report: what code was read, where it stayed, confirmation nothing left the box (from the egress counter and the journal).
  **Done:** the statement's numbers match the run's egress counter and journal.
- **K30 Drill mode.** Plant a known, harmless test weakness in a *copy* of a project to check the team's process (review, CI, response) catches it — a training exercise, copies only.
  **Done:** a drill never touches the original tree; its outcome is recorded against the team's process, not the code.


### Wave 5 — status (2026-10-04)

- **K1 ✓** `raksha/projects.py` — identity by name + structure fingerprint; on-box store (`RAKSHA_HOME`).
- **K2 ✓ K3 ✓ K4 ✓** `raksha/reports.py`, `raksha/signdoc.py` — signed reports chained to the previous
  version; the colour + icon + word diff (a crash not re-found is shown, never counted fixed); the
  needs-a-human list with reasons and checklists; marked-done items re-checked on the next run.
- **K5 ✓** console *Projects* screen (owner's page, versions, role views, summaries, certificate).
- **K6 ✓** one-page EN/HI summary, phone and print friendly.
- **K7 ✓ K8 ✓ K9 ✓ K10 ✓ K11 ✓** `raksha/learning.py` + console *Learning* screen — analytics and
  regressions; draft guidelines needing a named approver; lessons on probation, promoted only on
  gate-verified cases from 2+ projects, demoted on a false positive with the source quarantined;
  rollback restores prior behaviour (tested).
- **K12 ✓ K14 ✓ K22 ✓ K23 ✓ K25 ✓ K26 ✓ K27 ✓** `raksha/views.py`.
- **K13 ✓ K15 ✓ K16 ✓ K17 ✓ K18 ✓ K19 ✓ K29 ✓** in the reports.
- **K20 ✓** `raksha/premerge.py`. **K28 ✓** `raksha/compliance.py` (verifies with the standalone verifier).
- **K21, K24, K30 — to be built by the team.** Generating these was stopped by an automated safety
  classifier during this build, and the build assistant may not reproduce that content. The specs
  and Done lines above stand; the seams they plug into exist (`raksha/reports.py` rows and
  `raksha/views.py` for K21/K24, the project store for K30).
- Tests: `tests/test_wave5.py` (17).

### Suggested order

Tier 1 (K1–K6) first — it is what users see and it builds directly on the journal, bundles and
console. Then K12, K13 and K17 (they make commanders care and catch risk early), then K15 and K2's
chaining (approval-grade trust), then Tier 2 learning with K10/K11 landing **with** K9, never after
it. The rest by value as time allows.

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
