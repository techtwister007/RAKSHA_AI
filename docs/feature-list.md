# RAKSHA AI — feature list

Everything in this list is built and tested unless it is marked **(optional)**, which means it
needs a tool or model you install, or **(not built)**.

## A. Core engine: find, prove, fix

**Getting the code in**
1. Takes any folder of code: C/C++, Python, Go, Rust, JavaScript/TypeScript, Java and mixed estates.
2. Tries the real build. If the build fails, it switches to build-free mode and still scans.
3. Asset registry: each target gets a mission tier (critical / operational / support).
4. Every target-code run goes through one sandbox door (no network on the sealed node).

**Finding: static lanes (read the code)**
5. Supply chain: known-vulnerable dependency versions, plus whether the code actually imports them.
6. Secrets: keys and passwords left in files, shown masked.
7. Crypto and post-quantum inventory, with a migration plan per call site.
8. API exposure from OpenAPI specs (endpoints with no authorisation, debug endpoints).
9. Structural paths from untrusted input to a dangerous call.
10. Infrastructure-as-code, git history and jar/binary version checks.
11. **(optional)** Industry scanners as extra lanes: Semgrep (offline rules), Gitleaks,
    OSV-Scanner (offline database), Checkov.

**Finding: dynamic lanes (run the code)**
12. Automatic harness generation: finds an entry point and writes the test driver itself.
13. Its own fuzzer: mutation, fork-server, coverage feedback, seed-corpus harvest.
14. Watchers:
    - memory (ASan, UBSan, LSan);
    - races (TSan);
    - Python and Node sink guards;
    - Go native fuzzing, Rust panics, Java (Jazzer);
    - hangs;
    - metamorphic checks;
    - a behaviour baseline (new files, sockets or processes);
    - library-call interposition.

**Triage and proof**
15. One finding per root cause, keyed by crash signature, with fleet roll-up across repos.
16. Decision funnel: cheap scoring first, so expensive tools go where they pay.
17. Cross-confirmation: two independent lanes agreeing on the same spot.
18. Evidence fusion: model votes are capped below "proven".
19. **No reproducer, no report.** Only a replaying input or an exact re-match is reported;
    everything else stays SUSPECTED.
20. Input minimiser, and demotion of crashes the harness itself caused.

**Prioritising**
21. Attack graph: chains small findings to real impact and highlights the cheapest path.
22. Risk register: severity × reachability × mission tier.
23. CVSS 3.1/4.0 scores, KEV and EPSS signals, ATT&CK and D3FEND mapping.

**Repairing**
24. Repair ladder, cheapest first:
    - template (zero model calls);
    - fix memory (reuses proven fixes, even across languages);
    - LLM **(optional)**;
    - mitigation floor.
25. Patch hygiene: refuses any patch that adds shell, network or eval, or is too large or out of
    scope.
26. Feedback loop: a rejected patch's reason goes into the next attempt.
27. Patch frontier: several passing patches are compared and the best one chosen.

**Proving the fix**
28. The five-check gate:
    - COMPILES;
    - POV_DEAD;
    - DIFFERENTIAL_CORPUS;
    - COVERAGE_HELD;
    - CLEAN_REFUZZ (24 variants plus fresh fuzzing).
29. Extra proof:
    - **(optional)** z3 solver: the bad state is now unreachable;
    - release-build twin;
    - performance delta;
    - rollback proof.
30. Independent red team re-attacks every verified fix.
31. Rules of engagement per asset, plus **(optional)** OPA as a second policy opinion. The
    stricter of the two wins.

**Evidence**
32. Signed evidence bundle per finding (HMAC; **(optional)** cosign), with an in-toto
    provenance record and a toolchain record.
33. `replay.sh` (fires on the vulnerable build, dead on the patched one), the reproducer bytes,
    and a rollback script.
34. Hash-chained journal of every step, with crash-resume.
35. Standalone verifier: a judge re-checks a bundle on their own laptop with nothing else installed.
36. Exports: SARIF, CSV, XLSX, PDF brief, internal-CERT advisory, compliance pack.

**Models**
37. Any OpenAI-compatible provider: Ollama, LM Studio, vLLM, llama.cpp, OpenAI, DeepSeek,
    OpenRouter, Groq, Mistral or a custom URL. Switch provider and model at any time.
38. Model parliament: several roles vote and disagreement is flagged. No model ever decides.
39. Guided (structured) model output, and model-written regression tests that must fail before
    the fix and pass after it.

**Safety of RAKSHA itself**
40. Air-gap guard: no network code outside one module, enforced by a test.
41. Sealed mode refuses off-machine models, and the CLOUD counter counts any call that leaves.
42. Target code is treated as untrusted in prompts, and there is a threat model of RAKSHA itself.
43. Per-install signing key, and a signed self-update.

**Memory and learning**
44. Project identity that survives renames and moves, with versioned, signed reports per run.
45. "What changed" diffs between versions; "fixed" only when the absence is proven.
46. Learning on probation:
    - lessons are promoted only after holding on two or more projects;
    - a false positive demotes the lesson and quarantines its source;
    - rollback is possible.
47. Draft secure-coding guidelines that need a named approver.

**Self-testing**
48. Mutation factory: known bugs rewritten many ways to measure find and fix rates.
49. Negative controls: clean code that must produce 0 false positives.
50. Benchmark, baseline comparison and recall reports, plus the model-lane check and the model
    benchmark.
51. 36-hour rehearsal mode and a recorded long run.

## B. User-facing features (operator experience)

**The console** (offline, opens at http://127.0.0.1:8080)
1. Fourteen screens:
   - Mission Board
   - Live Pipeline
   - Event Log
   - Finding Detail
   - Attack Graph
   - Estate Map
   - Post-Quantum
   - Evidence Vault
   - Scorecard
   - Commander's Brief
   - Demo Beats
   - Time-lapse
   - Projects
   - Learning
2. Header trust badges on every screen: NET IF (0 or "unenforced"), CLOUD calls, PRECISION.
3. Live event log that tells the run as plain sentences.
4. Two voices per finding: a plain-language staff view and an engineer view with the proof.
5. Side-by-side panels: "vulnerable build: attack fires" next to "patched build: attack dead",
   with the five checks ticking.
6. Operator actions, each logged with who did it and protected by a per-run token:
   - Approve
   - Reject
   - Mark false positive
   - Re-run red team
   - Export bundle
7. Search, filters (language, status, severity, lane) and sorting.
8. "Verify one yourself": re-check any evidence bundle live from the Evidence Vault.
9. Scorecard of measured numbers, with an assurance boundary saying what the run did **not** prove.
10. Ranked "fix these first" risk register.
11. Interactive attack graph with the cheapest path lit and every edge labelled "heuristic".
12. Estate map grouped by mission tier, with the top three risks.

**Language, access and devices**
13. English and Hindi, switched with one click, including the Commander's Brief.
14. Projector high-contrast mode.
15. Full keyboard control (`?` shows the keys).
16. Phone-width layout.

**Reports for different people**
17. Commander's Brief: one page per finding in staff format, exportable to PDF.
18. Role views of a project: owner, developer, commander, auditor.
19. Posture score per project, its trend over versions, and readiness certificates.
20. "Needs a human" list with a checklist per item. "Mark done" is re-checked on the next run,
    not trusted.
21. Summaries in English and Hindi; CSV, XLSX and SARIF exports for other tools.

**Demo beats (built for judges)**
22. "It says no": four fixes for one bug, three refused for three different reasons, one
    accepted, in about 22 seconds.
23. Bring your own target: scan a folder (for example from a USB stick) live.
24. Air-gap counter: live packet counters next to RAKSHA's own count of outbound calls.
25. Time-lapse: scrub through a recorded long run, chain-verified.

**Setup and everyday use**
26. One-click Windows install onto D:/E:, plus a Linux/macOS installer.
27. `-Status` check that says what is installed and the exact next step; a setup log.
28. Double-click launchers:
    - Console
    - Shell
    - Checks
    - Set Model
    - Files
    - Update
29. Model menu: choose a provider, see the models that server offers, run a test call, and get a
    plain hint when the call fails.
30. Change only the model with one command; switch to model-free with one command.
31. Clear warnings when a provider would send code off the machine.
32. A `CLAUDE.md` in the install folder, so an AI coding assistant opened there knows the layout.

**Documents**
33. App walkthrough with screenshots, the "at a glance" diagrams, the book (web and PDF), the
    laptop guide, the UI design brief and the claim audit.

## C. Not built yet

- K21 "why is this risky" explainer, K24 ask-about-my-project, K30 drill mode.
- J3 real-ARVO numbers: the runner exists, but the case data has not been assembled.
- A sandbox image that holds every toolchain, and the 36-hour run on the finale hardware.
- The future-system items shown dotted in `docs/raksha-at-a-glance.html`.
