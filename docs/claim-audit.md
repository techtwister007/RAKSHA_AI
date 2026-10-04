# Claim audit (J10)

Every claim RAKSHA makes to the jury, reconciled line by line with a built, demonstrable
capability — or reworded until it is. The rule: **no sentence in the brief lacks a feature behind
it.** Where a claim could not be built, it is reworded here, and the brief reworded to match, rather
than left standing. This is the honesty ledger; it is read alongside the benchmark report (which
carries the measured numbers) and the threat model (which carries the controls).

Legend: **BUILT** — code and a test/demo back it; **MEASURED** — a number from a real run;
**REWORDED** — the original claim was softened or scoped to what is true; **PREP-NODE** — built and
unit-tested here, but the full execution needs the finale hardware (named in the rehearsal runbook).

## The seven show-stoppers (dossier 08)

| # | claim | status | the feature behind it |
|---|-------|--------|-----------------------|
| 1 | Install from a sealed SSD, cable pulled, live; zero network interfaces | BUILT + PREP-NODE | `deploy/install.sh`, air-gap guard (`raksha/airgap.py`), and the live egress counter (J6) on the console; the 20-minute SSD install is rehearsed on the finale node |
| 2 | Live Log4Shell, found and fixed offline | BUILT | `raksha/slice_three.py:run_java` + the Jazzer JNDI oracle; demo target `demo-targets/java-log4shell`; needs Maven + a warm local repo on the node |
| 3 | Split-screen exploit replay (red vulnerable, green patched) | BUILT | console Finding Detail (F3) renders before/after replay from the record |
| 4 | Public rejection of a bad patch | BUILT + MEASURED | the says-no beat (J1, `raksha/saysno.py`): a shallow fix dies at the gate, an unsafe diff at hygiene, a weak fix at the red team — all on the real gate, as scripted in ~25s |
| 5 | The Vulnerability Vaccine: one fix → fleet-wide sweep | BUILT | `raksha/vaccine.py` + `Session.run_vaccine_sweep`; the variant count is a live number on the Scorecard, `null` until a sweep runs |
| 6 | Commander's Brief, optionally in Hindi, as a JSSD staff paper | BUILT | `raksha/brief.py` (`jssd_brief`, `jssd_brief_hi`); console Commander's Brief screen (F10); PDF export is Latin-only (Hindi brief is on-screen) — **REWORDED** below |
| 7 | Three (of four) languages, one screen | BUILT | `raksha/slice_three.py`; C/Python always, Java/JS/Go/Rust where the toolchain is present |

## Reworded claims

- **"Frontier models fail ~2/3 of the time" (pitch beat 1).** This is a cited external figure about
  general coding agents, not a RAKSHA measurement. Kept only as *context for the problem*, attributed;
  never stated as our result.
- **"Commander's Brief in Hindi."** BUILT on screen and in the plain-text brief; the **PDF** export is
  single-font Latin, so a Hindi *PDF* is not claimed. The brief is shown in Hindi on the console; the
  PDF ships in English. Reworded in the dossier to say exactly that.
- **Fix-rate numbers.** The benchmark report quotes a fix rate **on the bundled demo set** with the
  set size beside every number, explicitly *not* a population fix-rate. No sentence claims a general
  security fix-rate.
- **Recall.** Previously declined entirely. Now **MEASURED** where the denominator is knowable
  (J5, `raksha/recall.py`): 100% on the mutation factory, 54.5% on the fuzzable demo ground truth,
  misses named. Still declined for an open corpus, and the brief says why.

## Real-world external benchmark (ARVO / AutoPatchBench)

- **Claim, reworded (J3).** The original plan beat was "real ARVO numbers, published with an honest
  win/loss table." The runner that executes real ARVO/OSS-Fuzz cases through the pipeline was **not
  built in this environment**. What stands instead:
  - the **loader seam** (`raksha/benchmark_arvo.py`) that plugs a prep-node manifest of real cases
    into the exact same find→confirm→repair→gate path, with `arvo_cases()` returning `[]` and
    `manifest_status()` saying so when no manifest is present — the honest offline state;
  - the baseline comparison (J4) and recall (J5) run on the bundled demo set and the mutation
    factory, labelled as such.
- **What the jury is told:** the full external baseline runs on a networked prep machine and plugs
  into this harness; the numbers in the report are the bundled-set baseline, named as a baseline, not
  a statistical security fix-rate. No real-ARVO figure is quoted that was not produced.

## Trust / assurance claims

| claim | status | behind it |
|-------|--------|-----------|
| Every report carries a replaying reproducer | BUILT + MEASURED | the data model forbids reporting a SUSPECTED finding; J4 table shows 7/7 RAKSHA reports with a reproducer |
| No report is false — "no reproducer, no report" | BUILT | precision is structural (reportable ⇒ reproducer); false positives measured separately against negative controls (0 on 11 clean artifacts) |
| Signed, replayable evidence bundle | BUILT | `raksha/bundle.py`; HMAC on the demo key (labelled), cosign/in-toto on deployment; `verify_bundle` re-checks every byte |
| A judge replays a finding on their own laptop in <1 min | BUILT + MEASURED | the verifier media (J7): self-verified with only a shipped runtime in ~0.3s; fire-on-vulnerable / dead-on-patched replay |
| Signed internal-CERT advisory from a verified fix | BUILT | `raksha/advisory.py`; sequential id, affected assets, proven patch; `verify_advisory` detects a one-byte change |
| Scrub the run to any hour | BUILT | the time-lapse (J9): replays a verified, hash-chained journal; a shipped 16-minute recording verifies |
| Tamper-evident audit trail | BUILT | hash-chained session journal (`raksha/journal.py`); `verify()` fails on any altered or dropped line |
| Air-gap: 0 cloud calls | BUILT + MEASURED | the egress counter (J6) + the inference client counting any non-local call; the two agree by construction |

## Wave 5 claims

| claim | status | behind it |
|-------|--------|-----------|
| Every project gets a unique ID that survives paths and patches | BUILT | `raksha/projects.py`; test `test_same_project_same_id_across_paths_different_project_new_id` |
| Each run is a signed, versioned report; history cannot be edited | BUILT | `raksha/reports.py` + `raksha/signdoc.py`; chain verification fails on a dropped finding (tested) |
| Colour-coded "what changed" with fixed / new / still open / needs a human | BUILT | the diff; "fixed" only when the absence is a proof; a crash not re-found is shown separately |
| A clear list of what the human must do | BUILT | needs-a-human reasons + checklists; marked-done items re-checked |
| The system learns recurring faults and proposes guidelines for ACG | BUILT | `raksha/learning.py`; drafts need a named approver; nothing changes behaviour until approved |
| Adapts to new frameworks | BUILT, scoped | lessons on probation, promoted only on gate-verified cases from 2+ projects; rollback |
| Readiness certificate, compliance pack | BUILT | issued only when the record supports it; the pack verifies on the standalone verifier |
| Attacker-path explainer (K21), ask-about-my-project (K24), process drill (K30) | NOT BUILT | to be built by the team; not claimed |

## Tools wired in

| claim | status | behind it |
|-------|--------|-----------|
| Industry scanners add independent evidence | BUILT (optional) | OSV-Scanner, Gitleaks, Checkov, Semgrep take lanes; `tests/test_tool_integrations.py` |
| Evidence can be verified without the power to forge | BUILT (optional) | cosign public-key seal, `raksha/cosign.py` |
| Rules of engagement are enforced twice | BUILT (optional) | OPA policy `raksha/data/roe.rego` must agree with `raksha/roe.py` |
| Each deployment has its own signing key | BUILT | `raksha/keys.py`, run by `deploy/install.sh` |

## Standing honest gaps (unchanged from the threat model)

- The 36-hour endurance run, vLLM serving, and the long sandboxed container run require the finale
  hardware; built and unit-tested here, executed in the two dress rehearsals (runbook).
- The real-ARVO runner (J3) is not built here; the seam and the honest offline state are.
- Hindi PDF export is Latin-only; the Hindi brief is on-screen and in text.

Every row above is either BUILT (with the file and test/demo named) or REWORDED (with the softening
stated). Nothing in the brief is left claiming more than the build does.
