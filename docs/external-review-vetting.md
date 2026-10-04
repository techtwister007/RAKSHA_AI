# Vetting RAKSHA against the external review (2026-10-04)

The core idea was given to a second model (ChatGPT) for a critical pass; it returned a long
list of "missing layers", a futuristic architecture, and a new USP. This document records what
that review got right, what it got wrong about *this* build, what we changed because of it, and
what we deliberately did not. It is the course correction, written down so it is not re-litigated.

## 1. The one-paragraph verdict

**We are not fundamentally weak. The review re-derives our foundation and then builds a ten-year
roadmap on top of it.** Its "assurance kernel that AI cannot overrule" is our five-check gate. Its
"negative-space / forbidden-behaviour" idea is our sink-injected runtime invariant, already the
headline novelty. Its "evidence independence" (model proposes, deterministic execution decides) is
the central bet in the first line of the brief. Its "proof of absence is impossible; report an
assurance boundary instead" was a real gap in our *outputs* and is now fixed. Its two strongest
technical criticisms — shallow fixes that kill the crash and not the defect, and the target's source
being untrusted input to the model — were valid against our build and are now closed with tests.
Everything else in it is either (a) something we already do and it did not know, (b) a legitimate
P1/P2 item for after the finale, or (c) scope that would lose the finale (judged on accuracy,
speed, resources, functionality, scalability in 36 hours) in exchange for a slide.

The one thing the review does better than our brief is **language**: "Model what the system must
never do, then make the machine try to do it" is a sharper sentence than ours, and it is a true
description of the sink-invariant pipeline. We adopt the sentence, not the architecture diagram.

## 2. What changed in the build because of this review

| # | Review point | What was true of our build | Change (all tested, all pushed) |
|---|---|---|---|
| 1 | *Shallow fixes*: PVBench found >40% of "validated" patches fail stronger PoC+ tests; agents patch the observed crash, not the defect | Our CLEAN_REFUZZ on synthesized targets was a short **random** campaign: a patch that special-cased the exact crashing input would pass unless the campaign stumbled on a sibling | CLEAN_REFUZZ now **opens with 24 deterministic variants of the reproducer** (bit flips, length changes, boundary integers) replayed on the patched build, before the fresh campaign. `tests/test_autorepair.py::test_a_shallow_fix_that_special_cases_the_reproducer_is_rejected` plants `if (len == N) return` on the real C target and it dies at CLEAN_REFUZZ with POV_DEAD passed. (`raksha/gate/runner.py::pov_neighbourhood`) |
| 2 | *Prompt injection from the target*: comments/strings in the code under test are untrusted input to the model | True. Our model has no tools and can only emit a diff — already far stricter than the review's "typed tool API" — but the gate judges behaviour and cannot see a backdoor the corpus never runs | **Patch hygiene** before any gate run: a candidate may touch only fix-site files, may add ≤150 lines, and may not introduce an execution/network/dynamic-load primitive absent from the removed lines. Prompt frames the source as `<<<UNTRUSTED SOURCE … >>>` and says so; prompt version is written on the record. A diff that fixes the overflow *and* adds `system("/bin/sh")` is refused unapplied, counted on the Scorecard, and the finding ends REPORT_ONLY. (`raksha/hygiene.py`, Scorecard `candidate_patches_rejected_before_gate`) |
| 3 | *Dependency reachability*: "library X has CVE Y" is not "this code reaches it" | True. Worse, our risk register scored every replaying dependency match as reachability 1.0 — a mislabel | The build-free walk now indexes imports (PyPI/npm/Go/Maven) in the same pass and stamps each dependency finding **imported / not-imported / unknown**; the risk register weights 0.9 / 0.3 / 0.6. On the demo estate a *critical* PyYAML CVE in a package the code never imports now ranks below a *medium* `requests` CVE it does. The finding stays proven (the version *is* present); only its priority changes. (`raksha/lanes/supply.py::ImportIndex`, `raksha/risk.py`) |
| 4 | *Proof of absence*: never say SAFE; report an assurance boundary | Our outputs never said "secure", but they also never said what was *not* analysed | Scorecard `boundary` section + an **assurance statement** on console Screen 5 and in `summary.json` / `ASSURANCE_BOUNDARY.txt`: findings proven, fixed, referred; languages exercised by exploit vs build-free only; targets that did not build; suspected-and-unreported count; dependencies not imported / unknown; and the sentence "this run establishes presence, not absence". A test asserts the word "secure" never appears. |
| 5 | *Reproducibility*: environment hash with every finding | We shipped reproducer bytes, replay scripts and content hashes, not the environment | `bundle.json` now carries `environment`: Python, platform, and gcc/go/java/mvn versions, inside the signed manifest. |

Net: 380 tests (was 371), all slices still `VERIFIED`, benchmark regenerated, air-gap guard clean.

## 3. Point-by-point: the review's "missing layers" against this build

Legend — **HAVE**: built and tested · **PARTIAL**: the mechanism exists, the review's full form does
not · **GAP→P1/P2**: real, scheduled in `HANDOVER.md` · **REJECT**: not for this product/finale, with reason.

| Review layer | Verdict | Where it stands |
|---|---|---|
| Intent → executable security & functional contract | PARTIAL | The differential corpus + the target's own tests are the functional contract ("must remain unchanged"); the sink oracles and the OpenAPI lane are the security contract for the classes we cover. We do **not** extract intent from docs/comments — and we should not let a model do it unverified: a wrong contract would silently re-define "correct". Mined contracts belong in the retrieval lane (P1-7), as data the gate checks, never as a judge. |
| Negative space / forbidden-behaviour graph | HAVE | This *is* the key novelty: `untrusted_input → command_execution` aborts at the sink like a memory bug (`sinkguard`, PySecSan, Jazzer detectors). The review re-derived our design. We adopt its sentence. |
| Security boundaries (authority / trust / state / resource / time / mission) | PARTIAL | Authority: ROE tiers, two-person rule, `may_deploy`. Trust: taint at sinks. Resource: rehearsal caps. State/time/mission: none. Mission tiers ride on the asset registry (P2-1). |
| Temporal / state-aware security (TOCTOU, ordering) | GAP→P2 | Not for the finale: needs a state model per target. A TSan oracle (`-fsanitize=thread`) is cheap and fits the oracle API; schedule fuzzing is research. |
| Concurrency / schedule fuzzing | GAP→P2 | Same. Demo targets are single-threaded; a TSan oracle is the honest first step. |
| Dependency reachability | HAVE (new) | §2 row 3. Import-level today; call-graph level is a later refinement. |
| Supply-chain / build-provenance graph | PARTIAL | Output side: signed bundle, content-addressed artifacts, environment in manifest, bundle manifest for the carried media. Input side (is the compiler / dependency trusted): out of scope — the sealed node's build chain is the customer's. |
| Environment & configuration as the target | PARTIAL | Secrets lane reads config/env files; OpenAPI lane reads exposure. Checkov/KICS as a "take" lane is P2-3. |
| Exploitability model | PARTIAL | `risk.py`: severity × reachability × exploitability, each factor from the record. No privilege/user-interaction axes — adding guessed factors would be *less* honest than the three measured ones. |
| Attack-chain / attack-graph reasoning | GAP→later | Real, valuable, not finale-scoped. Needs the asset registry and a reachability graph first. |
| Defence-in-depth verification | REJECT for now | Requires the contract layer above. Partially covered: a patch that removes a guard changes behaviour the corpus sees. |
| Unknown-unknowns / behavioural anomaly | PARTIAL | Fuzzing *is* the unknown-unknown engine for crash classes; the review wants it for logic classes too. Later. |
| Multi-baseline differential (A/B/C/D/E) | PARTIAL | Original vs patched, plus the project's own tests. "Previous known-good version" is a one-line addition when a target ships history; a spec-derived model is research. |
| Repair alternatives (local / structural / architectural) | HAVE | The ladder ends in the **mitigation floor** and in **REPORT_ONLY with a referral** — "patch is not always the answer" is already our fail-closed design. Memory-safe migration and CHERI: roadmap text, not product. |
| Patch frontier / Pareto choice | PARTIAL (deliberate) | We take the first candidate that passes, **cheapest first** (template before model), which is the Pareto proxy a 36-hour clock allows. A patch-cost metric would be a seventh number to defend; speed is scored. |
| Patch cost (performance) | REJECT for finale | Differential already rejects a fix that disables the feature. Timing on a sanitizer build is noise. |
| Agent security (hostile-by-default agent) | HAVE, stronger than proposed | The model has **no tools**: it returns text; RAKSHA applies the diff; target code runs through one sandbox door; one inference interface; the air-gap guard parses every shipped file. Now also patch hygiene. |
| Prompt injection from target code | HAVE (new) | §2 row 2. |
| Proof of absence → assurance boundary | HAVE (new) | §2 row 4. |
| Stopping policy (marginal information) | GAP→P1 | Our mutation engine is coverage-blind, so it cannot measure marginal information. Arrives with AFL++/libFuzzer behind the same `Fuzzer` interface (P1-9). |
| Deterministic replay / reproducibility | HAVE (+new) | Reproducer bytes, `replay.sh`, `python -m raksha match`, deterministic mutator seeds, now environment in the manifest. |
| Evidence independence | HAVE | The fuzzer finds the PoV, the sanitizer judges it, the gate judges the patch; the model proposes only. Exactly the review's demand. |
| Evidence fusion | PARTIAL | Cross-confirmation merges static + dynamic on the same site/CWE. A confidence calculus over contradicting evidence is not needed while the rule is "no reproducer, no report". |
| Self-testing RAKSHA / red-team benchmark | PARTIAL | Known-vulnerable cases, **known-secure negative controls (0 FP of 11)**, planted overfit and backdoor patches. Missing: mutated variants and a poisoned-comment target (P1-11). |
| Vulnerability mutation factory | GAP→P1-11 | Good idea, cheap to start from our own demo targets. |
| Model parliament / epistemic conflict | REJECT for finale | Multiple models multiply VRAM and tokens on a 32 GB single node; the gate already makes any single model's bias irrelevant to what ships. Disagreement-as-signal is a nice research line. |
| "Jev"-style fast decision model | REJECT | Could not verify the product the review names; the funnel it describes (cheap intelligence first, expensive last) is our ladder: template → retrieval → model, and build-free before build. |
| CPG + GNN structural lane | GAP→later | Joern is already on the tool map; a GNN adds training data we do not have. Semgrep "take" lane (P2-3) is the realistic structural input. |
| PQC / crypto-agility inventory | GAP→P1-10 | A deterministic, build-free **weak-crypto inventory** (MD5/SHA-1 for signatures, RSA < 2048, ECB, static IVs, RSA/ECDSA for a PQC migration list) fits our lanes exactly and is defence-relevant. Not quantum computing. |
| Hardware attestation / confidential computing | REJECT for product | Deployment property of the customer's node; the bundle is designed to be attested, not to attest. |
| Red vs blue adversarial rounds | PARTIAL → P1-9 | CLEAN_REFUZZ + the reproducer neighbourhood *are* the red team today; a real coverage-guided campaign on the patched build is the upgrade. |
| Digital twin of the target | HAVE in miniature | Every gate run builds two scratch copies and discards them; the sandbox is the twin. Topology-level twins are the customer's. |
| Deception / moving-target / federated learning / ZK / MPC / space / neuromorphic | REJECT | Different products. Noted as roadmap only. |
| Continuous assurance (re-prove on drift) | PARTIAL | The vaccine sweep and the asset registry are the seed; a nightly re-run is an ops task. |

## 4. What the review got wrong about *this* build

- It assumes the LLM has tools and a shell. It does not. It emits a diff; everything else is ours.
- It assumes "verification" means "the crash disappeared". Ours was always five checks including a
  behavioural differential, coverage of the fix site, and a fresh campaign; the review's valid
  criticism was the *strength* of the last check on synthesized targets, now fixed.
- It assumes outputs say "secure". They never did; they now say what was not analysed.
- It treats "runs where classified code lives" as a weaker USP than "model what must never happen".
  For *this* jury the first is the deployment argument and the second is the technical one. We
  keep both: the brief leads with the first, the architecture beat says the second.

## 5. The honest residual weaknesses (unchanged by this review, stated before a judge does)

1. The model lane has never run against a real endpoint; the "LLM proposes" half is exercised by
   a mock. First real run is P1-1.
2. The autofuzz mutation engine is coverage-blind. The reproducer neighbourhood closes the shallow-fix
   hole; it does not make the find loop as strong as AFL++/libFuzzer.
3. Intent is not extracted. The functional contract is "behaviour the corpus and the target's own
   tests observe". A bug class with no oracle here is outside the claim — and the boundary now says so.
4. Deep coverage is four languages; JS/TS and Rust are build-free only.

## 6. Language we adopt

For the architecture beat of the pitch, after the deployment line:

> **Don't scan for vulnerabilities. Model what the system must never do — then make the machine
> try to do it, and refuse to speak without proof.**
