# RAKSHA AI

**Reasoning-based Autonomous Knowledge & Security Hardening Agent**
AI Kavach Grand Finale · EME School, Vadodara · Indian Army

> Runs where classified code lives, and refuses to speak without proof.

An offline cyber-reasoning system: it finds a security hole in unfamiliar software,
fixes it, and proves the fix holds — autonomously, on an air-gapped network.

The governing principle is that **the LLM is not the brain; the verifier is.** A small
offline model *proposes* a fix. A mechanical five-check gate *decides* whether it is
real. Nothing unproven ever ships.

## Where things are

| Path | What it is |
|---|---|
| `RAKSHA_AI_Dossier/` | The settled brief — competition decode, architecture, tool map, models, honest gaps. Read `README.md` there first. |
| **`HANDOVER.md`** | **Start here on a new machine:** current state, how to resume, prioritised remaining work, honest limits. |
| `BUILD_PLAN.md` | The execution plan: finale answers, settled decisions, phases, and the scoring ledger. |
| `docs/` | The architecture sheet, campaign plan and plan map (HTML). **`docs/laptop-setup.md`: run the whole system on your own machine.** `docs/external-review-vetting.md`: the build vetted against an outside critical review. **`docs/future-technologies.md`: the 2026→2030 technology horizon — PQC, heterogeneous intelligence, concurrency, attack graphs, attestation — marked built / wired / roadmap.** **`docs/threat-model.md`: the threat model of RAKSHA itself — each surface mapped to a built control and its test.** |
| `raksha/` | The product. |
| `tests/` | The invariant and keystone tests. |

## Status

**All phases built** (phase table and exit gates in `BUILD_PLAN.md`). The system finds,
fixes and proves vulnerabilities across C, Python, Go, Rust, JavaScript/TypeScript and Java through one gate — including
on targets that ship **no fuzz harness**, which it synthesizes automatically — scans any
language build-free, serves the offline operator console, and signs an evidence bundle.
Plan V2 Waves 0, 1, 2, 3 and 4 are built (`PLAN_V2.md`, per-item status with evidence and caveats);
Wave 4's J3 (real-ARVO runner) is reworded, not built — see `docs/claim-audit.md`. Last verified run: **840 tests pass**, 0 fail, 2 skipped (the real multi-language benchmark and one
slow mutation test), with every slow lane, the deep and Java slices and the z3 proofs enabled;
air-gap guard and pyflakes clean; all slices `VERIFIED`.
What is deliberately not claimed — and what remains to do — is in `HANDOVER.md` §4–5 and
`docs/threat-model.md` (residual risks): the 36-hour rehearsal and the real-Docker sandbox need
the finale hardware; the model lane has run only against a mock endpoint; the SMT solver is an
optional extra baked into the sealed image (absent, proofs read `unavailable`); no code-embedding
model is bundled, so cross-language retrieval uses a stated structural vector; fix templates are
few and the model generalises beyond them.

```
raksha/
  finding.py      the unified finding record — SARIF 2.1 + a proof block, invariants enforced
  metrics.py      the scorecard, every number derived from the records
  gate/           the five-check gate: target protocol, differential corpus, runner, cross-confirm
  oracles/        the plugin interface + ASan (C/C++), Jazzer (Java), PySecSan (Python), Go panics
  harness/        automatic harness generation — discover an entry point, synthesize a harness,
                  fuzz it (fork-server), confirm; no hand-written driver needed
  autorepair.py   repair ladder (templates → model → mitigation) driven through the gate
  hygiene.py      patch hygiene: scope, size and primitive checks a candidate passes before any gate run
  lanes/          build-free: supply-chain (Maven/npm/PyPI/Go), secrets, service, dependency bump,
                  crypto + post-quantum readiness, structural source->sink (CPG-lite)
  adapters/       one per language — a real toolchain to the gate (c_asan, java, python_sink, go_fuzz)
  buildagent.py   detect → build → escalate → degrade to build-free
  inference.py    the ONE interface any model call goes through (air-gap guard proves it)
  repair.py       the repair ladder: template → retrieval → model → mitigation floor
  roe.py          Rules of Engagement — asset tiers, step-downs, two-person rule
  assets.py       the asset registry (mission tiers per codebase) that weights the risk ranking
  attackgraph.py  composes findings into attack chains scored by attack economics
  triage.py parliament.py evidence.py   decision funnel, model parliament, evidence-fusion kernel
  redteam.py      an independent red team that re-attacks every proven fix to falsify it
  vaccine.py      one verified fix → a proven detection rule → a fleet sweep
  bundle.py brief.py risk.py rollback.py   signed evidence (with environment), Commander's Brief, risk register
  replay.py __main__.py                    safe replay scripts and the `python -m raksha` replay CLI
  airgap.py sandbox.py                     the no-egress guard; the one door all target code runs through
  orchestrator.py console (../console/)    the live session the six-screen console renders
  health.py rehearse.py                    endurance watchdog and dress-rehearsal harness
  benchmark.py                             our own measured numbers (ARVO-style cases)
```

## Run it

```sh
pip install -e '.[dev]'
pytest                       # 840 tests: invariants, gate, lanes, oracles, autofuzz, evidence, hardening

python -m raksha.demo        # a C, a Java and a Python finding through one pipeline
python -m raksha.slice_three # three languages verified live through the one gate (needs gcc; Maven warm for Java)
python -m raksha.slice_autofuzz # find→fix→prove on targets that ship NO fuzz harness (C, Python)
python -m raksha.slice_go    # Go deep lane via native go test -fuzz, no hand-written harness
python -m raksha.orchestrator # serve the offline operator console on :8080
python -m raksha.airgap      # the no-egress guard (run before building the bundle)
python -m raksha.rehearse 10 # a short self-test of the endurance harness
python -m raksha.benchmark   # re-measure every published number, incl. false positives on negative controls

# replay a finding's evidence independently (what every bundle's replay.sh runs; exit 1 = reproduced)
python -m raksha match npm minimist 1.2.5 --advisory GHSA-xvch-5gv4-984h
```

The demo writes `raksha-findings.sarif`, which validates against the OASIS SARIF 2.1.0
schema vendored in `schemas/`.

## The two invariants everything rests on

Both are enforced mechanically in `raksha/finding.py`, by raising
`InvariantViolation` — not by convention, review, or a promise in a slide:

1. **No reproducer, no report.** A finding without a reproducer that actually replays
   can never leave `SUSPECTED`. This is why "100% precision on reports" is a structural
   property rather than a tuning result: the reportable set *is* the set of findings
   whose reproducer was replayed and observed to fire the oracle.
2. **Nothing unproven ships.** A patch reaches `VERIFIED` only with all five gate
   checks passed *and* evidence that the original attack is dead on the patched build.
   Each candidate patch must earn all five itself; it cannot inherit a previous
   round's passes. If nothing validates, the output is `REPORT_ONLY` — a proven
   vulnerability report, never a guess.

## Measurement

Shortlisting is banked, so every remaining point comes from the finale five:
performance, speed, precision, functionality, scalability.

> **A criterion you cannot measure is a criterion you cannot score.**

So no component is "done" until it emits the metric that proves it. The records
timestamp every status transition and tag the repair lane that produced each patch,
which is where `metrics.py` gets its numbers — including the unflattering ones:
candidate patches the gate rejected, corpus inputs quarantined as non-deterministic,
findings suppressed for want of a reproducer, and model calls that produced no fix.
An unmeasured metric reads as `None`, never as a flattering zero.

## Licence note

Every third-party weight and tool licence must be confirmed and recorded in a
`THIRD_PARTY.md` before the final bundle — a defence acceptance board will ask.
