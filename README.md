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
| `BUILD_PLAN.md` | The execution plan: finale answers, settled decisions, phases, and the scoring ledger. |
| `docs/` | The architecture sheet, campaign plan and plan map (HTML; also published as artifacts — links in `BUILD_PLAN.md`). |
| `raksha/` | The product. |
| `tests/` | The invariant and keystone tests. |

## Status

**Phase 0 — the keystone.** Three oracles → one record → one gate, proven on
trivial targets before anything clever is built (`RAKSHA_AI_Dossier/14_open_questions.md`
item 1).

```
raksha/
  finding.py    the unified finding record — SARIF 2.1 + a proof block
  metrics.py    the scorecard, derived from the records
  cwe.py        each oracle's vocabulary → CWE
  oracles/
    base.py     the oracle plugin interface
    asan.py     C/C++      — ASan / UBSan / MSan
    jazzer.py   Java       — Jazzer's built-in security detectors
    pysecsan.py Python     — PySecSan sink aborts, Atheris fallback
```

The gate itself (Phase 1) and the Java vertical slice (Phase 2) are next.

## Run it

```sh
pip install -e '.[dev]'
pytest                  # 62 tests
python -m raksha.demo    # a C, a Java and a Python finding through one pipeline
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
