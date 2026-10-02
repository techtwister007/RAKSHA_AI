# 03 · Architecture

## The governing principle

**The LLM is not the brain. The verifier is the brain.** Deterministic tools do the
finding, the localising and the deciding. The model only *proposes*. Everything is
written once and reused across every programming language, because every finder is
forced to speak one common language of "alarms."

## Five layers

```
┌───────────────────────────────────────────────────────────────┐
│ LAYER 1  LANGUAGE ADAPTERS  (one per language; each a thin shim)│
│   C/C++ · Java/Kotlin · Node/JS/TS · Python  (+ binary, web)   │
├───────────────────────────────────────────────────────────────┤
│ LAYER 2  ORACLE LAYER  (turn every bug class into ONE alarm)   │
│   memory sanitizers · Jazzer detectors · PySecSan ·            │
│   static taint · metamorphic authz oracle                      │
├───────────────────────────────────────────────────────────────┤
│ LAYER 3  INVARIANT CORE  (written once, runs for all)          │
│   normalise → localise → repair → (loop)                       │
├───────────────────────────────────────────────────────────────┤
│ LAYER 4  THE FIVE-CHECK GATE  (the incorruptible inspector)    │
│   compiles · PoV dead · differential corpus · coverage · refuzz│
├───────────────────────────────────────────────────────────────┤
│ LAYER 5  EVIDENCE & LEARNING                                   │
│   signed bundle · corpus · templates · failure memory · QLoRA  │
└───────────────────────────────────────────────────────────────┘
```

### Layer 1 — Language adapters
Each language contributes exactly one thing: an **oracle** that turns its bug classes
into the common alarm format. Everything below Layer 1 is language-agnostic.

- **Java is the easiest target, not the hardest** — Jazzer's autofuzz writes the
  harness automatically, its detectors catch security bugs out of the box, and JUnit
  gives a native regression suite.
- **React is not a fuzzing target** — its real attack surface is XSS, prototype
  pollution, client-side authz and vulnerable dependencies. For a React front end we
  run static + dependency lanes and point the fuzzing at the API behind it. Say this
  plainly; claiming to "fuzz React" would lose a technical judge.

### Layer 2 — The oracle layer (the key idea)
Different bug types produce different evidence. We **install an oracle** that converts
each into the same "abort event":

| Oracle | Languages | Catches |
|--------|-----------|---------|
| Memory sanitizers (ASan/UBSan/MSan) | C/C++, native | overflow, use-after-free, UB, leaks |
| Jazzer detectors | JVM | SQLi, LDAP, JNDI/log4j, command injection, deserialization, SSRF, path traversal, XPath, regex DoS |
| Jazzer.js detectors | Node/JS | command injection, path traversal |
| PySecSan (+ our extensions) | Python | shell exec, eval/exec, SQLi, pickle/yaml, path traversal, SSRF |
| Metamorphic oracle (ours) | all | authz bypass / IDOR / BOLA — two principals, same response = bug |

The non-crash insight: for bugs that don't crash, we **install a runtime tripwire** at
the dangerous point so they abort like a crash would. Then they re-use the whole
crash-bug pipeline. One pipeline, every bug class.

### Layer 3 — The invariant core
Written once, runs for every language:

1. **Normalise** — deduplicate crashes (stack hash), minimise each reproducer
   (delta-debug). 800 raw crashes collapse to ~6 real bugs.
2. **Localise** — the abort trace gives the line for free; a code-mapping tool
   (ripwire) walks from the crash site to the *fix site* in target-owned code and
   returns a ranked set of candidate locations.
3. **Repair** — four lanes, cheapest first:
   - **Template** (zero inference — known bug shape → known fix shape)
   - **Retrieval** (look up the nearest historical fix for this bug class)
   - **LLM** (the model proposes; sample several candidates)
   - **Mitigation floor** (a provably-safe hardening patch if nothing better validates)
4. **Loop** — a failed patch feeds the exact error back; cap ~3 rounds.

### Layer 4 — The five-check gate (the inspector)
A patch ships only if **all** pass, cheapest check first so failures are cheap:

1. **COMPILES / imports** cleanly
2. **POV_DEAD** — the reproducer no longer triggers the oracle
3. **DIFFERENTIAL_CORPUS** — every non-crashing input produces identical output before
   and after (the overfitting-patch killer; free, because fuzzing already made the
   corpus). Guarded by a determinism pre-flight + canonicaliser so real services with
   timestamps/UUIDs don't cause false rejections.
4. **COVERAGE_HELD** — patched code still reachable; no "fixed by deleting it"
5. **CLEAN_REFUZZ** — a fresh bounded campaign finds no new bug

If nothing passes → **REPORT_ONLY** (a proven vulnerability report, flagged for human
review). Never a guess on a live system.

### Layer 5 — Evidence & learning
- **Signed evidence bundle** per fix: reproducer hash, before/after, gate results,
  model + prompt version, fix-site, AST delta, approver signatures.
- **Four learning loops:** corpus persistence, template mining (every verified fix
  becomes a zero-inference rule), failure memory, nightly on-box QLoRA.

## The ingest funnel (front of the pipeline)

```
Target arrives
  → IDENTIFY  language, build system, source-or-binary, entry points
  → CLASSIFY  library / service / CLI / binary-only  → pick the lane set
  → BUILD     (build agent; see file 06)
       ├ success → full pipeline (build-dependent + build-free lanes)
       └ failure → build-free pipeline only (static, deps, secrets) — degrade, not die
```

## The nine stages, end to end

```
1 Build & instrument   2 Install oracles     3 Hunt (fuzz ∥ static ∥ taint)
4 Normalise            5 Localise            6 Repair (4 lanes)
7 Gate (5 checks)      8 Attest (sign)       9 Learn (4 loops)
```

Everything flows as **one record** — the unified finding record specified in the next
section of this file — advancing through these stages: SUSPECTED → CONFIRMED → PATCHED →
VERIFIED, or → REPORT_ONLY. (File 12 maps this record's `status` and `reproducer` fields
to the Precision scoring criterion.)

## The one record everything speaks (the keystone)

Every finder emits the **same** record — we extend **SARIF** (the OASIS standard every
static tool already outputs) with a proof block:

- `oracle`, `bug_class` (CWE), `reproducer` (artifact + how to replay it),
  `replay_before`, `replay_after`, `status`, `fix_site_set`, `gate` (five checks),
  `roe_level`, `signatures`.
- **The rule that makes precision real:** a finding without a `reproducer` can never
  leave SUSPECTED. Static-only findings stay SUSPECTED until a reproducer is attached
  and replays. This is why "100% precision on reports" is true *by construction* — it
  lives in the data model, not in a promise.

Build this record first, on trivial targets, before any clever lane. If a Java
reproducer, a C trace and a Python abort can all become valid records the same gate
consumes, the architecture holds.

## Hardware profile

One node, 32 GB VRAM. Two models co-resident (see file 05). Degrades to a CPU-only
smaller-model profile rather than failing. Everything in sandboxed containers with no
network interface.
