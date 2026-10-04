# 14 · Open Questions — What Is Still Undecided or Unproven

Kept separate and honest so no one mistakes a plan for a proven fact. None of these block
starting; all should be resolved by evidence, early.

> **Status (2026-10-04).** Resolved by evidence: **1** (keystone proven: four languages, one record,
> one gate, 371 tests), **2** (pre-flight + canonicaliser tested on noisy, error-path and
> `go test` output), **3** (harness synthesis built and verified for C, Python and Go — Java
> uses its replay driver). Still open: **4** (endurance — harness built, 36 h run pending, `HANDOVER.md`
> P0-1), **5–8** (decisions; 5 settled as Java + C + Python + Go deep), **9–10** (external).
> The organisers' answers that shaped the plan are recorded at the top of `../BUILD_PLAN.md`.

## Unproven assumptions (validate first)

1. **The unified finding record is the keystone and is only asserted.** Build the thinnest
   possible slice — three oracles (C ASan, Java Jazzer, Python PySecSan) → one SARIF+proof
   record → one gate — on trivial targets, in week one. If a Java reproducer, a C trace
   and a Python abort cannot all become valid records the same gate consumes, the
   "one pipeline" claim is false and we need to know immediately.

2. **The differential-corpus gate on real services.** The determinism pre-flight +
   canonicaliser is designed but not tested against a noisy target (timestamps, UUIDs,
   hash-ordered output). If it throws false rejections, patch success craters silently.
   Test on a deliberately noisy service early.

3. **Harness synthesis for C.** Highest-risk find-side unknown. If OSS-Fuzz-Gen + the
   quality gate can't produce a compiling, coverage-producing harness on a real target by
   a set checkpoint, fall back to hand-written harnesses and say so. (Java sidesteps this
   via autofuzz.)

4. **Endurance.** Nobody has run the whole system for 36 hours. Memory leaks, disk filling
   with corpus, model server falling over, stuck subprocesses — these only show up in a
   long dress rehearsal. Do at least one full-length rehearsal; two is better.

## Decisions still open

5. **Primary language depth.** Build the core language-agnostic from day one. Make **Java**
   the deepest adapter (Jazzer gives the most capability per hour). Keep **C/C++** second
   (the brief's wording implies it). Ship **Python** as the novelty showcase (our
   sanitizers are the only option there). Final weighting depends on any hint about the
   finale target's language.

6. **Fuzzing structured protocols.** For a web/JSON service, byte-level mutation wastes
   most of its budget on malformed requests. Grammar-aware generation (or spec-driven
   tools like Schemathesis/RESTler) is likely better; confirm by measurement whether the
   model or a template generator is the better input source.

7. **Cross-language template reuse.** Is a path-traversal fix template written for Java
   reusable as a pattern for Python? If yes, the template library grows superlinearly (a
   strong novelty claim). If no, we maintain one library per language. Test on two
   languages before claiming it.

8. **QLoRA on the security advisor.** Worth trying on ARVO data, but "calibration without
   comprehension" means we must *measure* whether it helps on a held-out set — don't
   assume fine-tuning improves it. The gate protects precision either way.

## Known external unknowns (can't resolve in advance)

9. **The finale target itself.** Language, build system, source-vs-binary, library vs
   service — all unknown until the finale. The entire ingest funnel + build-free fallback
   exists precisely because of this. Prepare Python *and* Java deeply; prepare the
   web-service and binary-only lanes as insurance.

10. **Finale hardware.** If a GPU isn't provided, the CPU-only smaller-model profile must
    work. Benchmark it in advance so the degraded path is known, not discovered live.
    Bring our own machine regardless.

## The one-line summary

Nothing *structural* is open — the architecture, tool map, models, differentiators,
console and scoring alignment are all settled. What remains is **execution and
validation**: prove the keystone, harden the weakest link (build/offline mirror),
and rehearse long. Resolve 1–4 early; they are the ones that could invalidate a core
assumption.
