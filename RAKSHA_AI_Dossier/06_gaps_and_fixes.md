# 06 · Gaps, Fixes & Honest Confidence

This is the most important file for not fooling ourselves. Read it before believing any
of the others.

## The honest confidence number

Nobody should claim >95% certainty. The realistic maths for the *flawless ideal* demo:

- Build + fuzz works on their target: ~70%
- Given that, find ≥1 real bug: ~80%
- Given a bug, produce a validated patch: ~65%
- All three, end to end, live: **~36%**

**But** with graceful degradation (fallbacks below), the probability of *a convincing
demo of something real* rises to **~85–90%**. Our confidence does not come from the
system always working — it comes from the system **degrading instead of dying.** Engineer
the fallback ladder, not the perfection.

And context: competitors are at the same ~36% or lower, and most don't know it. Knowing
our real number and designing for it is itself an edge.

## The single weakest spot

**"Their target won't build in the first 6 hours, and every downstream stage starves."**

This is the only single-point-of-total-failure. Harness synthesis failing costs one
language's crash-fuzzing; a weak model costs patch rate; but the build failing costs
*everything, at once, in hour 3.* It is the fuel line.

**Fix — the build-dependent / build-free split.** Many lanes need no successful build:
static analysis, dependency scan, secret/config scan, and Python/JS which don't compile.
So if the build fails we still produce verified findings (a dependency CVE is provable
from the version alone). We drop from "find + fix + prove" to "find + recommend." We
never drop to zero. *This single choice is what turns 36% into 85%.*

Full build-agent and offline-mirror spec is below in this file; it is the highest-value
engineering in the whole project.

## The gap table

| # | Gap | Severity | Fix | Tools |
|---|-----|----------|-----|-------|
| 1 | Build fails → pipeline starves | **Critical** | build-free lanes + offline mirror + build agent on OSS-Fuzz recipes | devpi, Nexus, Verdaccio, aptly |
| 2 | Too slow for the demo clock | High | pre-warmed corpora, parallel lanes, time-box each stage, stream first finding to screen | AFL++ -M/-S |
| 3 | Unified format unproven | High | **use SARIF + a proof block** (don't invent); prove all oracles map into it week one | SARIF 2.1 |
| 4 | Differential gate flaky on real services (timestamps/UUIDs) | High | determinism pre-flight (run 3×) + canonicaliser + quarantine list printed in bundle | own code |
| 5 | 36-hour endurance (leaks, disk, stuck procs) | Medium | cgroup caps, disk quotas, corpus minimisation, watchdog restarts, health panel | systemd, afl-cmin |
| 6 | Target is a running web service, not a library | High | API fuzzing from OpenAPI spec + stateful REST fuzzing + DAST | Schemathesis, RESTler, ZAP |
| 7 | Binary only, no source | Medium | headless decompile + binary-only fuzzing; degrade to triage/report | Ghidra, AFL++ QEMU |
| 8 | **Ignored the most common real bug class** | High | outdated vulnerable deps — easy to find, fix is a version bump, provable by rebuild | OSV-Scanner, Trivy, Grype |
| 9 | Secrets / misconfig | Medium | hardcoded keys, Docker/K8s misconfig | Gitleaks, Checkov, KICS |
| 10 | **We execute untrusted code on an Army box** | **Critical (trust)** | sandbox every build & run: no network, cgroups, seccomp, gVisor/Firecracker | Docker, gVisor |

Gaps 6, 8, 9 matter more than they look: real military software is more often a web app
with an outdated library and a hardcoded password than a C parser with a heap overflow.
Gap 10 *will* be asked by the jury; having the answer ready is itself a credibility win.

## Build agent + offline mirror (the weakest-link spec)

**The build agent is a loop, not a genius** — same philosophy as the whole system:

```
Detect build system → try standard build
  fails? → parse error
         → known error? apply known remedy (table)       ← no model
         → unknown?     ask model for ONE targeted fix    ← model, bounded
         → retry (cap ~5), then fall back to build-free
```

Known-error remedies (zero inference): missing package → install from mirror; wrong
runtime version → switch cached toolchain; missing build tool → apt mirror; needs a
flag → known-pattern list; test dep missing → build with tests off, note it.

**Knowledge source — don't invent:** OSS-Fuzz ships thousands of working `build.sh` +
`Dockerfile` recipes across 650+ projects. The build agent retrieves the nearest recipe
for the detected stack as its starting point and RAG context. We teach the model nothing
from scratch; we hand it the proven recipe.

**The offline mirror is the actual make-or-break.** You cannot mirror all of PyPI
(terabytes). Cache the **high-probability set** — most-used packages + everything the
benchmark targets need — and tell the jury exactly that: *"we carry the N most common
dependencies offline; anything missing degrades to static analysis, not failure."*
Stating the limit is more credible than faking completeness.

**Refresh path (sneakernet):** mirrors go stale; the update is a signed bundle on
removable media, verified on import — the air-gapped equivalent of `apt update`. Design
it now; it is also a deliverable and a spin-off.

## Other honest unknowns (see also file 14)

- The "unified abort format" is the architectural keystone and is **asserted, not yet
  proven**. Build the thinnest three-oracle → one-record → one-gate slice *first*.
- The determinism/canonicalisation pass for the differential gate is designed but not
  validated on a real noisy service.
- Nobody has watched the system run for 36 hours. The dress rehearsal is not optional,
  and it must be long.
- Cross-language template reuse (does a Java fix template help Python?) is an open
  empirical question — test on two languages before claiming it.

## The fallback ladder (what "degrade, don't die" means in practice)

1. Target won't build → build-free lanes (static, deps, secrets) → still real findings.
2. No harness can be synthesised → hand-written harness for the demo target.
3. Fuzzing finds nothing in time → static + dependency findings carry the demo.
4. No patch validates → **REPORT_ONLY**: a proven vulnerability report.
5. Our custom pipeline stalls → **OSS-CRS** ensemble fallback running in parallel.
6. Live demo breaks entirely → pre-recorded backup video, narrated over.

Every rung is still a *real, honest* result. That is the whole point.
