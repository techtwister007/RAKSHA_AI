# 04 · Tool Map — Build Almost Nothing

The strategy: **assemble proven open-source parts, contribute only the genuinely new
pieces.** This is what keeps us lightweight (jury criterion) and fast to build (36-hour
finale). Legend: **TAKE** = use as-is · **WRAP** = thin adapter · **BUILD** = our work.

## The full pipeline, stage by stage

| Stage | What it does (plain words) | Tool | Action |
|-------|----------------------------|------|--------|
| Agent loop | Drives the model: read → edit → test → retry | mini-SWE-agent / OpenHands | TAKE |
| Repair brain | Proposes fixes and tests | Qwen3-Coder-Next 32B (or SWE-Swiss-32B) | TAKE (weights) |
| Security advisor | Judges CWE / exploitability / depth of fix | Foundation-sec-8B-Reasoning | TAKE (weights) |
| Model serving | Runs models offline | vLLM / llama.cpp | TAKE |
| Find — crash bugs (C/C++) | Random-input hammering | AFL++, libFuzzer, honggfuzz | TAKE |
| Find — bugs (Java) | Fuzzer **with built-in security detectors** | Jazzer | TAKE |
| Find — bugs (JS/Node) | Same, for JavaScript | Jazzer.js | TAKE |
| Find — bugs (Python) | Coverage-guided fuzzer | Atheris | TAKE |
| Find — Python **security** | Security tripwires for Python | **PySecSan** (in OSS-Fuzz) | TAKE + extend |
| Find — non-crash / authz | "Two users, same answer = bug" | metamorphic oracle | **BUILD** |
| Harness writing (C) | Auto-writes the fuzz entry point | OSS-Fuzz-Gen + Fuzz Introspector | TAKE + WRAP |
| Harness writing (Java) | Automatic, no harness needed | Jazzer autofuzz | TAKE |
| Read code / find patterns | Static analysis | Semgrep, CodeQL, Joern | TAKE |
| Static taint (Python) | User input → dangerous sink | PySA, Bandit | TAKE |
| Localise the bug | Trace → function → callers → tests | **ripwire** | TAKE |
| Fix — easy cases | Known bug → known fix shape | fix-template library | BUILD (small) |
| Fix — similar past fixes | "How was this fixed before?" | FAISS index over ARVO pairs | WRAP |
| Prove — differential test | Did old behaviour change? | our harness over the fuzz corpus | **BUILD** |
| Prove — regression | Do existing tests still pass? | project's own JUnit / pytest / Jest | TAKE |
| Prove — re-fuzz | New bug after the fix? | AFL++ / Jazzer again | TAKE |
| Practice bugs | Real bugs w/ fix + trigger, pre-built | ARVO (6,100), SEC-bench | TAKE |
| Patch benchmark | AI-patching-specific scoring | AutoPatchBench, PatchBench | TAKE |
| Pick best of N patches | Test-time-scaling selector | our gate + verifier | WRAP |
| Whole-system fallback | A working CRS if ours stalls | OSS-CRS | TAKE |
| Self-improve | Retrain on our own wins | LLaMA-Factory (QLoRA) | TAKE |

## Extra lanes for real-world targets (not just C libraries)

Military software is far more often a web service with an outdated library and a
hardcoded password than a C parser with a heap overflow. These lanes catch what pure
fuzzing misses — and most are **build-free**, so they keep working even if the build
fails.

| Need | Tool | Action |
|------|------|--------|
| Running web service / REST API | Schemathesis, RESTler, OWASP ZAP, Nuclei | TAKE |
| Binary only, no source | Ghidra headless, AFL++ QEMU mode | TAKE |
| **Vulnerable dependencies** (most common real bug) | OSV-Scanner (offline DB), Trivy, Grype | TAKE |
| Hardcoded secrets | Gitleaks | TAKE |
| Config / IaC misconfig | Checkov, KICS | TAKE |
| Software bill of materials | Syft → CycloneDX | TAKE |

## Offline supply & safety (the make-or-break plumbing)

| Need | Tool | Action |
|------|------|--------|
| Python mirror | bandersnatch / devpi | TAKE |
| Java mirror | Nexus / Reposilite | TAKE |
| Node mirror | Verdaccio | TAKE |
| OS packages | aptly | TAKE |
| Policy engine (ROE) | Open Policy Agent (OPA) | TAKE |
| Signing / attestation | cosign, in-toto | TAKE |
| Sandbox isolation | Docker `--network none`, gVisor / Firecracker, seccomp | TAKE |

## What is actually left for us to BUILD

This short list **is** our novelty. Nothing more.

1. **Python security sanitizer extensions** — fill gaps PySecSan doesn't cover
   (SQL drivers, pickle/yaml, SSRF).
2. **Metamorphic authz oracle** — the two-users check; no sanitizer anywhere catches
   authz bypass.
3. **Unified finding record** — the SARIF + proof extension that makes all finders feed
   one pipeline.
4. **Differential-corpus gate** — the overfitting-patch killer, with the determinism
   pre-flight.
5. **ROE policy layer** — autonomy as doctrine (file 09).
6. **Vulnerability Vaccine** — one fix → fleet-wide variant sweep (file 09).
7. **Offline glue, operator console, evidence bundle** — the product skin.

Everything else is download-and-wire. We are assembling proven parts and contributing
seven genuinely new pieces — precisely the story that scores on *novelty* while staying
*lightweight*.

## Licensing note
Confirm every weight/tool licence permits our use. Qwen3-Coder is Apache-2.0 (clean);
Foundation-sec is open-weight; the fuzzers and scanners are permissive/OSS. Keep a
`THIRD_PARTY.md` of licences in the final bundle — a defence acceptance board will ask.

## Wired in today (October 2026)

| Tool | Where in RAKSHA | How to switch it on |
|------|-----------------|---------------------|
| OSV-Scanner | take lane: dependency advisories, confirmed by re-match | `RAKSHA_TAKE_OSV_SCANNER=1` (`RAKSHA_OSV_OFFLINE=1` + local DB on the sealed box) |
| Gitleaks | take lane: secrets, confirmed by re-match | `RAKSHA_TAKE_GITLEAKS=1` |
| Checkov | take lane: IaC / configuration, confirmed by re-match | `RAKSHA_TAKE_CHECKOV=1` |
| Semgrep | take lane: static leads on a bundled offline ruleset; count only when cross-confirmed | `RAKSHA_TAKE_SEMGREP=1` |
| cosign | public-key seal on every evidence bundle | `RAKSHA_COSIGN_KEY=<key>` (`python -m raksha.cosign init DIR`) |
| Open Policy Agent | rules of engagement as policy code; stricter answer wins | `RAKSHA_OPA=1` |
| Z3 | bound and reachability proofs | baked into the image (`[reasoning]` extra) |

`RAKSHA_TAKE_ALL=1` turns on every scanner lane that is installed. Measured on the demo estate:
90 extra findings in about 15 seconds, fully offline.
