# Third-party components and licences

A defence acceptance board will ask for this, so it is maintained from the start. RAKSHA's own code
(the `raksha/` package and the console) carries no third-party **runtime** Python dependency by
design — every runtime import is stdlib or a tool invoked as a subprocess. The components below are
the open-source tools and model weights the full deployment assembles; each is used under a
permissive or open licence. Confirm the exact version's licence before shipping the bundle.

## What the shipped code uses today

The tables further down list the full deployment's assembly. The code in this repository, as
committed, invokes only the following at runtime — everything else below is carried by the
sealed bundle when the operator provisions it, or is a planned "take" lane (`HANDOVER.md` P2-3).

| Component | Used by | Licence |
|---|---|---|
| Python 3.11+ standard library | everything (no third-party runtime package) | PSF |
| gcc + AddressSanitizer, gcov | C lane, autofuzz C coverage | GPL (toolchain; no linkage into our code) |
| JDK 17+, Apache Maven | Java lane | GPL+CE / Apache-2.0 |
| Go toolchain (native fuzzing, cover profile) | Go lane | BSD-3-Clause |
| git, `patch` | applying and reversing patches | GPL-2.0 (tools) |
| Apache Log4j 2.14.1 / 2.17.1, JUnit 5, Jazzer API | the bundled Java demo target only | Apache-2.0 / EPL-2.0 / Apache-2.0 |
| OASIS SARIF 2.1.0 schema (vendored in `schemas/`) | record format validation | OASIS, royalty-free |
| pytest, jsonschema | development only (`[dev]` extra) | MIT |

## Model weights

| Component | Role | Licence |
|---|---|---|
| Qwen3-Coder-Next 32B (or SWE-Swiss-32B) | repair brain | Apache-2.0 |
| Foundation-sec-8B-Reasoning (Cisco, Llama-3.1 8B) | security advisor | open weights (Llama-3.1 community licence) |

## Fuzzing and sanitizers

| Component | Role | Licence |
|---|---|---|
| AFL++ | C/C++ fuzzing | Apache-2.0 |
| libFuzzer / LLVM sanitizers (ASan/UBSan/MSan) | C/C++ fuzzing + oracles | Apache-2.0 WITH LLVM-exception |
| honggfuzz | C/C++ fuzzing | Apache-2.0 |
| Jazzer / Jazzer.js | JVM / Node fuzzing + security detectors | Apache-2.0 |
| Atheris | Python fuzzing | Apache-2.0 |
| PySecSan | Python security sanitizers (extended by us) | Apache-2.0 (OSS-Fuzz) |

## Static analysis, dependencies, secrets, config

| Component | Role | Licence |
|---|---|---|
| Semgrep | static analysis / vaccine rules | LGPL-2.1 |
| CodeQL | deep data-flow (optional) | proprietary — free for open-source; confirm use terms |
| Joern | code property graph | Apache-2.0 |
| OSV-Scanner | vulnerable dependencies (offline DB) | Apache-2.0 |
| Trivy / Grype | SCA alternatives | Apache-2.0 |
| Gitleaks | secrets | MIT |
| Checkov / KICS | IaC / config | Apache-2.0 |
| Syft (→ CycloneDX) | SBOM | Apache-2.0 |

## Serving, orchestration, offline supply, trust

| Component | Role | Licence |
|---|---|---|
| vLLM | offline model serving | Apache-2.0 |
| llama.cpp | CPU-only serving | MIT |
| mini-SWE-agent / OpenHands | agent scaffold | MIT |
| Open Policy Agent (OPA) | ROE policy engine | Apache-2.0 |
| cosign / in-toto | signing / attestation | Apache-2.0 |
| Docker · gVisor · Firecracker | sandbox isolation | Apache-2.0 |
| devpi · Nexus · Verdaccio · aptly | offline package mirrors | mixed permissive (confirm per tool) |

## Benchmarks and corpora

| Component | Role | Licence |
|---|---|---|
| ARVO (~6,100 bugs) | practice set, training data, ground truth | per-dataset terms — confirm |
| SEC-bench · AutoPatchBench · PatchBench | patch-scoring benchmarks | per-benchmark terms — confirm |
| OSS-Fuzz build recipes | build-agent RAG context | per-project (OSS-Fuzz, Apache-2.0) |

## Standards

| Component | Role | Licence |
|---|---|---|
| SARIF 2.1.0 schema (OASIS) | the finding record format | OASIS / royalty-free |

> Note: "confirm" above marks a licence whose exact terms depend on the version or dataset and must
> be verified against the shipped artifact before the bundle is handed over.
