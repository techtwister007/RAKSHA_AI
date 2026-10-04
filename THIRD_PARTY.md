# Third-party components and licences

A defence acceptance board will ask for this, so it is maintained from the start. RAKSHA's own code
(the `raksha/` package and the console) carries no third-party **runtime** Python dependency by
design — every runtime import is stdlib or a tool invoked as a subprocess. The components below are
the open-source tools and model weights the full deployment assembles; each is used under a
permissive or open licence. Confirm the exact version's licence before shipping the bundle.

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
