# RAKSHA AI — the technology horizon (2026 → 2030)

The finale asks for a system that finds, fixes and proves vulnerabilities on an air-gapped
military network. That is the product. This document is the **wider perspective**: the technologies
that will define software assurance over the next five to ten years, which of them RAKSHA already
runs, which it is wired for, and which it names as its roadmap. It exists so the jury sees that the
architecture was designed for where the field is going, not only for the demo on the day.

The organising idea the design commits to:

> **Don't scan for vulnerabilities. Model what the system must never do — then make the machine
> try to do it, and refuse to speak without proof.**

Three rules hold across every item below, present and future, and are what keep the system honest
as it grows:

1. **The verifier is the brain, not the model.** No neural component — one model or twelve — ever
   decides whether a vulnerability exists or a patch is correct. A deterministic five-check gate
   does. Every future "intelligence" plugs in as a *proposer* or a *ranker* behind that gate.
2. **Presence, never absence.** The system never says "secure". It reports what it proved, and the
   boundary of what it did not analyse.
3. **Offline by construction.** Every capability degrades to a documented deterministic fallback
   with no network and no GPU, because that is where classified code lives.

## Legend

**NOW** — built and tested in this repository · **WIRED** — the seam exists; the capability turns on
when its hardware/weights are present · **ROADMAP** — designed-for, not yet built, with the honest
reason.

---

## 1. Post-quantum cryptography and crypto-agility — **NOW (lane) + ROADMAP (migration)**

A cryptographically-relevant quantum computer breaks RSA, ECC and Diffie-Hellman. NIST has
finalised the replacements (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), and defence
guidance now treats migration as a planning requirement, not a theory.

- **NOW**: a build-free crypto lane finds weak primitives (MD5/SHA-1 for signatures, DES/RC4, AES-ECB,
  static IVs, RSA < 2048, disabled certificate verification, obsolete TLS) deterministically, with a
  replaying match, in any language.
- **NOW**: a **PQC-readiness inventory** — not findings, an inventory — of every RSA/ECC/DH/signature
  use, each tagged quantum-vulnerable or not, each with its NIST replacement, aggregated into a
  migration blast-radius for the Commander's Brief.
- **ROADMAP**: generating and proving the migration patch (hybrid X25519+ML-KEM first), and a
  "harvest-now-decrypt-later" exposure estimate per channel.

We deliberately do **not** claim to *use* a quantum computer. The quantum angle that matters for a
defence network is readiness, and that is deterministic and offline.

## 2. Heterogeneous intelligence — the model parliament and the decision funnel — **NOW**

A single LLM has systematic blind spots, and a biased model is a real risk on a classified network.
The answer is not a bigger model; it is an ecosystem where cheap models filter, several models
disagree in the open, and a deterministic kernel decides what may be believed.

- **NOW**: a **fast decision funnel** (the "decision-model" tier) ranks tens of thousands of candidate
  sites deterministically — severity, sink presence, reachability, structural path, entry-point
  shape — so expensive fuzzing and the repair model run only where cheap signals say it is worth it.
  It accepts a model score when one is served, but the model only re-orders; it can never veto a
  real bug below the floor.
- **NOW**: a **model parliament** — independent roles (coding model, security advisor, a second
  opinion) classify a finding, and the measured **disagreement** becomes an *investigation signal*:
  the system looks harder where its reasoners diverge. The parliament annotates; it never sets
  status. Offline, disagreement reads `unmeasured`, never a false 0.
- **NOW**: an **evidence-fusion kernel** combines independent channels (exploit replay, deterministic
  match, structural path, cross-confirmation, model votes) into a transparent confidence, with model
  votes capped so they can never dominate, and the "proven" threshold unreachable without a
  non-model reproducing channel. This is the quantitative face of "no reproducer, no report".
- **WIRED**: extra model roles (`triage`, `red`, `judge`) are addressable by name through the one
  inference interface, so a third weight — a small fast model, an independent attacker — plugs in
  without touching the pipeline.

## 3. Adversarial self-defence — the independent red team — **NOW**

Asking one model "is my patch correct?" is correlated evidence. RAKSHA runs an **independent red
team** against every proven patch: the reproducer's deterministic neighbourhood at a wider radius,
the mutation engine against the patched build, and (when a model is served) a `red`-role model
proposing fresh inputs — all purely to *falsify the fix*. A patch only stays VERIFIED if the red
team cannot make the oracle fire again. This is the blue-repair / red-attack loop the field is
moving toward, bounded to fix-verification so it is safe to run autonomously.

## 4. Concurrency and temporal security — **NOW (race oracle) + ROADMAP (schedule fuzzing)**

Many serious defects are about *order*, not reachability: time-of-check/time-of-use, a check that
runs after the action, a data race under an alternate schedule.

- **NOW**: a **ThreadSanitizer oracle** (and Go's `-race`) turns a data race into an abort the gate
  treats exactly like a memory bug — CWE-362, with the racing stacks as evidence.
- **ROADMAP**: schedule fuzzing (explore thread interleavings), a happens-before model, and explicit
  TOCTOU/state-transition checks. These need a per-target state model; the race oracle is the
  honest first rung and it is in the box now.

## 5. Attack-chain reasoning and mission impact — **NOW**

A vulnerability is not scored in isolation on a military network; what matters is whether a chain of
individually-moderate weaknesses reaches a mission-critical function.

- **NOW**: an **attack graph** composes findings (a leaked credential → an unauthenticated endpoint →
  an RCE) into chains, scored by **attack economics** — the cheapest viable path to impact — so the
  operator is told "of 1,800 findings, these few form a real path", not handed a flat list.
- **NOW**: an **asset registry** (data, per codebase) carries a mission-impact tier that weights the
  risk ranking, so a flaw on a command function outranks the same flaw on a test tool.
- **ROADMAP**: an adversary digital-twin that continuously searches for the cheapest new path as the
  estate changes.

## 6. Structural intelligence — code-property-graph lane — **NOW (lite) + ROADMAP (GNN)**

- **NOW**: deep find→fix→prove now spans **six languages** (C, Python, Go, Rust, JavaScript/TypeScript
  through synthesized harnesses; Java via the shipped driver), each through the one gate.
- **NOW**: a CPG-lite lane builds a source→sink graph and finds taint paths (Python via the real
  `ast`; C/Go via body analysis), producing *suspected* findings that exist to be cross-confirmed by
  a dynamic lane and to feed triage — a perception channel independent of the LLM.
- **ROADMAP**: a graph neural network over that CPG. The graph and its per-node features are already
  exported as the training-data hook; no learned model ships, and the doc says so.

## 7. Supply chain, provenance and reproducibility — **NOW**

- **NOW**: dependency findings carry **import-level reachability** (a CVE in an unused library is
  ranked down, not dressed up as an exploit); the signed evidence bundle is content-addressed and
  now **names the environment** (interpreter, platform, toolchain versions) the proof was made in,
  so a finding reproduced here and not there is distinguishable from a flaky one.
- **NOW**: external scanners (Semgrep / Gitleaks / OSV-Scanner) plug in as "take" lanes behind flags,
  cross-confirming our own findings when their binaries are carried; our lanes stay the floor.
- **ROADMAP**: call-graph-level reachability; a full build-provenance graph (source → compiler →
  binary) and binary/source correspondence for when the customer ships binaries, not source.

## 8. Trust rooted in hardware — confidential computing and attestation — **ROADMAP**

Whether the *binary actually running* is the one that was proven is a deployment property of the
customer's node (TPM, secure boot, remote attestation, confidential VMs). RAKSHA's bundle is
designed to be *attested* — its manifest is exactly what a measured-boot chain would check — but
RAKSHA does not itself attest the host. We state this as the customer's layer, not ours, rather than
claim a capability we cannot demonstrate on the finale node.

## 9. Memory-safe migration — Rust / CHERI — **ROADMAP**

When a memory bug cannot be safely patched in C, the safest remediation may be structural: isolate
the parser, reduce privilege, or migrate the component to a memory-safe implementation. RAKSHA's
remediation ladder already ends in *mitigation* and *refer-to-human* rather than forcing a code
patch; automated C→Rust migration and CHERI-style hardware bounds are named as the structural rungs
above it, as roadmap.

## 10. Federated and continuous assurance — **ROADMAP**

- Different establishments cannot share classified source, but they could share *sanitised* attack
  signatures and proof artifacts — a federated defence-learning network across distributed
  infrastructure. The vaccine sweep (one proven fix → a detection rule → a fleet sweep) is the
  single-site seed of this.
- Software is not static: dependencies, configuration and threats change. **Continuous assurance** —
  re-proving on drift rather than once a month — is the end state; the asset registry and the
  evidence-backed security memory are its foundations. Nightly re-runs are an ops task, not a model
  change, which avoids the poisoning risk of continuous fine-tuning.

## 11. The agent itself as attack surface — **NOW**

Autonomous agents are now a security problem in their own right. RAKSHA treats itself as
hostile-by-default and is *stricter* than the typed-tool-API designs the field proposes:

- The model has **no tools**. It returns text; RAKSHA applies the diff. There is no shell, no
  network, no filesystem in the model's hands.
- **Patch hygiene** refuses, before any gate run, a diff that leaves the fix site, grows beyond a
  cap, or introduces an execution/network/dynamic-load primitive the original did not have — so a
  prompt injection hidden in the target's own source cannot turn a fix into a backdoor.
- **Untrusted-source framing**: target code is fenced and labelled as data in every model prompt.
- One inference interface, and an air-gap guard that parses every shipped file to prove no other
  path to the network exists.

---

## What this adds up to for the jury

RAKSHA is not "an LLM that finds bugs" — that is becoming a commodity. It is an **autonomous
software-assurance system**: it models what the software must never do, uses cheap intelligence to
decide where to look and expensive intelligence to propose, runs an independent red team against its
own fixes, fuses independent evidence in a deterministic kernel, and reports the boundary of its own
knowledge — all offline, all behind a gate no model can overrule, and all designed for the
cryptographic, concurrent, and AI-adversarial threats of the next decade.

The exhaustive point-by-point vetting that produced this list — including what was deliberately left
as roadmap and why — is in `docs/external-review-vetting.md`.
