# 13 · Glossary — Every Difficult Term, Plainly

**Air-gapped** — a network with no connection to the internet, physically sealed. Army
classified systems are air-gapped. Nothing can `pip install` or call a cloud AI there.

**AST (Abstract Syntax Tree)** — the structured, tree form of source code a tool parses
it into. We swap in a fixed function by editing the tree, not by text find-and-replace,
which small models get wrong.

**AST delta** — how much a patch changed, measured on the tree. Small delta = minimal,
surgical fix (good). Large delta = suspicious.

**Attestation** — a signed statement of *what was tested, by which version, with what
result*. Makes the evidence tamper-evident.

**ARVO** — Atlas of Reproducible Vulnerabilities for Open-source software: ~6,100 real
bugs, each with a pre-built vulnerable version, a fixed version, a trigger and the gold
patch. Our practice set, training data and ground truth.

**Bug class / CWE** — a category of vulnerability (e.g. SQL injection, buffer overflow).
CWE = Common Weakness Enumeration, the standard numbered list of these categories.

**DAST** — Dynamic Application Security Testing: probing a *running* application from the
outside (e.g. a live web service) for vulnerabilities. Used in our web-service lane.

**JSSD** — the Indian Armed Forces' Joint Services house style for service writing — the
format staff papers, notes and reports are written in. Our Commander's Brief can output
in it.

**OPA (Open Policy Agent)** — an open-source, offline policy engine. Our Rules of
Engagement become a signed OPA policy file; OPA answers "is this action allowed?"

**SAST** — Static Application Security Testing: finding vulnerabilities by reading code
*without running it* (Semgrep, CodeQL, Bandit). The build-free side of our finding.

**CRS (Cyber-Reasoning System)** — a program that reasons about other programs' security
by itself. What the competition asks us to build.

**Corpus** — the pile of inputs a fuzzer has collected. Our differential gate replays the
whole corpus to check behaviour didn't change.

**Differential testing** — run the same inputs through the old and new build; if any
non-crashing input gives a different answer, the patch changed behaviour (likely broke
something). The core of our overfitting-patch check.

**Dynamic analysis** — studying a program while it runs.

**Fuzzer / fuzzing** — bombarding a program with many malformed inputs to force a crash or
bad behaviour. "Coverage-guided" means it steers inputs toward unexplored code paths.

**Gate** — our five mechanical checks a patch must pass. The incorruptible inspector.

**Harness (fuzz harness)** — the small wrapper that feeds fuzzer bytes into the specific
function under test. Often missing; sometimes must be written automatically.

**IDOR / BOLA** — "Insecure Direct Object Reference" / "Broken Object-Level
Authorisation": a user accessing data they shouldn't by changing an ID. An authz bug that
doesn't crash — caught by the metamorphic oracle.

**LLM** — large language model; the AI that proposes fixes. Our "intern."

**Localisation** — working out exactly which function/line the bug is in.

**Metamorphic testing** — checking a program by comparing two related runs instead of
knowing the "right" answer (two users → same response = authz bug).

**Mitigation (lane)** — a provably-safe hardening patch used as a floor when no elegant
fix validates. Blunt but verified.

**Oracle** — anything that can tell you a bug just happened. A sanitizer is an oracle; our
tripwires and the metamorphic check are oracles too.

**Overfitting patch** — a "fix" that silences the one test but secretly breaks normal use.
The differential-corpus check catches it.

**Pass@1** — how often a model's *first* answer is correct. The headline accuracy number.

**PoV (Proof of Vulnerability) / reproducer** — a concrete input (or request pair) that
triggers the bug. "No reproducer, no report" is our precision rule.

**Quantization (Q4/Q5/Q8)** — shrinking a model to fit in memory. Lower number = smaller,
faster, slightly less accurate. Q4 ≈ quarter size.

**QLoRA / fine-tune** — cheaply teaching a model new tricks from your own examples without
retraining the whole thing.

**Regression / regression test** — did my fix break something that used to work? The
regression suite is the program's own "does it still work?" checks.

**ROE (Rules of Engagement)** — our per-asset authority model for how much the system may
do on its own (Observe → Recommend → Act-with-approval → Act-autonomously).

**SARIF** — Static Analysis Results Interchange Format; the OASIS JSON standard that
security tools output. We extend it with a proof block so every finder speaks one format.

**Sanitizer / bug detector / probe** — instrumentation that makes a silent bad action
(overflow, SQL injection) loudly abort so it can be caught. ASan (memory), Jazzer
detectors (JVM security), PySecSan (Python security).

**SBOM (Software Bill of Materials)** — a machine-readable list of every component inside
a piece of software.

**Scaffold** — the reusable loop around the model that lets it act (read files, run
commands, edit code) instead of just chatting. We take an existing one (mini-SWE-agent).

**Static analysis** — studying code without running it.

**Test-time scaling (TTS)** — spend more compute at answer time by generating several
attempts and keeping the best (the verifier picks). Cheaper and safer than a bigger model;
lifts scores ~10 points.

**Variant analysis** — after finding one bug, searching for the same mistake everywhere
else. Our Vulnerability Vaccine automates this from a verified fix.

**Verifier** — see Gate. The part that decides what is true. In our design, the brain.
