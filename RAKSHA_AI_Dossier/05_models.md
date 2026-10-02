# 05 · The Model Choice

## The lesson the research forces on us

A plain small model is terrible at this: a bare Qwen2.5-Coder-32B scores ~9% on
SWE-bench, and Qwen3-Coder-30B ranges 7–51% depending on setup. But the *same size*
model, **trained as an agent and paired with a proper harness**, reaches 60–71% on the
same benchmark (SWE-Swiss-32B 60.2%, SWE-Master-32B 70.8% with test-time scaling,
Qwen3-Coder-Next >70%, Mocha-Coder-32B 62.6%).

**The lesson lands exactly on our core bet: the scaffold and the training matter far
more than raw size.** A 32B already fine-tuned into an SWE agent beats two generic 8B
models. And test-time scaling — sample several candidate patches, let the verifier pick
— adds ~10 points for free, which is a perfect fit because our verifier (the five-check
gate) already exists and we have offline compute to spend.

## The sober reality check (put this on a slide)

Security find-and-fix is *harder* than general coding, and nobody has solved it:

- Best frontier agents: ~18% PoC generation, ~34% patching on SEC-bench.
- SEC-bench Pro (real browser-engine bugs): strongest config ~32%, open-weight baseline
  ~12% — and the majority stay unsolved even with a 90-minute budget.
- Best security *detection* model: ~24% F1 on a 25,440-function CVE benchmark.
- Fine-tuning security models gives "calibration without comprehension" — more
  confidence, not more correctness.

**Do not promise a general-coding score as our bug-fix rate.** Expect lower on security
specifically, and let the gate protect precision. The reality check is not bad news for
us — it is the *argument for the whole design*: if even frontier models fail two-thirds
of the time, the winning move is not a bigger model, it is a better scaffold and an
incorruptible verifier. We compete where the losses actually are.

## The RAKSHA model plan — a two-model split (fits 32 GB)

| Role | Model | Why |
|------|-------|-----|
| **Repair brain** (heavy lifter) | Qwen3-Coder-Next 32B (or SWE-Swiss-32B) | Best open coding-agent; writes the actual patch and the regression test |
| **Security advisor** (specialist) | Foundation-sec-8B-Reasoning (Cisco, Llama-3.1 8B) | Knows CWEs/CVEs/MITRE; classifies the bug, judges exploitability, checks the fix addresses the *security* root cause, not just the crash |

The coding model fixes; the security model keeps it honest about whether the fix is
*securely* correct. Both co-resident in 32 GB at Q4/Q5, with room for context.

Candidates to also consider: **RedSage** (~8B agentic cybersecurity model) for the
advisor role; **CyberPal 2.0** (4B–20B) as a lighter alternative.

## Task decomposition (copy it at runtime)

The best models all split the job into three sub-skills. We mirror this in the
pipeline:

- **Localize** → done deterministically by ripwire (feed the model one function, not
  the whole repo).
- **Repair** → model + template/retrieval lanes.
- **Test generation** → the model writes the regression test that *proves* the fix.
  This goes straight into the evidence bundle — the model doesn't just patch, it
  produces the proof.

## The local "JEV-style" decision layer (buildable, offline)

JEV (TypeSafe) is a cloud-only "System One" model that returns fast, calibrated typed
decisions instead of text — great for routing/gating, wrong for us because it is online.
We steal the *concept*, not the product: a tiny local **calibrated classifier** (a
small model with a classification head, which research shows hits ~0.95 F1 on BigVul,
or even logistic regression over features) that does three cheap jobs:

- **Finding triage** — rank 800 crashes before spending model tokens.
- **Lane routing** — decide template vs. retrieval vs. LLM, so the 32B only runs when
  it must (directly improves the *resource-utilisation* score).
- **Patch gating** — kill obviously-bad candidates before the expensive differential
  test.

This is itself a "don't trust free-form AI judgement" tool: bounded, typed, calibrated.
It is the intern's dispatcher — not the inspector, not the mechanic.

## Self-improvement (design for it, be honest about the demo)

QLoRA nightly refresh on validated fixes (via LLaMA-Factory) is a real capability
multiplier and a legitimate design feature. But it will not visibly improve anything
inside 36 hours. Say so: *"the deployment design includes periodic on-premise QLoRA
refresh from validated fixes; the prototype demonstrates the three online learning
loops"* (corpus, template mining, failure memory). Honesty here reads as maturity, and
a technical judge will catch an over-claim instantly.
