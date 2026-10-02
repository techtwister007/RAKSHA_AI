# RAKSHA AI — Executive Summary (one page)

**Reasoning-based Autonomous Knowledge & Security Hardening Agent**
AI Kavach Grand Finale · EME School, Vadodara · Indian Army

> *On the name:* RAKSHA (रक्षा, "protection") is the point; the expansion is a backronym.
> If asked what "Knowledge" covers, the honest answer is the accumulated, persisting
> knowledge the system builds — the learned fix-template library, the mined vaccine rules,
> and the retrieval index over past fixes — which is what makes each run smarter than the
> last. Have that answer ready rather than improvising it.

## The task
An AI that, on its own and fully offline, **finds** a security hole in unfamiliar
software, **fixes** it, and **proves** the fix works — ready to run on the Indian Armed
Forces' air-gapped networks. Scored on resource-efficiency, novelty and lightweight
design; the finale adds performance, speed, precision, functionality, scalability.

## The problem with the obvious approach
Big AI models live online (can't reach them on a sealed network) and, even so, fail this
task ~2/3 of the time. We are limited to a modest offline model (small *relative to the
frontier cloud models* — a 32B that runs on one GPU, not a trillion-parameter cloud
service), which is weaker.

## Our bet
> **Don't trust the AI — make it prove everything.** A small offline model *guesses* a
> fix; an incorruptible mechanical **gate** proves it (original attack dead, all old
> behaviour unchanged, fresh attacks find nothing). Weak guesser, strong judge, airtight
> proof. If nothing proves out, we issue a verified report, never a guess.

This is lighter, runs where competitors can't, and never cries wolf — mapping exactly
onto what the jury scores.

## How it's built (assemble, don't reinvent)
One pipeline, every language: each language's bugs are turned into the same "alarm," then
flow through **find → localise → repair → prove → attest → learn**. We **take** proven
open-source parts (AFL++, Jazzer, Atheris, PySecSan, Semgrep, ripwire, OSS-Fuzz-Gen,
vLLM, OSS-CRS, ARVO) and **build** only the genuinely new pieces: the unified
finding-record, the metamorphic authz oracle, the differential-corpus gate, the ROE
authority model, and the Vulnerability Vaccine.

## The brain
A two-model split that fits one 32 GB box: a 32B coding-agent model (Qwen3-Coder-Next /
SWE-Swiss) to write fixes, and a security-specialist 8B (Foundation-sec-Reasoning) to
judge whether a fix is *securely* correct. The verifier — not the model — decides truth,
so a small model is enough; a better model just finds the answer faster.

## What makes us hard to copy
- **Offline-deployment mastery** — installs from a sealed SSD, cable pulled, live. Most
  teams' "offline" systems secretly need the internet.
- **Rules of Engagement** — autonomy as military doctrine (Observe → Recommend →
  Act-with-approval → Act-autonomously), auto-tightening as risk rises; two-person rule
  for critical assets.
- **Vulnerability Vaccine** — one verified fix becomes a rule that sweeps the whole fleet
  for the same mistake.
- **Military-trust framing** — signed evidence bundles, fail-closed, human handoff,
  JSSD-format commander's brief. The AI that knows the limits of its own authority.

## Honest posture
We do not claim it always works. **It degrades, it does not die:** build fails → analysis
that needs no build; no fix validates → a proven report; limits stated plainly. Realistic
confidence in a flawless end-to-end demo is ~36%; in *a convincing demo of something
real*, ~85–90% — because of the fallback ladder. For a defence jury, that honesty is the
strongest trust signal we can give.

## The pitch in one line
> **Runs where classified code lives, and refuses to speak without proof.**
