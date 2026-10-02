# 01 · The Competition, Decoded

## What AI Kavach is

AI Kavach is a data-centric challenge to build robust technological solutions for
real-world defence and national-security problems. The specific task:

> *Build a cyber-reasoning system — an LLM laced with fuzzers, static and dynamic
> analysis, and a regression test harness — that autonomously finds a vulnerability,
> patches it, and proves the fix holds. The solutions worked out in the finale by the
> teams shall be pitched to run autonomously against specific customised
> infrastructure of the Indian Armed Forces.*

## The sentence, word by word

- **Cyber-reasoning system (CRS)** — a program that reasons about *other programs'*
  security by itself. The term comes from the 2016 DARPA Cyber Grand Challenge; the
  modern, LLM-powered version was the subject of DARPA's AI Cyber Challenge (AIxCC),
  whose finals concluded in August 2025.
- **LLM** — the AI language model. In our design, the unreliable but creative "intern."
- **laced with** — wired together with. The LLM sits *inside* a frame of hard tools,
  not on its own.
- **Fuzzer** — a tool that bombards a program with thousands of weird, malformed
  inputs to make it crash or misbehave. This is how you *find* bugs that crash.
- **Static analysis** — reading the code *without running it*, looking for dangerous
  patterns. (Proof-reading, not test-driving.)
- **Dynamic analysis** — watching the program *while it runs* to catch bad behaviour
  live. (Test-driving.)
- **Regression test harness** — the program's existing automatic "does it still work?"
  checks. "Regression" means *did my change break something that used to work?* The
  harness is the setup that runs all those checks.
- **Autonomously** — no human in the loop during the find→fix→prove cycle.
- **Proves the fix holds** — don't claim it's fixed; demonstrate it with evidence.
- **Customised infrastructure of the Indian Armed Forces** — the Army's own software,
  written or modified specifically for them, that no public tool has ever seen, living
  on a **sealed, offline (air-gapped) network.**

## The plain-English version

> Build a self-driving security mechanic. It pokes unfamiliar software until it finds a
> weakness, repairs the weakness, and hands over proof the repair works — all by
> itself, and all offline on Army systems.

## What gets scored

**Shortlisting (the 5-slide stage), by an expert jury:**

1. **Resource utilisation** — does it sip or guzzle compute?
2. **Novelty of idea** — is the thinking original?
3. **How lightweight the solution is** — small and deployable, not a heavy stack?

**Grand Finale (the 36-hour build), tested against a simulated IAF software
environment:**

- **Performance** — how many bugs found and patched
- **Speed** — how fast
- **Precision** — how often it is right, how little noise
- **Functionality** — does the full loop work, autonomously
- **Scalability** — does it hold up across many targets / languages

## What the brief implies but does not say out loud

1. **Offline is non-negotiable.** "Customised IAF infrastructure" means air-gapped.
   No cloud AI. No `pip install` at runtime. This single constraint eliminates most of
   what a naive team would build.
2. **The target is unknown.** "Customised" means we cannot pre-study it. The system
   must handle code it has never seen, possibly in a language we only partly support.
3. **Trust is the real currency.** Software that autonomously changes Army systems
   will never be accepted unless it can *prove* what it did and *know the limits of its
   own authority.*

These three implications — offline, unknown, trust — shape every design decision in
this dossier.
