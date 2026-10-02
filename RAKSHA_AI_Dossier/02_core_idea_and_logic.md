# 02 · The Core Idea and Its Logic

## The hard problem nobody says out loud

The obvious approach — point a big, smart AI at the code and ask it to find and fix
bugs — fails here for two independent reasons:

1. **The big models live online.** Army networks are sealed. You cannot reach them.
2. **Even the best models are bad at this.** Independent benchmarks (SEC-bench,
   SEC-bench Pro, SecVulEval) show the strongest frontier models solve this task only
   ~18–34% of the time, and the best *detection* model scores ~24% F1 on a large CVE
   benchmark. Research on fine-tuning security models found "calibration without
   comprehension" — fine-tuning makes a model *more confident*, not *more correct*.

So "just use a smarter AI" is both unavailable (offline) and insufficient (nobody has
solved it). We are allowed only a **small** offline model. A small model is weaker.
The whole design question is: **how do you win with a weaker tool?**

## The one central bet

> **Do not trust the AI. Make it prove everything.**

Think of the AI as a clever but unreliable intern. You never let the intern *say*
"trust me, it's fixed." Instead a **strict inspector** checks the work mechanically:

- The AI **guesses** a fix.
- The inspector **tests** it: Does the original attack still work? No. Do all the old
  features still behave exactly as before? Yes. Does a fresh round of attacks find
  anything new? No.
- Only if every check passes does the fix count.
- If any check fails, the AI tries again with the inspector's feedback.

The AI can be weak, because **the AI is not the thing that decides what is true.** The
inspector decides, and the inspector is mechanical checks that cannot be fooled. That
is why a small offline model is enough.

## The intern paradox — and its resolution

A sharp question: *if the mechanical inspector does the deciding and the AI is just an
unreliable intern, why does a bigger, security-trained AI help at all?*

Because **"deciding what is true" and "thinking of what to try" are different jobs,**
split on purpose. Use a courtroom:

- The **verifier is the judge** — decides what is true, verdict final and
  incorruptible. But the judge does not investigate the case or write the arguments.
- The **LLM is the lawyer** — it generates the case for the judge to rule on. A better
  lawyer never overrules the judge, but walks in with a far stronger case, so the judge
  says "yes" more often and sooner.

Concretely, a bigger / security-trained model helps in three ways *without ever being
trusted to decide*:

1. **A better guesser needs fewer guesses.** The judge will reject 1,000 bad patches
   all day — you just never find a fix. A strong model's first few guesses are far more
   likely to contain the real one. (This is why "test-time scaling" — sampling several
   patches and letting the verifier pick — lifts scores ~10 points.)
2. **Localisation and understanding are hard thinking, not yes/no checks.** Working out
   *which function* is vulnerable and *why* (the CWE, the root cause) is reasoning the
   mechanical code cannot do. A security-trained model points the repair at the right
   place.
3. **It avoids the shallow-but-test-clean fix.** A naive model "fixes" SQL injection by
   escaping one quote — passes the tests, leaves the hole. A security-trained model
   knows to parameterise the query. The verifier catches *regressions*; it does not
   catch *a fix that is shallow but test-clean*. The security model raises the odds the
   fix is deep.

**One line:** the verifier guarantees we never ship a *wrong* fix; the better LLM
raises the odds we *find a right one at all, quickly*. The mechanical code is a floor
on correctness; the model is the engine of discovery. Improving each improves a
different dimension — the verifier makes us **safe**, the model makes us **effective**.

## Why this also wins the scoring

- **Lightweight / low-resource** — a small model on one box, no internet, no cluster.
  Exactly what the jury rewards.
- **Runs where it matters** — fully offline, so it works on the sealed network where
  every internet-dependent competitor is dead on arrival.
- **Trustworthy** — we never report a bug we cannot *demonstrate*, and never ship a fix
  we cannot *prove*. For the military this is decisive: a false alarm on a classified
  system wastes scarce cleared-expert time, and a bad "fix" could break something live.
  Our system would rather stay silent than guess.

## The posture that falls out of the bet

Because the verifier — not the model — is the source of truth, the system can fail
*safely*:

- Build won't work? Fall back to analysis that needs no build.
- No fix validates? Issue a proven vulnerability report, not a patch.
- Language only partly supported? Handle what we can, state what we can't.

**Degrade, don't die. Prove everything. State every limit.** That is the whole
character of RAKSHA in three phrases.
