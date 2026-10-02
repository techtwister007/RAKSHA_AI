# RAKSHA AI — The Plain-Language Explainer

For anyone non-technical: a CO, a family member, a judge who isn't a programmer.

## What the competition asks for
They give you a piece of software. Your system must do three things, completely on its
own:

1. **Find a security hole** — a weakness an attacker could abuse.
2. **Fix the hole** — write the repair itself.
3. **Prove the repair worked** — show the hole is closed and nothing else broke.

No human helping. And it must run on **Army computers that are cut off from the internet**
— so no calling any online service.

## The hard part
The obvious idea — use a big, smart online AI — fails twice over. Those AIs live on the
internet, and Army networks are sealed off, so you can't reach them. And even the best AIs
in the world get this *wrong about two-thirds of the time.* You're allowed only a small
AI that runs offline, and a small AI is weaker. So how do you win with a weaker tool?

## Our trick
**Don't trust the AI. Make it prove everything.**

Think of the AI as a clever but unreliable intern. You never let the intern *say* "trust
me, it's fixed." Instead, a strict **inspector** checks the work mechanically:

- the AI **guesses** a fix,
- the inspector **tests** it — does the original attack still work? do all the old
  features still work exactly as before? does a fresh round of attacks find anything new?
- only if every check passes does the fix count,
- if it fails, the AI tries again.

The AI can be weak, because the AI isn't the one deciding what's true. **The inspector
decides, and the inspector can't be fooled.** That's why a small offline AI is enough.

## Why a better AI still helps (if the inspector does the real work)
Picture a courtroom. The inspector is the **judge** — the verdict is final and can't be
bribed. The AI is the **lawyer** — it builds the case for the judge to rule on. A better
lawyer never overrules the judge, but walks in with a much stronger case, so the judge
says "yes" sooner. We use a judge *and* a good lawyer: the judge keeps us safe, the lawyer
makes us effective.

## Why this wins
- **Light and cheap** — a small AI on one computer, no internet, no giant hardware.
- **Runs where it matters** — fully offline, so it works on sealed Army networks where
  internet-dependent tools are useless.
- **Trustworthy** — we never report a problem we can't *show*, and never ship a fix we
  can't *prove*. For the military that's vital: a false alarm wastes scarce expert time,
  and a bad "fix" could break something live. Our system would rather stay quiet than
  guess.

## The clever extras
- **Rules of Engagement** — like a weapon, the AI has permission levels. On a training
  system it may fix things by itself; on a critical war-fighting system it may only
  *suggest* and wait for two officers to approve.
- **The vaccine** — once it fixes one bug, it automatically checks every other system for
  the same mistake. Fix one, protect all.
- **The receipts** — every fix comes with a sealed evidence file an officer can sign off.
  We're not asking anyone to trust the AI; we're handing them the proof.

## In one breath
> The task is an AI that finds, fixes and proves security bugs — by itself, offline, on
> Army computers. Everyone else will reach for a big online AI that can't run there and
> isn't good enough anyway. Our bet: a small offline AI that is never trusted, wrapped in
> a strict inspector that proves every fix. It's lighter, it runs where the others can't,
> and it never cries wolf.
