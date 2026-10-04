# 08 · Wow Factors & The Live Demo

The architecture will be similar across many teams (it's the AIxCC template everyone's
AI will suggest). We win the *room* with things the jury can **see**, not be told —
especially things that come from understanding the customer, which a competitor's AI
won't produce.

## The seven show-stoppers

1. **Install from a sealed SSD, cable pulled, live.** Twenty minutes from box to running
   system, with zero network interfaces shown on screen. Almost no one else will dare to
   demo truly offline. This is our moat made visible.

2. **Live Log4Shell.** Every judge knows Log4Shell. A sample Java service with the
   vulnerable log4j → Jazzer's built-in JNDI detector fires → RAKSHA patches → proof.
   The most famous vulnerability of the decade, found and fixed autonomously, offline,
   in front of them.

3. **Split-screen exploit replay.** Left: the attack hits the vulnerable build — red.
   Right: the same attack bounces off the patched build — green. Proof you can *see* in
   two seconds, no explanation needed.

4. **Public rejection of a bad patch.** Inject an overfitting "fix"; watch the
   differential gate refuse it on screen. Shows judgement, not just output. No other
   team will deliberately demo a failure — and that is exactly why it lands.

5. **The Vulnerability Vaccine.** After fixing one bug, RAKSHA auto-writes a detection
   rule from the fix and sweeps *every other codebase* for the same mistake. One fix →
   fleet-wide immunity. "We fixed one bug, and in the same minute found the same mistake
   in four other systems." (Full spec in file 09.)

6. **Commander's Brief.** Every finding produces two outputs: the technical bundle, and a
   one-paragraph plain-language brief a non-technical CO can act on — shown in Hindi on
   the console and in the text brief, and formattable as a proper JSSD staff paper. (The
   PDF export is single-font Latin; the Hindi brief is on-screen and in text, not in the
   PDF.) A cyber tool that outputs a service document is a quiet show-stopper for *this* jury.

7. **Three languages, one screen.** A C bug, a Java bug and a Python bug fixed in
   parallel by the same pipeline. (We support four — C/C++, Java, Node/JS, Python — but
   three on one screen is the clearest live proof; add JS if time allows.) Scalability
   made visible in one glance.

## The 7-minute pitch arc (every beat is on-screen)

```
1. The problem        frontier models fail ~2/3 of the time; Army networks are sealed
2. Pull the cable     NETWORK INTERFACES: 0 — and it keeps running
3. Mission Board      targets light up; amber = "build-free mode, still finding"
4. Log4Shell found    the pipeline carries it SUSPECTED → CONFIRMED live
5. Split-screen proof  red vulnerable build, green patched build
6. Reject a bad patch  the gate publicly refuses an overfitting fix
7. Vaccine sweep      one fix → variants found in other systems → fixed by template
8. ROE slider         flip a C2 asset to "recommend"; the same fix now waits for 2 sigs
9. Commander's Brief   one click → a formal staff paper up the chain
   (Scorecard panel visible the whole time: precision 100%, 0 cloud calls, VRAM, speed)
```

The difference we are dramatising: most teams *describe* a system; we *operate* one in
the room, offline, with the jury's own scoresheet visible the entire time.

## Wave 4 additions — the proof, the product, the honesty

These are built and on the console's *Demo Beats* and *Time-lapse* screens; each is in the
rehearsal runbook as a scripted beat.

- **"It says no."** One button runs four patches through the real gate, live: a shallow fix dies at
  the fuzz check, an unsafe diff is refused by hygiene before it builds, a weak fix passes the gate
  and is broken by the red team, the proper fix is accepted. Refusal, demonstrated, is the
  trust-maker — and it runs in under a minute.
- **Bring your own target.** A judge's media goes in; time-to-first-finding ticks on screen; a first
  finding appears with no restart. The intake path is bounded and refuses links, so a hostile medium
  cannot hang or escape.
- **Pull the cable, with the counter at zero.** The egress counter reads live; pull the cable, the
  carrier drops and the transmit delta goes flat. The air-gap claim, shown rather than asserted.
- **Replay it on your own laptop.** A signed verifier medium a judge runs with nothing but Python:
  it checks every seal and replays a finding — fires on the vulnerable copy, dead on the patched —
  in well under a minute.
- **The internal-CERT advisory.** One verified fix becomes a signed, numbered advisory with
  affected assets and the proven patch — the product framing a CERT actually ships.
- **Scrub the run.** The time-lapse replays the hash-chained journal of a long run, so the jury can
  see what the system was doing at any minute.

Honesty, folded in: the **claim audit** (`docs/claim-audit.md`) reconciles every claim above with a
built capability or rewords it; **recall** is now measured where the denominator is known (100% on
the mutation factory, 54.5% on fuzzable demo ground truth) rather than only declined; and the
real-world ARVO baseline is stated as a prep-node run through the same harness, never quoted as a
number we did not produce.

## Backup

Record the full demo at a safe point before judging. If anything dies live, narrate over
the recording and lose almost nothing. The pre-recorded run is the last rung of the
fallback ladder (file 06).
