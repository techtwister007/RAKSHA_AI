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
   one-paragraph plain-language brief a non-technical CO can act on — optionally in
   Hindi, and formattable as a proper JSSD staff paper. A cyber tool that outputs a
   service document is a quiet show-stopper for *this* jury.

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

## Backup

Record the full demo at a safe point before judging. If anything dies live, narrate over
the recording and lose almost nothing. The pre-recorded run is the last rung of the
fallback ladder (file 06).
