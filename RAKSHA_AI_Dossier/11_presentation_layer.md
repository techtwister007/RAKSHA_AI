# 11 · The Presentation Layer — The Operator Console

One operator console, built in our own stack (FastAPI + vanilla JS), served entirely
offline. The design rule: **every screen shows something the jury scores, with no
narration needed. The console is the pitch.**

## Screen 1 — Mission Board
Every target as a card: name, language(s), **build status (green = built / amber =
build-free mode, still finding / red = couldn't ingest)**, finding count, ROE level,
overall status. Amber is labelled a success state, not a failure. One glance = the whole
operation, and it shows multi-language scalability without a word.

## Screen 2 — Live Pipeline
The nine stages as a flowing diagram; findings light up and move through in real time.
You watch a finding travel SUSPECTED → CONFIRMED → PATCHED → VERIFIED. This is the
"it's actually working, live" screen — the antidote to a canned demo.

## Screen 3 — Finding Detail (the money screen)
- **Split-screen exploit replay:** attack hits vulnerable build (red), bounces off
  patched build (green).
- the **diff**, with the plain-English explanation beside it.
- the **five-check gate** ticking green one by one.
- the ranked `fix_site_set` and which repair lane won.
This is where Log4Shell gets fixed in front of the jury.

## Screen 4 — Evidence Vault
Every VERIFIED finding as a signed, downloadable bundle: reproducer, before/after, gate
results, SBOM, attestation, two-person signatures. A judge can **open one and verify the
signature live.** Proof you can hand over, not just claim.

## Screen 5 — Scorecard (leave this visible during judging)
The jury's own criteria as live KPIs:

| Resource | Speed | Precision | Autonomy | Scale |
|----------|-------|-----------|----------|-------|
| tokens/patch, VRAM, % fixed zero-inference | median time-to-PoV, time-to-patch | % with reproducer (100%), % patches surviving differential | zero-human-input count | targets in parallel, languages |

Plus two badges that never change: **NETWORK INTERFACES: 0** and **CLOUD CALLS: 0**.
We hand the judges their own scoresheet, already filled in.

## Screen 6 — Commander's Brief
Plain-language summary per finding, and a one-click **formal report in JSSD
service-writing format**, ready to go up the chain — optionally in Hindi. A cyber tool
that outputs a proper staff paper is a quiet show-stopper for this specific jury.

## The pitch arc the console enables

```
pull cable → Mission Board (amber proves graceful degradation)
→ Live Pipeline carries Log4Shell through
→ Finding Detail split-screen proof
→ inject a bad patch, gate rejects it
→ Vault, verify a signature live
→ vaccine sweeps the fleet on the Board
→ flip a C2 asset's ROE, the same fix now waits for two signatures
→ Commander's Brief prints the staff paper
(Scorecard sits there the whole time at 0 / 0)
```

Every beat is **seen**, not told. That is the difference between a team that *describes* a
system and a team that *operates* one in the room.

## Build notes
- Our stack, offline, no CDN, no external fonts/assets — everything self-contained
  (consistent with the air-gap claim; a console that phones out would contradict the
  whole pitch).
- Keep screens 1, 3 and 5 flawless; they carry the demo. The rest can be lighter.
