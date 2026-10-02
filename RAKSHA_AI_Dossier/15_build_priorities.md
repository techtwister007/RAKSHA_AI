# 15 · Build Priorities — What To Do First

The dossier describes a rich system. The danger with a rich system is building all of it
badly. This file is the antidote: a single ordered view of what matters most, so the team
always knows what to work on next and what to drop if time runs short.

## The four tiers

| Tier | Meaning | Rule |
|------|---------|------|
| **CORE** | Without these, nothing works | Must be flawless |
| **HIGH-VALUE** | Turns a demo into a product | Build if core is solid |
| **WOW** | Wins the room | A few, done perfectly, beat many done poorly |
| **STORY-ONLY** | One slide, no code | Describe, don't build |

## CORE — build and harden these first

1. **The unified finding record** (SARIF + proof block). The keystone. Prove three
   oracles → one record → one gate on trivial targets **before anything else** (file 14,
   item 1).
2. **The five-check gate**, including the differential-corpus check with its determinism
   pre-flight (files 03, 06).
3. **The build agent + offline mirror + build-free fallback.** The weakest link; the
   single point of total failure (file 06). This is where graceful degradation lives.
4. **One full vertical slice** on one language (Java recommended — Jazzer gives the most
   per hour): ingest → find → localise → repair → prove → signed bundle.
5. **Sandboxing** — no-network containers, cgroups, seccomp (file 06, gap 10). Non-
   negotiable: we execute untrusted code on an Army box.
6. **Model serving offline** (vLLM + the two-model split, file 05).

If only the CORE works, you still have a real, honest, demonstrable system.

## HIGH-VALUE — build once core is solid

- SBOM, signed attestations, reviewable patch packet with rollback (file 07).
- Ranked risk register (file 07) — "fix these 3 first."
- The build-free lanes that catch real-world bugs: dependency scan (OSV), secrets
  (Gitleaks), config (Checkov) (files 04, 06).
- The operator console screens 1, 3 and 5 — the three that carry the demo (file 11).
- The sneakernet offline-refresh kit (file 07).

## WOW — pick a few, make them perfect

Priority order for impact-per-effort:

1. **Cable-pull offline install** (file 08) — the moat made visible. Low effort, huge.
2. **Live Log4Shell + split-screen proof** (file 08) — Java, Jazzer's built-in detector.
3. **Public rejection of a bad patch** (file 08) — the gate refusing an overfitting fix.
4. **ROE slider** — same fix, different authority per asset (file 09).
5. **Vulnerability Vaccine sweep** (file 09) — if time allows; it's the hardest to fake.

Console screens 2, 4, 6 support these.

## STORY-ONLY — one slide each, no code

Spin-offs (file 10), digital-twin rehearsal, red-vs-blue self-play, two-person rule,
mission-aware priority, nightly QLoRA self-improvement (file 09, 05). All legitimate, all
describable, none worth finale build time.

## The kill-switch rules (decide in advance, obey them)

- Build agent can't produce a compiling/coverage harness by a set checkpoint → hand-write
  harnesses for the demo target, say so openly.
- LLM repair lane not beating templates by a set checkpoint → demo templates as primary,
  LLM as fallback. Still impressive, still honest.
- Their target won't build → switch to a bundled ARVO target, reframe as a portability
  demo. A working demo on target B beats a dead terminal on target A.
- Anything in WOW slipping → cut it before it threatens CORE. A flawless core demo with
  three wow beats beats a broken attempt at all five.

## The one sentence to keep on the wall

> **Make CORE flawless. Make a few WOW beats perfect. Describe the rest. Never let a
> nice-to-have break a must-have.**
