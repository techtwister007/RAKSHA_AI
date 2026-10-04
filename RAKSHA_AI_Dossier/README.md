# RAKSHA AI — Project Dossier

**Reasoning-based Autonomous Knowledge & Security Hardening Agent**
AI Kavach Grand Finale entry · EME School, Vadodara · Indian Army

---

## What this folder is

This is the complete, self-contained brief for RAKSHA AI. It exists so that anyone
on the team — or a mentor, or a judge — can read it cold and get the *whole* picture:
what the competition asks, what we are building, why it is built this way, what is
proven versus unproven, and how we win. Nothing important lives only in someone's
head or in a chat log.

Read the files in order. Each stands alone, but they build on each other.

| # | File | What it covers |
|---|------|----------------|
| 00 | `README.md` (this file) | Index and how to use the dossier |
| 01 | `01_competition_brief.md` | What AI Kavach asks for, decoded in plain words; scoring criteria |
| 02 | `02_core_idea_and_logic.md` | The one central bet, why it wins, the intern-vs-verifier logic |
| 03 | `03_architecture.md` | The full system: layers, pipeline, the nine stages |
| 04 | `04_tool_map.md` | Every component → the open-source tool that provides it (take / wrap / build) |
| 05 | `05_models.md` | The LLM choice, the two-model split, why size + training matters |
| 06 | `06_gaps_and_fixes.md` | Honest weak spots and the fix for each; confidence assessment |
| 07 | `07_deliverables.md` | What we actually hand over to make the system usable |
| 08 | `08_wow_factors.md` | The show-stoppers and the live demo beats |
| 09 | `09_differentiators.md` | ROE, the Vulnerability Vaccine, and the out-of-box ideas |
| 10 | `10_spinoffs.md` | Product spin-offs for one slide / future roadmap |
| 11 | `11_presentation_layer.md` | The operator console: six screens and the pitch arc |
| 12 | `12_scoring_alignment.md` | Every design decision mapped to the jury's criteria |
| 13 | `13_glossary.md` | Every difficult term, in plain words |
| 14 | `14_open_questions.md` | What is still genuinely undecided or unproven |
| 15 | `15_build_priorities.md` | What to build first — CORE / HIGH-VALUE / WOW / STORY tiers, kill-switch rules |

### Also in this folder (not numbered)

| File | What it is |
|------|------------|
| `EXECUTIVE_SUMMARY.md` | The whole project on one page — read this or the layman explainer first |
| `LAYMAN_EXPLAINER.md` | The same, for a non-technical reader (a CO, a judge who isn't a programmer) |
| `RAKSHA_submission_deck_v1.pptx` / `.pdf` | The 5-slide submission deck. **Status: v1 — see the note below** |

### On the deck's status (important)

The deck in this folder is **version 1**. The written documents (01–14) are **ahead of
it**: v1 predates the two-model split (Foundation-sec + Qwen), the Rules-of-Engagement
model, the Vulnerability Vaccine, and the SARIF keystone. Treat the documents as the
source of truth; the deck needs a v2 rebuild to match them before final submission. This
is the one place the dossier is deliberately out of sync, and it is flagged here so no
one is misled.

---

## Status note (2026-10-04)

This dossier is the **settled brief** and is kept as written. The build it describes is now
complete through Phase 11 (automatic harness generation): see `../HANDOVER.md` for the verified
state, the per-language matrix and the remaining work, and `../BUILD_PLAN.md` for the phase table
and scoring ledger. Where this brief says "planned" or "unproven", those two files say what
actually happened. The deck is still v1 (note above); its rebuild is `HANDOVER.md` P2-6.

---

## The thirty-second version

The competition wants an AI that, on its own and fully offline, **finds** a security
hole in unfamiliar software, **fixes** it, and **proves** the fix works — ready to run
on the Indian Armed Forces' own air-gapped networks.

Everyone will reach for a big online AI. That can't run on a sealed network, and
independent tests show even the best models fail this task roughly two-thirds of the
time. So our bet is different:

> **Use a small offline AI, but never trust it. Wrap it in a strict mechanical
> inspector that proves every fix. Weak guesser, incorruptible judge, airtight proof.**

That design is lighter, it runs where the others can't, and it never cries wolf —
which maps exactly onto the three things the jury scores: resource-efficiency,
novelty, and lightweight deployment.

---

## The honest posture (read this before anything else)

This dossier does **not** pretend the system always works. It is built on one
principle that we state openly to the jury:

> **The system degrades, it does not die.** If the target won't build, we fall back
> to analysis that needs no build. If no fix validates, we issue a proven report
> instead of a patch. If a language isn't fully supported, we handle what we can and
> say what we can't. Nothing unproven is ever presented as proven.

That honesty is not a weakness in the pitch. For a defence jury it is the single most
trust-building thing we can show — because a tool that knows the limits of its own
authority is the only kind they would ever let near a live system.

---

## Status legend used throughout

- **TAKE** — use an existing open-source tool as-is.
- **WRAP** — thin adapter around an existing tool.
- **BUILD** — our own work (this is where our novelty concentrates).
- **PROVEN** — we are confident this works.
- **UNPROVEN** — plausible but not yet validated by us; flagged honestly.
