# RAKSHA AI console — design brief for Claude Design

You are designing the operator console for RAKSHA AI. **How it looks, how it is laid out, the
navigation, the typography, the motion and the visual language are yours to decide.** The current
console (screenshots in `docs/walkthrough/`) is a working reference for *what* is shown, not for
*how*. Redesign freely. Merge, split or reorder screens, invent better visualisations. This brief
covers only the facts, the people, the data and a few rules the product cannot break.

## The product, in one paragraph

RAKSHA AI is an offline system that finds security weaknesses in software, writes fixes, and
**proves** both. A weakness is reported only with evidence that replays, either an input that
triggers it or an exact match against a known-vulnerable version. A fix is accepted only after
passing five automatic checks:
1. **compiles**;
2. **the original attack is dead**;
3. **normal inputs behave exactly as before**;
4. **the fixed code is still exercised**;
5. **fresh attacks on it fail**.

Everything runs on one sealed machine with no internet. It is built for the Indian Army's AI Kavach
Grand Finale, where judges watch it work live for 36 hours.

## Who looks at it, and what each needs in five seconds

| Person | Situation | Needs at a glance |
|---|---|---|
| Operator | at the keyboard during the run | what is running now, what needs a decision, anything stuck |
| Judge / jury | watching on a projector, a few metres away | that findings are *proven*, fixes are *proven*, nothing left the machine, the measured numbers |
| Commander | reads a one-page brief | what is at risk, what is fixed, what needs authorisation |
| Project owner / developer | their own project over weeks | what changed since last time, what to do next, posture trend |
| Auditor | after the fact | signed evidence they can verify themselves, the history chain |

## The story the interface must tell

Each finding moves through these states:

`SUSPECTED → CONFIRMED (evidence replays) → PATCHED (fix written) → VERIFIED (fix passed all five checks)`

or it ends at `REPORT ONLY` (proven, but the fix needs a human, e.g. rotate a password).

A suspicion without evidence is never shown as a finding; it stays "suspected". The most
convincing moment in the product is the side-by-side **vulnerable build: attack fires** against
**patched build: attack dead**, with the five checks ticking. Give it the weight it deserves.

## What there is to show

All data comes from a local JSON API served by `console/server.py` on `127.0.0.1:8080`.
`GET /api/snapshot` returns everything live. The UI polls it.

| Area | Data (field names as the API returns them) | Notes |
|---|---|---|
| Header badges | `egress` (`raksha_egress_calls`, `links_up`), `scorecard.precision.reports_with_reproducer_pct`, network posture (`0` or `unenforced`) | always visible; these are the trust signals |
| Targets | `board[]`: `name`, `languages`, `build_status` (BUILT / BUILD-FREE), `findings`, `verified`, `roe_level`, `status`, `note` | a target that could not build still yields findings ("build-free") |
| Pipeline | `pipeline[]`: `status`, `count`, `at_or_past`; `risk[]` ranked: `score`, `severity`, `has_fix`, `reachability`, `mission_impact` | "fix these first" |
| Event log | `events[]`: `at`, `level`, `seq`, `text` | the run's story in sentences |
| Finding detail | `GET /api/finding/<id>`: status, evidence kind, the five checks with one-line reasons, the proven patch (unified diff), repair lane (TEMPLATE / RETRIEVAL / LLM / MITIGATION), red-team result, CVSS, solver proofs | two voices: plain-language "staff view" and "engineer view" (`/api/voices/<id>`) |
| Operator actions | `POST /api/action/<name>`: approve, reject, mark false positive, re-run red team, export bundle | every action is logged with who did it |
| Attack graph | `attack_graph.nodes/edges/chains/summary` | single findings chained to impact; cheapest path highlighted; every edge is labelled "heuristic" |
| Estate map | `estate_map.tiers[]`, `top_risks[]` | mission-critical / operational / support |
| Post-quantum | `pqc`: sites, quantum-vulnerable sites, migrations | inventory and migration advice, not findings |
| Evidence vault | signed bundles; `GET /api/verify/<id>` re-verifies one live | "verify one yourself" |
| Scorecard | `scorecard.*`: performance, speed, precision, functionality, scalability, resource, posture, **boundary** (what the run does NOT establish), depth | every number is measured or shown as `—` (null) |
| Commander's brief | `GET /api/brief/<id>`, PDF at `/api/export/brief/<id>.pdf`, English and Hindi | one page, print-ready |
| Demo beats | `saysno` (the system refusing a bad fix), `intake` (bring your own target), `egress` (live packet counter) | live demonstrations for judges |
| Time-lapse | `GET /api/timelapse`: a recorded 36-hour journal to scrub through | chain-verified |
| Projects | `/api/projects`, `/api/project/<id>/...`: versions, posture score, diff since last version, role views (owner / developer / commander / auditor), certificate, summaries EN/HI | long-term memory per project |
| Learning | `/api/learning`: recurring faults, draft guidelines (need a named approver), lessons on probation | "proposes, never decides" |
| Exports | `/api/export/findings.csv`, `.xlsx` | |

Run it and look at real data: `python -m raksha.orchestrator`, then open http://127.0.0.1:8080.

## Rules the design cannot break

1. **Offline.** No web fonts, CDNs, external images or scripts. Everything is inline or served from
   `console/`. Use system font stacks, or embed a font file in the repo.
2. **Never imply "secure".** No green "secure / safe / clean / all clear" state for a target. The
   product proves *presence* of weaknesses, never *absence*. The calmest possible state is
   "nothing proven in what was examined", shown together with the assurance boundary.
3. **Evidence before claims.** Every finding visibly carries its evidence type: *exploit-replay*
   (an attack replays) or *deterministic-match* (exact version or pattern match). Keep the two
   distinguishable.
4. **Unknown is not zero.** A metric that was not measured shows `—`. It never shows `0` or a
   placeholder value.
5. **Colour never carries meaning alone.** Pair it with a word or symbol. The projector mode must
   stay legible at 3–4 metres in a bright hall.
6. **Bilingual.** English and Hindi (Devanagari) throughout, switchable. Labels come from
   `/api/labels`. Allow for Hindi strings being longer.
7. **Works at phone width** (around 390 px) without horizontal page scroll, and on a 1080p projector.
8. **Keyboard operable.** The operator drives it during the live demo. `/api/help` lists the
   current shortcuts; keep or improve them.
9. **Human authority is explicit.** Deploying a fix, rotating a secret and approving a guideline are
   human actions with a named person. The UI never presents them as automatic.

## Where the freedom is

Everything else is open, including:
- the overall concept (control room, single scrolling story, map-first, or something new);
- the information architecture and number of screens;
- how the five checks, the state machine, the attack graph and the time-lapse are visualised;
- motion and live-update behaviour, as long as it stays readable on a projector;
- light, dark or both;
- a visual identity that suits a defence setting without clichés.

Surprise us.

## Deliverable that slots in

- Static files only: `console/index.html`, plus any `.css`, `.js` and font files under `console/`.
  `console/server.py` already serves that folder.
- Plain JavaScript, or a framework compiled to static files with no runtime downloads.
- Read the same endpoints. If a screen needs data the API does not give, list it and it will be
  added server-side.
- Write actions (`POST /api/action/...`) need the per-run token: keep the literal
  `__RAKSHA_TOKEN__` somewhere in `index.html` (the server replaces it when it serves the page) and
  send it as the `X-RAKSHA-Token` header. See how `console/app.js` does it.
- Keep the existing endpoints and actions working. `tests/test_console*.py` and the UI checks call
  them.
