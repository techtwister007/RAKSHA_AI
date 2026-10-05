# RAKSHA AI — the console, screen by screen

These screenshots are from a real run, not a mock-up. The run covered the bundled demo estate
(five services in Go, Java, JavaScript, Python and an API spec) plus two programs that ship with
**no test harness** (one C, one Python). RAKSHA wrote a harness for each, found the bug, fixed it
and proved the fix. The screenshots were regenerated on 5 October 2026 from commit
`claude/magical-mayer-gs2xno`.

To see it yourself:
```sh
python -m raksha.orchestrator      # then open http://127.0.0.1:8080
```
On the laptop install, double-click `RAKSHA Console.bat`.

## The journey in one picture

```
 targets ──► build (or build-free) ──► find ──► CONFIRM (evidence replays) ──► repair ladder ──► five-check gate ──► red team ──► signed bundle ──► brief / reports
              Mission Board           Pipeline / Event Log       Finding Detail                  Finding Detail       Demo Beats    Evidence Vault    Brief / Projects
```

Header badges, always visible:
- **NET IF** — `0` when the sandbox has no network; `unenforced` on a laptop without the sandbox,
  and it says so honestly.
- **CLOUD** — model calls that left the machine.
- **PRECISION** — share of reports carrying evidence that replays.

---

### 1 · Mission Board — what is being examined
![Mission board](walkthrough/01-mission-board.png)

One card per target.
- **BUILT** means RAKSHA compiled it and can run attacks against it.
- **BUILD-FREE · FINDING** means it could not build (missing toolchain or broken build), yet RAKSHA
  still finds weaknesses from manifests, configs and source. A failed build is never a dead end.
- **Status** moves through `scanning → finding → fixing → fixed`. `fixed` means every finding on
  that target has a proven fix. It never means "secure".
- **ROE** is the rules-of-engagement level: what RAKSHA may do on its own for that asset.

### 2 · Live Pipeline — the status machine and what to fix first
![Pipeline](walkthrough/02-live-pipeline.png)

Counts at each state, SUSPECTED → CONFIRMED → PATCHED → VERIFIED (or REPORT ONLY), then the
**ranked risk register**. Ranking uses severity, reachability, mission impact and whether a proven
fix exists. Here the C buffer overflow ranks first because it is exploit-proven and already fixed,
then the AWS key, then Log4Shell.

### 3 · Event Log — the run's story
![Event log](walkthrough/03-event-log.png)

Every step is a sentence with a timestamp. For one target the sentences read:
1. "looking for an entry point (no harness shipped)";
2. "harness synthesized; quality gate passed";
3. "CWE-78 confirmed; reproducer replays";
4. "candidate 1 (template lane) cleared all five gate checks";
5. "VERIFIED";
6. "independent red team held".

The log is hash-chained, so it can be replayed later.

### 4 · Finding Detail — staff view
![Finding detail, staff view](walkthrough/04-finding-detail.png)

Plain language for a non-specialist: what was found, that a fix was written and proven, and the
action needed. Operator buttons: Approve, Reject, Mark false positive, Re-run red team, Export
bundle. Every action is logged with who did it.

### 4b · Finding Detail — engineer view (the proof)
![Finding detail, engineer view](walkthrough/04b-finding-detail-engineer.png)

The heart of the product:
- **Vulnerable build: attack fires ✗** next to **patched build: attack dead ✓**.
- The **five checks**, each with its reason:
  1. compiles;
  2. the original attack is dead;
  3. 34 normal inputs behave identically;
  4. the fixed code is still reached;
  5. 24 variants of the attack plus fresh fuzzing fail.
- Solver proofs, when they apply.
- Which repair lane produced the fix (here TEMPLATE, zero model calls), the independent red-team
  result, and the exact proven patch.

### 5 · Attack Graph — single findings chained to impact
![Attack graph](walkthrough/05-attack-graph.png)

Individually modest findings, such as a weak hash, an exposed credential and an unauthenticated
endpoint, are chained to an impact such as remote code execution. The cheapest path is
highlighted. Every edge is labelled with the rule that created it and marked **heuristic**: this
screen is for prioritising, not proof.

### 6 · Estate Map — asset tier against status
![Estate map](walkthrough/06-estate-map.png)

Targets grouped by how much the mission depends on them (mission-critical / operational / support),
with fixed, proven and open counts, and the top three risks.

### 7 · Post-Quantum — crypto inventory and migration
![Post-quantum](walkthrough/07-post-quantum.png)

Every cryptographic call site, which ones a future quantum computer breaks (RSA, ECDSA, old TLS),
and the NIST replacement for each: ML-KEM, ML-DSA, SLH-DSA, hybrid TLS 1.3. This is an
inventory and a plan, not a list of findings.

### 8 · Evidence Vault — verify one yourself
![Evidence vault](walkthrough/08-evidence-vault.png)

Each reportable finding has a signed evidence bundle. **Verify** re-checks its signature and
hashes live. A judge can also copy a bundle to their own machine and run the standalone verifier
(`raksha/data/verify_standalone.py`) with nothing else installed.

### 9 · Scorecard — the jury's scoresheet, live
![Scorecard](walkthrough/09-scorecard.png)

Every number is measured from this run, or shows `—` if it was not measured. Below the numbers:
- the **assurance boundary**: which languages had exploit-level analysis and which only build-free,
  which targets fell back to build-free, and how many suspicions stayed unproven;
- **what this run does not claim**: it establishes presence, not absence;
- **lane trust**: how often each lane's findings held up.

### 10 · Commander's Brief — one page, English or Hindi
![Brief list](walkthrough/10-commander-s-brief.png)
![Brief, English](walkthrough/15-brief-english.png)
![Brief, Hindi](walkthrough/16-brief-hindi.png)

A staff-style one-pager per finding (subject, details, action taken, recommendation, enclosures).
It switches to Hindi with one click and exports to PDF.

### 11 · Demo Beats — moments built for the judges
![Demo beats](walkthrough/11-demo-beats.png)
![It says no](walkthrough/11b-demo-says-no.png)

- **It says no.** Four candidate fixes for the same real C bug run through the real gate, about
  22 seconds in all:

  | Candidate | Outcome | Why |
  |---|---|---|
  | shallow | refused by the gate | the defect still fires |
  | unsafe | refused before the gate | it adds a `system()` call |
  | weak | passes all five checks, then broken by the independent red team | 18 inputs in 277 attempts break it |
  | proper | accepted | — |

  Refusal is what makes the "yes" believable.
- **Bring your own target.** Point it at a folder (a USB stick, say) from an allowed location and
  RAKSHA scans it live.
- **Air-gap counter.** Live packet counters on every network interface next to RAKSHA's own count
  of outbound calls (0).

### 12 · Time-lapse — scrub a long run
![Time-lapse](walkthrough/12-time-lapse.png)

A recorded long run (916 events, 70 targets, 480 findings), replayed from its signed journal.
The chain is verified before it plays.

### 13 · Projects — memory across runs
![Projects](walkthrough/13-projects.png)

Each project keeps versioned, signed reports: posture score over versions, what changed since last
time, and "needs a human" items with a checklist. A "mark done" is re-checked on the next run, not
trusted. There are role views (owner / developer / commander / auditor), summaries in English and
Hindi, and a readiness certificate.

### 14 · Learning — proposes, never decides
![Learning](walkthrough/14-learning.png)

Recurring faults by family and by unit. Draft coding guidelines need a named approver. Lessons go
on probation and are promoted only after they hold on two or more projects; a false positive
demotes them and quarantines the source.

### Accessibility and form factors
![High contrast](walkthrough/17-high-contrast.png)
![Keyboard help](walkthrough/18-keyboard-help.png)
![Phone](walkthrough/19-phone.png)

Projector high-contrast mode, full keyboard control (`?` lists the keys), and a phone-width layout.

---

## What the screenshots honestly show

- **NET IF: unenforced.** These were taken without the network-less sandbox container. On the
  sealed node it reads `0`.
- **Most findings are CONFIRMED by deterministic match.** For example, a dependency version known
  to be vulnerable, or a key in a config file. Those are fixed by an operator: rotate the key,
  bump the version. Only the two deep targets show the full find → fix → prove loop here; the
  other demos (`python -m raksha.slice_three`, `slice_go`, `slice_rust`, `slice_js`) show it for
  more languages.
- **The run made no model calls** (CLOUD: 0). Every fix came from a template. The model lane is
  checked separately by `python scripts/model_lane_check.py` (see `docs/model-benchmark.md`).
