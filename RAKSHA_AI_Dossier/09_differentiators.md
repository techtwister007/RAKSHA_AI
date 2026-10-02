# 09 · Differentiators — The Hard-to-Copy Ideas

These come from thinking like an Army officer, not a hackathon coder. An AI-shaped
competitor optimises for the brief as written; these optimise for what the Army actually
needs on Monday morning. That is the real moat.

---

## A. Rules of Engagement (ROE) — autonomy as doctrine

**One line:** autonomy is not a switch; it is a per-asset authority level that the system
obeys, and that automatically tightens when risk rises — exactly like fire control.

### The four levels

| Level | Name | Analogue | May… | May not… |
|-------|------|----------|------|----------|
| R0 | Observe | Weapons Hold | scan statically, map code, list suspects | run the target, write any patch |
| R1 | Recommend | Weapons Hold | + fuzz in sandbox, prove bugs, draft & gate patches | apply anything outside the sandbox |
| R2 | Act with approval | Weapons Tight | + stage a verified patch, deploy **after human sign-off** | deploy without approval |
| R3 | Act autonomously | Weapons Free | + deploy verified fixes to that asset directly | exceed standing orders |

### Assets get a criticality tier that caps their ROE

| Asset tier | Example | Max ROE |
|------------|---------|---------|
| Routine | training LMS, internal portal | R3 |
| Important | logistics, admin | R2 |
| Critical | C2, comms management | R2 + two-person rule |
| Mission-critical | fire control, weapon-system software | R1 (recommend only) |

Operators may always set ROE *lower* than the cap, never higher.

### Automatic step-down (this is what makes it more than a settings page)

Even an R3-cleared asset drops a specific patch to a lower level when risk rises:

| Trigger | Drops to |
|---------|----------|
| Patch touches auth / crypto / access-control | R2 |
| Fix came from the mitigation lane, not a real fix | R2 |
| Patch is large (AST delta over threshold) | R2 |
| Differential gate quarantined many flaky inputs | R2 |
| Security advisor disagrees with the coding model | R1 |
| First time this bug class seen on this asset | R2 |

The pattern: **confidence buys autonomy, uncertainty takes it away.**

### Standing orders (never broken, any ROE)
No network egress, ever · never deploy a patch that failed any gate · never delete more
than a set amount of code · every action logged with the ROE in force and who authorised
it · every deployment ships with a rollback.

### Two-person rule
Critical assets require two different officers to sign a patch with their own keys before
release — borrowed from nuclear/crypto custody doctrine. Signatures go into the evidence
bundle.

### Build with, don't invent
Open Policy Agent (OPA) as the offline policy engine — ROE becomes a signed policy file;
OPA answers "is this action allowed?" Signatures via cosign. Audit log append-only and
hash-chained.

### Why it scores
Novelty (no one frames autonomy in doctrine the jury already uses) · functionality
(proves it can run fully autonomous *and* safely constrained) · trust (answers the
jury's unspoken question: "who controls this thing?"). This is probably our single
strongest differentiator.

---

## B. The Vulnerability Vaccine — one fix, fleet-wide immunity

**One line:** every verified fix teaches RAKSHA what the mistake looked like; it turns
that into a search rule and sweeps every other codebase for the same mistake.

### The flow
```
Verified fix (gate passed)
 → EXTRACT     vulnerable shape vs fixed shape, the sink, the missing guard
 → WRITE RULE  model drafts a Semgrep rule: match the bad shape, not the fixed shape
 → PROVE RULE  three checks (below) — a rule that fails is thrown away
 → SWEEP       run the rule across every registered codebase (read-only, R0-safe)
 → CONFIRM     each hit is only SUSPECTED until it gets its own reproducer
 → FIX         confirmed hits go through the normal pipeline, template lane first
              (the original fix IS the template)
```

### The rule must earn its place (same philosophy as patches)

| Check | Pass condition | Why |
|-------|----------------|-----|
| Hits the original | matches the vulnerable code | else it doesn't describe the bug |
| Misses the fix | does NOT match the patched code | else it flags safe code forever |
| Low noise | fires rarely on a clean reference corpus | else it floods reviewers |

So even our own detection rules are not trusted until proven — the same rule that governs
patches and findings. That symmetry is worth saying out loud.

### Safety
Only *verified* fixes become vaccines (an unproven fix would spread a wrong pattern) ·
sweeping is read-only so always R0-safe · fixing each hit follows *that asset's* ROE, so
a vaccine never bypasses authority · a sweep hit is never a finding until it reproduces,
so precision stays 100%.

### Build with, don't invent
Semgrep (offline, simple enough for a small model to write rules reliably); CodeQL for
deeper data-flow variants. The "fix-as-template" is our template-mining loop extended
from one codebase to the whole estate.

### Why it scores
Wow ("fixed one, found the same mistake in four others") · scalability (value grows with
number of systems) · resource utilisation (vaccine hits are fixed by the zero-inference
template lane — the more it learns, the less model compute it needs).

---

## C. How ROE and the Vaccine connect

The vaccine *finds*; ROE decides *what may be done*. A variant in the training LMS gets
fixed autonomously; the same variant in a C2 system gets a recommendation and waits for
two signatures. **One mechanism, different authority per asset** — exactly what a real
military deployment needs, and proof the system was designed for the customer, not the
brief.

---

## D. Other out-of-box ideas (story-level; one slide each)

- **Red-vs-blue self-play.** A red RAKSHA injects realistic bugs into clean code; blue
  RAKSHA must find and fix them. Generates unlimited offline training data *and*
  continuously measures true recall — so we know our real hit rate instead of guessing.
- **Digital-twin rehearsal.** Before any patch reaches a live system, it runs against a
  sandboxed replica under replayed real traffic. A drill before the operation.
- **Mission-aware priority.** Findings ranked not just by severity but by which unit and
  mission depends on that system.
- **Two-person rule** (also used in ROE above) as a general deployment control.

These are differentiators precisely because they answer *operational* questions
(authority, rehearsal, mission impact) that a brief-literal competitor won't think to
ask.
