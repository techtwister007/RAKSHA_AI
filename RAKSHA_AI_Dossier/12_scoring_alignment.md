# 12 · Scoring Alignment

Every design decision maps to a jury criterion, with the number or artifact that proves
it. Build the system to *emit* these, don't retrofit them.

## Shortlisting criteria (the 5-slide stage)

| Criterion | Design decision | Evidence we show |
|-----------|-----------------|------------------|
| **Resource utilisation** | Escalation ladder (template → retrieval → LLM → mitigation); JEV-style local router sends work away from the big model; bandit-style reallocation | tokens per validated patch; **% of fixes with zero inference**; live VRAM |
| **Novelty** | Unified cross-language oracle; Python security sanitizers; metamorphic authz oracle; differential-corpus gate; ROE-as-doctrine; vulnerability vaccine | six named mechanisms, each demonstrable — not "we use AI" |
| **Lightweight** | One node, 32 GB, a 32B coding model + an 8B advisor (both self-hostable on a single GPU), no cloud; degrades to CPU-only smaller-model profile | offline bundle size; the cable-pull demo; runs-without-GPU fallback |

## Grand Finale criteria (the 36-hour build)

| Criterion | Design decision | Live metric |
|-----------|-----------------|-------------|
| **Performance** | four discovery lanes + four repair lanes, cross-confirmed | bugs found / patched per target |
| **Speed** | trace-based localisation (no LLM search), minimised PoVs, template-first, pre-warmed corpora | median time-to-PoV; median time-to-validated-patch |
| **Precision** | **no reproducer, no report** (enforced in the data model); differential gate kills overfitting fixes | % reports with reproducer = **100% by construction**; % patches surviving differential |
| **Functionality** | full autonomy, oracle plugin API, language auto-detect + routing, ROE authority model | zero-human-input counter; language coverage matrix; ROE in action |
| **Scalability** | job queue, parallel targets, one-adapter-per-language, vaccine value grows with fleet size | N targets concurrently; one target per language on the same core; graceful CPU-only degrade |

## The two criteria where we can be uniquely strong

- **Precision → 100% on reports, by construction.** This is a structural property (the
  data model forbids an unproven finding from being reported), not a tuning result. Say
  it that way; it is unusual and defensible.
- **Scalability → demonstrate *language* scalability, not just thread count.** Showing
  the same core fix a C bug, a Java bug and a Python bug answers "will this work on our
  unknown infrastructure?" far better than eight parallel workers on one C library —
  especially when the jury won't tell us in advance what their infrastructure is written
  in.

## The honesty that itself scores

For a defence jury, the most trust-building move is to **state limits plainly**:

- we claim 100% precision on *reports*, not on *patch semantic-correctness* — the gate
  proves "no observed behaviour changed across N inputs and M tests," with K flaky inputs
  quarantined and listed; we do not claim formal equivalence.
- we carry the most common dependencies offline; anything missing degrades to static
  analysis, not failure.
- self-improvement is designed and demonstrated at the loop level; the nightly QLoRA is a
  deployment feature, not a 36-hour result.

Volunteering the bound is what makes the headline numbers believable — and it is exactly
the posture a signals authority needs before trusting software near a live system.
