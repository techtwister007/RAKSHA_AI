# 07 · Deliverables — What Makes It Actually Usable

The core product finds, fixes and proves. These deliverables turn a demo into something
an Army unit could actually adopt. They are also where "we understand the customer, not
just the brief" becomes visible.

## Core deliverables (the product itself)

1. **Offline deployment bundle** — one `docker compose` file, installable from removable
   media onto an air-gapped node, zero network calls at runtime.
2. **RAKSHA orchestrator** — the FastAPI service: ingest funnel, oracle plugin API, four
   repair lanes, the five-check gate, the learning loops.
3. **Language adapters** — C/C++, Java, Node/JS, Python (+ binary, web).
4. **Python security sanitizer set** — PySecSan plus our extensions.
5. **Fine-tuned advisor adapter** — QLoRA weights trained on validated ARVO fix pairs,
   shipped with the bundle.
6. **Operator console** — the six-screen web UI (file 11).

## Deliverables that make it *trustworthy* and *adoptable*

7. **SBOM per target** — machine-readable list of every component inside the software
   (Syft → CycloneDX). Increasingly a procurement requirement.
8. **Signed attestations** — cryptographic proof of *what* was tested, *by which*
   version, *with what* result (cosign / in-toto, fully offline). The evidence bundle
   becomes tamper-evident.
9. **Reviewable patch packet** — the diff + a plain-English explanation + the new
   regression test + a **rollback script**. Nobody deploys a patch they cannot undo.
10. **Permanent regression test** — committed into the target's own test suite, so the
    bug can never silently return.
11. **Ranked risk register** — severity × reachability × exploitability. "Fix these 3
    first, ignore these 400." Arguably more valuable to a real operator than the
    patching itself, because an operator with 500 systems wants priorities, not 500
    patches dumped on them.
12. **Approval workflow** — a human approves before any patch leaves the sandbox; for
    critical assets, two officers (file 09).
13. **Sneakernet update kit** — how vuln databases and model weights get refreshed on an
    air-gapped network: signed bundles on removable media, verified on import. Every
    air-gapped tool needs this; almost nobody designs it.
14. **Ops documentation in JSSD format** — install manual, SOP, runbook, written the way
    the Services actually consume documents.
15. **Benchmark report** — our numbers on ARVO + AutoPatchBench, methodology included,
    losses shown next to wins.

## The evidence bundle — the heart of the trust story

Every VERIFIED finding produces one sealed, signed bundle containing:

- the reproducer (and how to replay it)
- before/after oracle output (the proof it was real, and is now dead)
- the five-check gate results
- the diff and its plain-English explanation
- the new regression test
- the rollback script
- the SBOM delta
- the ROE level that governed it and the approver signature(s)
- model + prompt version, fix-site, AST delta

This bundle is the thing an officer acts on. It is why we can say, truthfully, *"we are
not asking anyone to trust the AI — we are handing them the receipts."*

## Performance objectives (state these, then measure and adjust)

| Objective | Target |
|-----------|--------|
| Report precision (findings with a replayable reproducer) | 100% by construction |
| Patch validity (survives differential corpus test) | measure on AutoPatchBench; do not pre-promise |
| Median time to first proof-of-vulnerability | track and show live |
| Median time to a validated patch | track and show live |
| Run-2 speed-up from the learning loops | demonstrate the curve |
| Peak footprint | single node, 32 GB, zero network |

> Note: numeric targets must come from our own ARVO / AutoPatchBench baseline, not from
> borrowed general-coding scores. A jury may ask where a number came from.
