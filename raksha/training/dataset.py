"""E8 — assemble a fine-tuning dataset from gate-VERIFIED findings only. It learns only from proofs.

This is scaffolding, OFF by default: nothing in the RAKSHA pipeline calls it. An operator invokes it
by hand to curate a corpus of (context, diff) pairs from findings that the five-check gate actually
proved. A proven fix is a fact — the PoV was dead, the differential corpus held, coverage held, the
refuzz was clean — so a dataset built only from VERIFIED findings is clean by construction. Anything
unproven (SUSPECTED, REPORT_ONLY, PATCHED-but-ungated) is refused and the refusal is recorded.

    WHAT THIS MODULE DOES NOT DO, loudly: it does not train, fine-tune, or load a model; it does not
    touch the network; it does not spin up a GPU. Actual fine-tuning is an optional,
    operator-initiated step on separate GPU infrastructure, outside this repository's runtime. This
    module only curates proven pairs and refuses unproven data. `write_jsonl` is the only function
    that writes anything, and only to the path the operator hands it.

Public API
----------
* ``eligibility(finding, *, require_verified=True) -> str | None`` — ``None`` if the finding may
  enter the dataset, else a human-readable reason it is refused.
* ``build_dataset(findings, *, require_verified=True) -> list[dict]`` — the ``{context, diff,
  bug_class, language}`` pairs for the eligible findings; unproven findings are skipped (their
  reasons are available via ``eligibility`` / ``dry_run``).
* ``write_jsonl(pairs, path) -> int`` — write pairs as JSON Lines; returns the count written.
* ``dry_run(findings) -> dict`` — a summary (counts, per-class / per-language breakdown, and the
  recorded refusals) that performs NO training and NO I/O beyond reading the records it is given.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..finding import Finding, Status

#: Guard rail: this module is inert scaffolding. The pipeline never flips this on; an operator who
#: wants a corpus calls the functions directly. Kept as an explicit, greppable "off by default".
ENABLED_IN_PIPELINE = False


def eligibility(finding: Finding, *, require_verified: bool = True) -> str | None:
    """Why a finding may NOT enter the dataset, or ``None`` if it may.

    The dataset learns only from proofs, so a finding is eligible only when the gate actually passed
    (all five checks) and a patch diff is on the record. With ``require_verified=True`` (the default)
    the finding must additionally be in terminal ``VERIFIED`` status — the status the invariant only
    grants once the PoV is dead. ``require_verified=False`` relaxes the *status* check (e.g. to admit
    a frontier passer held at CONFIRMED whose gate nonetheless passed) but STILL requires a passing
    gate and a diff, so even then no genuinely unproven pair is ever emitted.
    """
    if require_verified and finding.status is not Status.VERIFIED:
        return f"status {finding.status.value}, not VERIFIED — the dataset learns only from proofs"
    if not finding.gate_passed:
        return "gate did not pass all five checks — unproven, refused"
    if not (finding.patch_diff and finding.patch_diff.strip()):
        return "no patch diff on record — nothing to learn from"
    return None


def _context(finding: Finding) -> str:
    """The textual situation a model would condition on: class, language and the fix site.

    Built only from fields already on the proven record — no source is read and nothing is executed.
    """
    site = finding.fix_site_set[0] if finding.fix_site_set else None
    where = ""
    if site is not None:
        where = site.uri + (f":{site.start_line}" if site.start_line else "")
        if site.symbol:
            where += f" ({site.symbol})"
    parts = [
        f"language: {finding.language}",
        f"bug_class: {finding.bug_class}",
        f"finding: {finding.message}",
    ]
    if where:
        parts.append(f"fix_site: {where}")
    return "\n".join(parts)


def _pair(finding: Finding) -> dict:
    return {
        "context": _context(finding),
        "diff": finding.patch_diff,
        "bug_class": finding.bug_class,
        "language": finding.language,
    }


def build_dataset(findings: Iterable[Finding], *, require_verified: bool = True) -> list[dict]:
    """The clean ``{context, diff, bug_class, language}`` pairs from the eligible findings.

    Unproven findings are skipped (never raised over, so one bad record cannot abort a curation
    run); use ``dry_run`` or ``eligibility`` to see exactly which were refused and why. Deterministic:
    input order is preserved.
    """
    out: list[dict] = []
    for f in findings:
        if eligibility(f, require_verified=require_verified) is None:
            out.append(_pair(f))
    return out


def write_jsonl(pairs: Iterable[dict], path: str | Path) -> int:
    """Write pairs as JSON Lines to ``path``. Returns the number of lines written.

    The only function here that writes anything, and only to the operator-supplied path. Still no
    training and no network — this is a local file of curated text.
    """
    path = Path(path)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for pair in pairs:
            fh.write(json.dumps(pair, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def dry_run(findings: Iterable[Finding], *, require_verified: bool = True) -> dict:
    """Summarise what a curation run WOULD produce, without training, fine-tuning or writing files.

    Returns counts, per-bug-class and per-language breakdowns of the accepted pairs, and the full
    list of refusals (finding id + reason). Performs no I/O beyond reading the records handed in.
    """
    findings = list(findings)
    accepted: list[Finding] = []
    refusals: list[dict] = []
    for f in findings:
        reason = eligibility(f, require_verified=require_verified)
        if reason is None:
            accepted.append(f)
        else:
            refusals.append({"id": f.id, "status": f.status.value, "reason": reason})

    by_bug_class: dict[str, int] = {}
    by_language: dict[str, int] = {}
    for f in accepted:
        by_bug_class[f.bug_class] = by_bug_class.get(f.bug_class, 0) + 1
        by_language[f.language] = by_language.get(f.language, 0) + 1

    return {
        "total": len(findings),
        "accepted": len(accepted),
        "refused": len(refusals),
        "require_verified": require_verified,
        "by_bug_class": by_bug_class,
        "by_language": by_language,
        "refusals": refusals,
        "trained": False,  # loudly: this module never trains
        "note": "curation only — fine-tuning is a separate, operator-initiated GPU step; no model "
                "was trained and no network was used.",
    }
