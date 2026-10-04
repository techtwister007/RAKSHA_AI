"""KEV + EPSS exploit-intelligence lane — offline snapshots stamped onto dependency findings.

Severity says how bad a vulnerability *could* be; exploit intelligence says how likely it is to be
used. Two public feeds answer that: CISA's **KEV** catalogue (CVEs known to be exploited in the
wild) and FIRST.org's **EPSS** (a model's probability that a CVE will be exploited in the next 30
days). This lane carries small offline snapshots of both (``data/kev.json``, ``data/epss.json``)
and stamps each dependency finding with ``kev: bool`` and ``epss: float | None``, so the risk
register can rank an exploited-in-the-wild dependency above a theoretically-worse but quiet one.

This is intelligence **metadata on existing findings, not a new finding** — nothing here is
reportable on its own, and this lane creates no ``Finding``.

What is measured vs heuristic
-----------------------------
*Measured*: KEV membership is an exact set lookup; EPSS is the published probability read straight
from the snapshot. The resolver maps a finding's advisory id (GHSA or CVE) to its CVE via the vuln
DB's ``aka`` field, then looks both feeds up by CVE. The snapshot date of each feed travels with the
annotation, so a stale snapshot is visible, never silently trusted.

*Honest nulls*: a CVE absent from the EPSS snapshot reads ``None`` (unknown), never ``0.0`` — 0/0 is
not a measurement. A finding whose CVE is not in KEV reads ``False`` (not *known* exploited), which
is the honest meaning of the feed, not a claim that it is unexploitable.

The snapshots carried here are a hand-verified slice; the full KEV/EPSS feeds are a networked
prep-machine refresh of the **same format** (``kev.load`` / ``epss`` loaders read either). Stdlib
only, offline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..finding import Finding
from . import vulndb

_DATA = Path(__file__).parents[1] / "data"
_KEV_PATH = _DATA / "kev.json"
_EPSS_PATH = _DATA / "epss.json"


@dataclass(frozen=True)
class ExploitIntel:
    """The two loaded snapshots, each with the date it was captured."""

    kev: frozenset[str]
    kev_snapshot: str | None
    epss: dict[str, float]
    epss_snapshot: str | None

    def is_kev(self, cve: str | None) -> bool:
        return cve is not None and cve in self.kev

    def epss_for(self, cve: str | None) -> float | None:
        return self.epss.get(cve) if cve is not None else None


def load(kev_path: Path | None = None, epss_path: Path | None = None) -> ExploitIntel:
    """Load the KEV and EPSS snapshots carried in the bundle (or a refreshed copy of the same shape)."""
    kev_data = _read_json(kev_path or _KEV_PATH)
    epss_data = _read_json(epss_path or _EPSS_PATH)
    cves = kev_data.get("cves") or []
    scores = epss_data.get("scores") or {}
    clean_scores = {k: float(v) for k, v in scores.items() if isinstance(v, (int, float)) and 0.0 <= v <= 1.0}
    return ExploitIntel(
        kev=frozenset(str(c) for c in cves),
        kev_snapshot=kev_data.get("snapshot_date"),
        epss=clean_scores,
        epss_snapshot=epss_data.get("snapshot_date"),
    )


def _read_json(path: Path) -> dict:
    try:
        obj = json.loads(path.read_text())
        return obj if isinstance(obj, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _advisory_id(f: Finding) -> str | None:
    repro = f.reproducer
    if repro is None:
        return None
    cmd = repro.replay_cmd
    if "--advisory" in cmd:
        i = cmd.index("--advisory")
        if i + 1 < len(cmd):
            return cmd[i + 1]
    return None


def _cve_of(f: Finding, db: vulndb.VulnDB) -> str | None:
    """The CVE for a dependency finding: its advisory id if a CVE, else the advisory's ``aka`` CVE."""
    adv_id = _advisory_id(f)
    if adv_id is None:
        return None
    if adv_id.upper().startswith("CVE-"):
        return adv_id
    adv = db.by_id(adv_id)
    if adv and isinstance(adv.get("aka"), str) and adv["aka"].upper().startswith("CVE-"):
        return adv["aka"]
    return None


def annotate_exploit_intel(findings: Iterable[Finding], intel: ExploitIntel | None = None,
                           db: vulndb.VulnDB | None = None) -> list[Finding]:
    """Stamp each dependency finding (``osv:version-match``) with KEV/EPSS intel, carrying the dates.

    Sets instance attributes (not ``Finding`` fields, which this lane may not extend):
    ``f.kev`` (bool), ``f.epss`` (float | None) and ``f.exploit_intel`` (a dict with the cve and both
    snapshot dates). Annotates in place and returns the same list. Non-dependency findings are left
    untouched.
    """
    intel = intel or load()
    db = db or vulndb.load()
    findings = list(findings)
    for f in findings:
        if f.oracle != "osv:version-match":
            continue
        cve = _cve_of(f, db)
        is_kev = intel.is_kev(cve)
        epss = intel.epss_for(cve)
        f.kev = is_kev
        f.epss = epss
        f.exploit_intel = {
            "cve": cve,
            "kev": is_kev,
            "kev_snapshot": intel.kev_snapshot,
            "epss": epss,
            "epss_snapshot": intel.epss_snapshot,
        }
        tag = []
        if is_kev:
            tag.append(f"KEV (known exploited, snapshot {intel.kev_snapshot})")
        if epss is not None:
            tag.append(f"EPSS {epss:.3f}")
        if tag:
            f.message += " [" + "; ".join(tag) + "]"
    return findings
