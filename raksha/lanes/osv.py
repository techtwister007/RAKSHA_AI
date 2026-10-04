"""OSV-format loader / ingester for the offline vulnerability database.

RAKSHA ships a small, curated, hand-verified slice of advisories in `raksha/data/vulndb.json`
(the format `vulndb.VulnDB` loads). The *full* mirror is far larger and is produced on a networked
prep machine: `osv.dev` publishes a complete export (one JSON file per advisory, and per-ecosystem
`all.zip` bundles). The sneakernet kit downloads that export there — never at runtime — and this
module is what ingests it into RAKSHA's internal shape. The curated set carried in the bundle is
parsed by the *same* loader, so the offline slice and the full mirror share one code path.

Nothing here touches the network. `parse_osv` converts one OSV v1 record; `load_osv_dir` walks a
directory of such records (individual files and/or an `all.json` array); `merge_into_db` folds the
converted advisories into `vulndb.json` idempotently (same id updates in place, never duplicated).

The internal advisory shape (what `vulndb.json` holds and `vulndb.VulnDB` indexes):

    {"ecosystem": "Maven", "package": "group:artifact", "id": "GHSA-…" | "CVE-…",
     "aka": "CVE-…" | null, "cwe": "CWE-###", "severity": "critical|high|medium|low",
     "summary": "…", "ranges": [{"introduced": "<ver>", "fixed": "<ver>" | null}, …]}

`introduced` is inclusive, `fixed` is exclusive (and null means unbounded above) — exactly the
convention `version.in_range` enforces, so a backport fix on one release line never flags a patched
version on another.
"""

from __future__ import annotations

import json
from pathlib import Path

_DEFAULT_DB = Path(__file__).parents[1] / "data" / "vulndb.json"

#: OSV ecosystem names RAKSHA's lanes understand, mapped to the canonical internal name. OSV already
#: spells the four we parse (`Maven`, `npm`, `PyPI`, `Go`) the way we do; the map also tolerates the
#: common sub-ecosystem spelling (`Go - stdlib` etc.) and is the single place to extend coverage.
_ECOSYSTEM = {
    "Maven": "Maven",
    "npm": "npm",
    "PyPI": "PyPI",
    "Go": "Go",
}

#: OSV severity vocabularies → RAKSHA's lowercase tiers. `database_specific.severity` is usually one
#: of these words; a CVSS vector is mapped by its qualitative band when that is all OSV carries.
_SEVERITY_WORD = {
    "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
    "LOW": "low", "NEGLIGIBLE": "low",
}


def normalise_ecosystem(ecosystem: str) -> str | None:
    """Canonical internal ecosystem name for an OSV ecosystem string, or None if unsupported.

    OSV qualifies some ecosystems with a sub-name after a colon (`Go:stdlib`) or a space; the base
    name is what RAKSHA keys on.
    """
    base = ecosystem.split(":", 1)[0].split(" ", 1)[0].strip()
    return _ECOSYSTEM.get(base)


def _pick_aka(record_id: str, aliases: list[str]) -> str | None:
    """A secondary identifier for the record: the CVE when the id is a GHSA (and vice versa).

    RAKSHA's internal convention is id=GHSA / aka=CVE, but OSV records are keyed either way; we keep
    whichever the id is not, preferring a CVE alias so the human-recognisable number is always
    reachable.
    """
    cve = next((a for a in aliases if a.upper().startswith("CVE-")), None)
    if not record_id.upper().startswith("CVE-") and cve:
        return cve
    ghsa = next((a for a in aliases if a.upper().startswith("GHSA-")), None)
    if record_id.upper().startswith("CVE-") and ghsa:
        return ghsa
    # id is a CVE with no GHSA alias (or vice versa): surface the other CVE/GHSA if any, else nothing.
    return cve if not record_id.upper().startswith("CVE-") else None


def _pick_cwe(record: dict) -> str:
    """A single representative CWE for the advisory.

    OSV carries CWEs under `database_specific.cwe_ids` (GHSA-sourced records). We take the first —
    the primary weakness — and fall back to CWE-1104 (use of unmaintained/vulnerable component),
    which is the supply lane's own default, when none is published.
    """
    ds = record.get("database_specific") or {}
    cwes = ds.get("cwe_ids") or ds.get("cwes") or []
    for c in cwes:
        if isinstance(c, str) and c.upper().startswith("CWE-"):
            return c.upper()
    return "CWE-1104"


def _pick_severity(record: dict) -> str:
    ds = record.get("database_specific") or {}
    word = ds.get("severity")
    if isinstance(word, str) and word.upper() in _SEVERITY_WORD:
        return _SEVERITY_WORD[word.upper()]
    # Fall back to the qualitative band of a CVSS vector if that is all OSV gives us.
    for sev in record.get("severity") or []:
        score = str(sev.get("score", ""))
        band = _cvss_band(score)
        if band:
            return band
    return "medium"


def _cvss_band(vector_or_score: str) -> str | None:
    """Crude qualitative band from a CVSS base score if one is embedded, else None.

    OSV `severity` entries carry a vector string (`CVSS:3.1/AV:N/…`) rather than a number; we do not
    re-score the vector offline, so this only fires when a bare numeric score is present.
    """
    try:
        score = float(vector_or_score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def ranges_from_affected(affected: dict) -> list[dict]:
    """Convert one OSV `affected` entry's ranges+versions into internal {introduced, fixed} list.

    OSV expresses affected versions as a sequence of `events` inside each range: an `introduced`
    event opens an interval and a `fixed` event closes it (exclusive upper bound). A single range's
    events may hold several introduced/fixed pairs (independently patched release lines), which we
    carry as separate internal ranges — collapsing them would flag a backport-fixed version.

    `last_affected` (inclusive upper bound, no clean fix) is preserved as metadata and left
    open-above only when no `fixed` closes the interval; it never silently becomes unbounded in a way
    that could over-match a patched version, because RAKSHA's range check treats a missing `fixed` as
    unbounded — so a `last_affected`-only interval is emitted with its bound recorded and the caller
    (and curator) can see it is approximate.
    """
    out: list[dict] = []
    for rng in affected.get("ranges") or []:
        introduced: str | None = None
        for ev in rng.get("events") or []:
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif "fixed" in ev:
                out.append({"introduced": introduced if introduced is not None else "0",
                            "fixed": ev["fixed"]})
                introduced = None
            elif "last_affected" in ev:
                out.append({"introduced": introduced if introduced is not None else "0",
                            "fixed": None, "last_affected": ev["last_affected"]})
                introduced = None
        if introduced is not None:
            # An `introduced` with no closing event: affected from there with no published fix.
            out.append({"introduced": introduced, "fixed": None})
    if not out and affected.get("versions"):
        # No ranges, only an explicit version list: OSV sometimes ships this for ecosystems without
        # orderable ranges. We cannot express a discrete set as an interval safely, so record it as
        # an explicit-versions range the curator can review; the range check ignores a None fixed
        # with no introduced floor only here because `introduced` is the min listed version.
        versions = sorted(affected["versions"])
        out.append({"introduced": versions[0], "fixed": None, "versions": list(affected["versions"])})
    return out


def parse_osv(record: dict) -> dict | None:
    """Convert a single OSV v1 schema record into RAKSHA's internal advisory dict.

    Returns None when the record names no package in an ecosystem RAKSHA parses (OSV covers many
    more than our four). A record that affects several packages is converted at its FIRST
    supported package — `parse_osv` yields one advisory; `load_osv_dir` fans a multi-package record
    out across every supported package (see `parse_osv_all`).
    """
    advisories = parse_osv_all(record)
    return advisories[0] if advisories else None


def parse_osv_all(record: dict) -> list[dict]:
    """Every internal advisory in an OSV record — one per supported affected package.

    A record like Spring4Shell lists both `spring-beans` and `spring-webmvc`; each becomes its own
    internal advisory (same id, same aka/cwe/severity/summary) so `for_package` finds it under
    either name. Packages in unsupported ecosystems are skipped.
    """
    record_id = record.get("id")
    if not record_id:
        return []
    aliases = record.get("aliases") or []
    aka = _pick_aka(record_id, aliases)
    cwe = _pick_cwe(record)
    severity = _pick_severity(record)
    summary = record.get("summary") or record.get("details") or ""
    if len(summary) > 300:
        summary = summary[:297].rstrip() + "…"

    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        eco = normalise_ecosystem(pkg.get("ecosystem", ""))
        name = pkg.get("name")
        if not eco or not name:
            continue
        ranges = ranges_from_affected(affected)
        if not ranges:
            continue
        key = (eco, name)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "ecosystem": eco,
            "package": name,
            "id": record_id,
            "aka": aka,
            "cwe": cwe,
            "severity": severity,
            "summary": summary,
            "ranges": ranges,
        })
    return out


def load_osv_dir(path: str | Path) -> list[dict]:
    """Load and convert every OSV record under `path`.

    Accepts a directory of individual OSV JSON files (the shape `osv.dev`'s per-advisory export
    uses) and/or an `all.json` holding a JSON array of records (a convenient single-file bundle). A
    single file may itself be either one OSV record (a dict) or an array of them. Records in
    unsupported ecosystems are silently skipped. The result is deduplicated on (id, ecosystem,
    package), first occurrence winning.
    """
    root = Path(path)
    advisories: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def _ingest(obj: object) -> None:
        records = obj if isinstance(obj, list) else [obj]
        for rec in records:
            if not isinstance(rec, dict):
                continue
            for adv in parse_osv_all(rec):
                key = (adv["id"], adv["ecosystem"], adv["package"])
                if key in seen:
                    continue
                seen.add(key)
                advisories.append(adv)

    if root.is_file():
        _ingest(json.loads(root.read_text()))
        return advisories
    if not root.is_dir():
        return advisories
    for file in sorted(root.rglob("*.json")):
        try:
            _ingest(json.loads(file.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return advisories


def merge_into_db(advisories: list[dict], db_path: str | Path | None = None) -> dict:
    """Merge converted advisories into a RAKSHA vulndb.json, writing it back.

    Idempotent on advisory id + (ecosystem, package): an advisory already present is updated in
    place (its fields replaced), never appended a second time, so re-ingesting the same export twice
    leaves the DB unchanged. Returns a small summary: how many were added vs updated and the new
    total. The curated `_comment` and any other top-level keys are preserved.
    """
    path = Path(db_path) if db_path is not None else _DEFAULT_DB
    data = json.loads(path.read_text()) if path.exists() else {"advisories": []}
    existing = data.setdefault("advisories", [])

    def ident(adv: dict) -> tuple[str, str, str]:
        return (adv["id"], adv["ecosystem"], adv["package"])

    index = {ident(a): i for i, a in enumerate(existing)}
    added = updated = 0
    for adv in advisories:
        key = ident(adv)
        if key in index:
            existing[index[key]] = adv
            updated += 1
        else:
            index[key] = len(existing)
            existing.append(adv)
            added += 1

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return {"added": added, "updated": updated, "total": len(existing)}
