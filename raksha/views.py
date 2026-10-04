"""Read-only views over the signed project history (K12, K14, K22, K23, K25, K26, K27).

Each function renders what the report versions already hold; none computes a new security fact.

  K12 mission_view    open items grouped by the mission function the asset registry names
  K14 heatmap         each project's posture by version, and the estate at any past moment
  K22 before_after    a proven patch, side by side, with its gate result
  K23 kb_search       past proven fixes, searchable by family, component or text
  K25 role_view       the same report for a developer, a commander or an auditor
  K26 team_scorecard  a unit's most repeated weakness families and the matching guidance,
                      shown only to that unit or the units above it in its chain
  K27 digest / alert  a short per-project summary; an alert only when something serious is new
"""

from __future__ import annotations

from . import reports
from .projects import Store

_OPEN = ("open", "referred", "fix-proven")


def latest(store: Store, pid: str) -> dict | None:
    vs = reports.versions(store, pid)
    return reports.load(store, pid, vs[-1]) if vs else None


def _sev_rank(s: str) -> int:
    return reports.SEVERITIES.index(s) if s in reports.SEVERITIES else 9


# ---- K12 ----------------------------------------------------------------------------------------

def mission_view(store: Store) -> dict:
    groups: dict[str, list[dict]] = {}
    for p in store.all():
        b = latest(store, p.id)
        if b is None:
            continue
        fn = b["project"].get("mission_function") or "unregistered (no asset-registry entry)"
        for r in b["findings"]:
            if r["state"] in _OPEN:
                groups.setdefault(fn, []).append({"project": p.id, "name": p.name, "title": r["title"],
                                                  "severity": r["severity"], "state": r["state"]})
    return {fn: sorted(rows, key=lambda r: _sev_rank(r["severity"])) for fn, rows in sorted(groups.items())}


# ---- K14 ----------------------------------------------------------------------------------------

def heatmap(store: Store) -> list[dict]:
    out = []
    for p in store.all():
        hist = reports.history(store, p.id)
        if hist:
            out.append({"project": p.id, "name": p.name, "tier": p.tier,
                        "versions": [{"version": b["version"], "at": b["created"],
                                      "score": b["score"]["score"], "counts": b["counts"]} for b in hist]})
    return out


def heatmap_at(store: Store, when: str) -> list[dict]:
    """Each project's latest version at or before `when` (ISO time); None if it had none yet."""
    out = []
    for row in heatmap(store):
        past = [v for v in row["versions"] if v["at"] <= when]
        out.append({"project": row["project"], "name": row["name"], "tier": row["tier"],
                    "state": past[-1] if past else None})
    return out


# ---- K22 ----------------------------------------------------------------------------------------

def before_after(row: dict) -> dict | None:
    """Split a proven patch into its removed and added lines, per file, with the gate result."""
    diff = row.get("patch_diff")
    if not diff:
        return None
    files: list[dict] = []
    cur = None
    for ln in diff.splitlines():
        if ln.startswith("+++ "):
            cur = {"file": ln[4:].split("\t")[0].removeprefix("b/"), "before": [], "after": []}
            files.append(cur)
        elif ln.startswith(("--- ", "@@")) or cur is None:
            continue
        elif ln.startswith("-"):
            cur["before"].append(ln[1:])
        elif ln.startswith("+"):
            cur["after"].append(ln[1:])
        else:
            cur["before"].append(ln[1:])
            cur["after"].append(ln[1:])
    return {"title": row["title"], "files": files, "gate": row.get("gate"),
            "gate_passed": bool(row.get("gate")) and all(row["gate"].values()) and len(row["gate"]) >= 5}


# ---- K23 ----------------------------------------------------------------------------------------

def kb_search(store: Store, query: str = "", *, family: str | None = None) -> list[dict]:
    """Every proven fix in every report version, newest first, matching `query`/`family`."""
    q = query.lower().strip()
    out, seen = [], set()
    for p in store.all():
        for b in reversed(reports.history(store, p.id)):
            for r in b["findings"]:
                if r["state"] != "fix-proven" or not r.get("patch_diff") or r["key"] in seen:
                    continue
                if family and (r.get("family") or "") != family:
                    continue
                hay = " ".join(str(x) for x in (r["title"], r.get("file"), r.get("family"),
                                                r.get("bug_class"), p.name)).lower()
                if q and q not in hay:
                    continue
                seen.add(r["key"])
                out.append({"project": p.id, "name": p.name, "version": b["version"], "title": r["title"],
                            "family": r.get("family"), "file": r.get("file"), "lane": r.get("lane"),
                            "patch_diff": r["patch_diff"]})
    return out


# ---- K25 ----------------------------------------------------------------------------------------

def role_view(store: Store, pid: str, role: str, version: int | None = None) -> dict:
    vs = reports.versions(store, pid)
    if not vs:
        return {"error": "no report for this project"}
    b = reports.load(store, pid, version or vs[-1])
    base = {"project": b["project"], "version": b["version"], "created": b["created"], "role": role}
    if role == "developer":
        return {**base, "findings": [{k: r.get(k) for k in ("title", "severity", "state", "file", "line",
                                                            "symbol", "lane", "patch_diff", "needs_human")}
                                     for r in b["findings"]],
                "drift": b["drift"], "diff": b["diff"]}
    if role == "commander":
        return {**base, "mission_function": b["project"].get("mission_function"),
                "score": b["score"]["score"], "counts": b["counts"], "trend": b.get("trend"),
                "needs_human": [{"title": h["title"], "why": h["why"]} for h in b["needs_human"]],
                "deadline_breaches": [e for e in b["exposure"] if e["breached"]]}
    if role == "auditor":
        ok, problems = reports.verify_chain(store, pid)
        return {**base, "chain_verified": ok, "chain_problems": problems,
                "gate_records": [{"title": r["title"], "gate": r["gate"], "evidence": r["evidence"],
                                  "reproducer_sha256": r["reproducer_sha256"]} for r in b["findings"]],
                "data_statement": b["data_statement"], "marks_rechecked": b["marks_rechecked"]}
    return {"error": f"unknown role {role!r}; one of developer, commander, auditor"}


# ---- K26 ----------------------------------------------------------------------------------------

def team_scorecard(learning, unit: str, *, viewer_unit: str, chain: dict[str, list[str]] | None = None) -> dict | None:
    """A unit's most repeated weakness families with the matching guidance. None unless the viewer
    is that unit or a unit above it in `chain` ({unit: [units above it]})."""
    from .learning import _RULES
    if viewer_unit != unit and viewer_unit not in (chain or {}).get(unit, []):
        return None
    counts: dict[str, int] = {}
    for o in learning.state["observations"]:
        if o.get("unit") == unit:
            counts[o["family"]] = counts.get(o["family"], 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:5]
    return {"unit": unit, "framing": "support for the team, not a ranking",
            "top": [{"family": f, "count": n, "guidance": _RULES.get(f)} for f, n in top]}


# ---- K27 ----------------------------------------------------------------------------------------

def alert(body: dict) -> dict | None:
    """A short notice only when this version holds a NEW critical or high item."""
    by = {r["key"]: r for r in body["findings"]}
    serious = [by[k] for k in body["diff"].get("new", []) if k in by and by[k]["severity"] in ("critical", "high")]
    if not serious:
        return None
    return {"project": body["project"]["id"], "version": body["version"],
            "text": f"{body['project']['name']} v{body['version']}: {len(serious)} new serious item(s) — "
                    + "; ".join(r["title"][:80] for r in serious[:3])}


def digest(store: Store, pid: str, *, since_version: int = 0) -> dict:
    """What changed for one project across the versions after `since_version`."""
    hist = [b for b in reports.history(store, pid) if b["version"] > since_version]
    if not hist:
        return {"project": pid, "versions": [], "text": "no new report since the last digest"}
    fixed = sum(len(b["diff"].get("fixed", [])) for b in hist)
    new = sum(len(b["diff"].get("new", [])) for b in hist)
    last = hist[-1]
    return {"project": pid, "versions": [b["version"] for b in hist], "fixed": fixed, "new": new,
            "waiting_on_you": len(last["needs_human"]), "score": last["score"]["score"],
            "text": f"{last['project']['name']}: {fixed} fixed, {new} new, {len(last['needs_human'])} "
                    f"waiting on you; score {last['score']['score']}"}
