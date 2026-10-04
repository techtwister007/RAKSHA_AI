"""Self-learning, under probation (K7–K11).

RAKSHA learns from its own history — but learning only ever **proposes**; the five-check gate still
decides what is true, and a human approves anything that becomes policy. Four parts:

**K7 Recurring-fault analytics.** Every report version is observed: each weakness by family,
language, component and owner unit. From the observations: what recurs most, which faults came
back after being fixed (regressions), and the trend per family over time.

**K8 Guideline proposals for ACG.** A fault family that recurs across projects becomes a draft
guideline: the rule, the evidence count, anonymised examples (project ID and file name only), and
the proven fix pattern where the history holds one. Drafts are *proposed*; nothing changes RAKSHA's
behaviour until a named human approves one, and an approved guideline is then enforced only by the
pre-merge check (K20).

**K9 Learning new technology, on probation.** A package the analytics have never seen is logged as
unfamiliar surface. A *lesson* — e.g. "treat this call as privileged" — starts on probation: it
applies only inside the project that proposed it. It is promoted (applied everywhere) only after
``PROMOTE_AFTER`` gate-verified cases from at least ``PROMOTE_PROJECTS`` distinct projects, and
demoted at once when it causes a false positive on a negative control.

**K10/K11 Learning health and poisoning defence.** Every lesson keeps its full history: who or
what proposed it, each piece of evidence, each promotion and who approved it, and a one-click
rollback. Evidence counts only when it comes from a gate-VERIFIED record; a source whose evidence
ever caused a demotion is quarantined and its later evidence ignored; and a single project can
never promote a lesson on its own, however much it submits.

State lives in ``$RAKSHA_HOME/learning.json``, on the box.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

PROMOTE_AFTER = 3          # gate-verified cases …
PROMOTE_PROJECTS = 2       # … from at least this many distinct projects
GUIDELINE_MIN = 3          # observations of a family …
GUIDELINE_PROJECTS = 2     # … across at least this many projects, before a draft guideline

#: Packages the system already knows (frameworks whose surface the lanes model). Anything else in an
#: inventory is "unfamiliar surface" — logged, never trusted, a prompt for a lesson.
KNOWN_PACKAGES = {
    "flask", "django", "fastapi", "requests", "pyyaml", "jinja2", "sqlalchemy", "numpy", "pandas",
    "express", "lodash", "minimist", "react", "axios", "org.apache.logging.log4j:log4j-core",
    "com.fasterxml.jackson.core:jackson-databind", "org.springframework:spring-core",
    "github.com/gin-gonic/gin", "golang.org/x/text", "serde", "tokio",
}

#: Draft rule text per weakness family (K8). The evidence and examples come from the record.
_RULES = {
    "memory": "Every copy into a fixed-size buffer must be bounded by the destination size; use the "
              "size-checked form and reject inputs longer than the buffer.",
    "injection": "Never build a shell command from input; pass an argument list with no shell, and "
                 "validate input against an allow-list.",
    "secrets": "No credential may appear in source or config; read it from the secret store at run time.",
    "crypto": "Use only approved algorithms and key sizes; certificate verification may never be disabled.",
    "dependency": "Pin every dependency to a version outside all known advisories; review pins each release.",
    "authz": "Every API operation must declare its authorisation requirement; debug endpoints may not ship.",
    "numeric": "Arithmetic on input-derived sizes must be checked for overflow before use.",
    "deserialization": "Never deserialise untrusted input with a general-purpose loader; use a safe schema loader.",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fam(row: dict) -> str:
    o = row.get("oracle") or ""
    if o.startswith(("secrets", "githistory", "git-secret")):
        return "secrets"
    if o.startswith("crypto"):
        return "crypto"
    if o.startswith(("osv", "binary:version")):
        return "dependency"
    if o.startswith("service"):
        return "authz"
    return row.get("family") or row.get("bug_class") or "other"


class Learning:
    def __init__(self, store) -> None:
        self.store = store
        self.path = Path(store.root) / "learning.json"
        self.state = self._load()

    # -- persistence -------------------------------------------------------------------------
    def _load(self) -> dict:
        if self.path.is_file():
            return json.loads(self.path.read_text())
        return {"observations": [], "seen_reports": [], "unfamiliar": {}, "lessons": {},
                "guidelines": {}, "quarantine": []}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.state, indent=2, sort_keys=True))

    # -- K7: observe and analyse --------------------------------------------------------------
    def observe_report(self, body: dict) -> None:
        p = body["project"]
        rid = f"{p['id']}/v{body['version']}"
        if rid in self.state["seen_reports"]:
            return
        self.state["seen_reports"].append(rid)
        for r in body["findings"]:
            file = r.get("file") or ""
            self.state["observations"].append({
                "project": p["id"], "version": body["version"], "at": body["created"], "key": r["key"],
                "family": _fam(r), "bug_class": r["bug_class"], "language": r.get("language"),
                "component": file.split("/")[0] if "/" in file else (file or "-"),
                "file": file.rsplit("/", 1)[-1], "unit": p.get("owner_unit"), "state": r["state"],
                "severity": r["severity"], "lane": r.get("lane"), "title": r["title"],
                "patch_excerpt": (r.get("patch_diff") or "")[:400] or None})
        for d in body.get("inventory", []):
            name = d["package"].lower()
            if name not in KNOWN_PACKAGES and d["package"] not in KNOWN_PACKAGES:
                u = self.state["unfamiliar"].setdefault(d["package"], {"ecosystem": d["ecosystem"],
                                                                       "projects": [], "first_seen": _now()})
                if p["id"] not in u["projects"]:
                    u["projects"].append(p["id"])
        self.save()

    def analytics(self) -> dict:
        obs = self.state["observations"]
        def count(field: str) -> list[tuple[str, int]]:
            c: dict[str, int] = {}
            for o in obs:
                c[str(o.get(field) or "-")] = c.get(str(o.get(field) or "-"), 0) + 1
            return sorted(c.items(), key=lambda kv: -kv[1])
        # regressions: present in a version, absent in a later one, present again later still
        per: dict[tuple, list[int]] = {}
        versions_of: dict[str, set[int]] = {}
        for o in obs:
            per.setdefault((o["project"], o["key"]), []).append(o["version"])
            versions_of.setdefault(o["project"], set()).add(o["version"])
        regressions = []
        for (pid, key), vs in per.items():
            present = set(vs)
            seq = sorted(versions_of[pid])
            was_on = gone = False
            for v in seq:
                if v in present:
                    if gone:
                        regressions.append({"project": pid, "key": key, "returned_in": v})
                        break
                    was_on = True
                elif was_on:
                    gone = True
        trend: dict[str, dict[str, int]] = {}
        for o in obs:
            trend.setdefault(o["family"], {})
            month = o["at"][:7]
            trend[o["family"]][month] = trend[o["family"]].get(month, 0) + 1
        return {"observations": len(obs), "by_family": count("family"), "by_language": count("language"),
                "by_component": count("component"), "by_unit": count("unit"),
                "regressions": regressions, "trend": trend,
                "unfamiliar_surface": self.state["unfamiliar"]}

    # -- K8: guideline proposals --------------------------------------------------------------
    def propose_guidelines(self) -> list[dict]:
        by: dict[str, list[dict]] = {}
        for o in self.state["observations"]:
            by.setdefault(o["family"], []).append(o)
        out = []
        for fam, obs in sorted(by.items(), key=lambda kv: -len(kv[1])):
            projects = sorted({o["project"] for o in obs})
            if len(obs) < GUIDELINE_MIN or len(projects) < GUIDELINE_PROJECTS:
                continue
            gid = f"G-{fam}"
            prior = self.state["guidelines"].get(gid, {})
            fixes = [o for o in obs if o["state"] == "fix-proven" and o.get("patch_excerpt")]
            g = {"id": gid, "family": fam, "rule": _RULES.get(fam, f"Review every occurrence of {fam} weaknesses."),
                 "evidence_count": len(obs), "projects": projects,
                 "examples": [{"project": o["project"], "file": o["file"], "title": o["title"]}
                              for o in obs[:5]],
                 "proven_fix_pattern": fixes[0]["patch_excerpt"] if fixes else None,
                 "evidence_keys": sorted({o["key"] for o in obs})[:50],
                 "status": prior.get("status", "proposed"), "decided_by": prior.get("decided_by"),
                 "decided_at": prior.get("decided_at")}
            self.state["guidelines"][gid] = g
            out.append(g)
        self.save()
        return out

    def decide_guideline(self, gid: str, *, approver: str, approve: bool) -> dict:
        g = self.state["guidelines"].get(gid)
        if g is None:
            return {"ok": False, "error": "no such guideline"}
        if not approver:
            return {"ok": False, "error": "a guideline is policy: a named approver is required"}
        g.update(status="approved" if approve else "rejected", decided_by=approver, decided_at=_now())
        self.save()
        return {"ok": True, "guideline": g}

    def approved_guidelines(self) -> list[dict]:
        return [g for g in self.state["guidelines"].values() if g["status"] == "approved"]

    # -- K9/K10/K11: lessons ------------------------------------------------------------------
    def propose_lesson(self, kind: str, value: str, *, source_project: str, rationale: str) -> dict:
        if kind not in ("dangerous-call", "entry-point", "fix-template"):
            raise ValueError(f"unknown lesson kind {kind!r}")
        lid = f"L-{kind}-{value}"
        if lid in self.state["lessons"]:
            return self.state["lessons"][lid]
        lesson = {"id": lid, "kind": kind, "value": value, "state": "probation",
                  "source_project": source_project, "rationale": rationale, "evidence": [],
                  "history": [{"at": _now(), "event": "proposed", "by": source_project, "note": rationale}]}
        self.state["lessons"][lid] = lesson
        self.save()
        return lesson

    def record_outcome(self, lid: str, *, project: str, finding_status: str,
                       false_positive: bool = False, note: str = "") -> dict:
        """Evidence for a lesson. Counts only from a gate-VERIFIED record and an unquarantined source;
        a false positive demotes the lesson at once and quarantines the source."""
        lesson = self.state["lessons"][lid]
        if project in self.state["quarantine"]:
            lesson["history"].append({"at": _now(), "event": "evidence-ignored", "by": project,
                                      "note": "source quarantined"})
            self.save()
            return lesson
        if false_positive:
            lesson["state"] = "demoted"
            lesson["history"].append({"at": _now(), "event": "demoted", "by": project,
                                      "note": note or "false positive on a negative control"})
            src = lesson["source_project"]            # the source that taught it is quarantined
            if src not in self.state["quarantine"]:
                self.state["quarantine"].append(src)
            self.save()
            return lesson
        if finding_status != "VERIFIED":
            lesson["history"].append({"at": _now(), "event": "evidence-ignored", "by": project,
                                      "note": f"not gate-verified ({finding_status})"})
            self.save()
            return lesson
        lesson["evidence"].append({"at": _now(), "project": project, "note": note})
        lesson["history"].append({"at": _now(), "event": "evidence", "by": project, "note": note})
        projects = {e["project"] for e in lesson["evidence"]}
        if (lesson["state"] == "probation" and len(lesson["evidence"]) >= PROMOTE_AFTER
                and len(projects) >= PROMOTE_PROJECTS):
            lesson["state"] = "promoted"
            lesson["history"].append({"at": _now(), "event": "promoted", "by": "rule",
                                      "note": f"{len(lesson['evidence'])} verified cases from "
                                              f"{len(projects)} projects"})
        self.save()
        return lesson

    def rollback(self, lid: str, *, actor: str, note: str = "") -> dict:
        lesson = self.state["lessons"][lid]
        lesson["state"] = "rolled-back"
        lesson["history"].append({"at": _now(), "event": "rolled-back", "by": actor, "note": note})
        self.save()
        return lesson

    def active_calls(self, project_id: str | None = None) -> list[str]:
        """Calls to treat as privileged for `project_id`: promoted lessons everywhere; a probation
        lesson only inside the project that proposed it (never applied elsewhere unproven)."""
        out = []
        for l in self.state["lessons"].values():
            if l["kind"] != "dangerous-call":
                continue
            if l["state"] == "promoted" or (l["state"] == "probation" and l["source_project"] == project_id):
                out.append(l["value"])
        return sorted(out)

    def health(self) -> dict:
        """K10: the learning-health dashboard."""
        ls = list(self.state["lessons"].values())
        by: dict[str, int] = {}
        for l in ls:
            by[l["state"]] = by.get(l["state"], 0) + 1
        return {"lessons": ls, "by_state": by, "quarantined_sources": list(self.state["quarantine"]),
                "guidelines": list(self.state["guidelines"].values()),
                "unfamiliar_surface": self.state["unfamiliar"]}
