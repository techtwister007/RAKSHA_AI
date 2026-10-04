"""Versioned project reports (K2–K4, K6, K13, K15, K16, K19, K29).

Every time a project is run, RAKSHA writes **Report vN** for it: a signed document (see signdoc)
chained to v(N-1), so the history is tamper-evident — a finding cannot silently drop between
versions, and no version can be edited or removed without breaking every later one.

A report holds, all read from the finding records (never invented):

  * every finding present in this run, with its state — ``open`` (proven, no fix), ``fix-proven``
    (RAKSHA proved a patch; it is not in the code until someone applies it), ``referred``;
  * the **diff against v(N-1)** (K3), each line with a colour *and* an icon *and* a word:
        🟢 ✓ fixed       — gone, and the absence is a proof (a deterministic re-check)
        ⚪ ? not re-found — gone from this run, but its absence is not a proof (a crash not seen
                            again); shown, never counted as fixed
        🔴 ✚ new         — not in v(N-1), including anything a patch introduced
        🟠 ● still open  — present in both, with how many versions it has been open
        🔵 ⚑ needs human — RAKSHA may not or cannot close it; the reason and a checklist
  * the **needs-a-human list** (K4) and the re-check of anything a person marked done;
  * a **posture score** (K16) whose breakdown sums to the deduction, null below the evidence floor;
  * **exposure-days** (K13) per serious weakness against a tier-set deadline, and the **secrets
    tracker** (K19), both computed from the version history;
  * the **data-handling statement** (K29): what was read, and that nothing left the box;
  * the component inventory and attack surface, with **drift** against v(N-1) (K17, K18).

``summary_html`` renders the one-page, phone- and print-friendly colour summary (K6) in English
or Hindi. ``issue_certificate`` writes the readiness certificate (K15) only when its conditions
hold in the record.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import signdoc
from .finding import Finding, Status
from .projects import Project, Store, drift, inventory, surface

STEM = "report"
SCHEMA = "raksha-project-report/1"
SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_WEIGHT = {"critical": 25.0, "high": 12.0, "medium": 5.0, "low": 2.0, "info": 0.0}
_TIER_MULT = {"mission-critical": 2.0, "operational": 1.5, "support": 1.0, "test": 0.5}
#: Days a weakness may stay open before its deadline is breached, by severity; scaled by tier.
_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
_SLA_TIER = {"mission-critical": 0.5, "operational": 1.0, "support": 1.5, "test": 2.0}
EVIDENCE_FLOOR_FILES = 1

#: The diff vocabulary: (colour name, emoji, icon, English word). Colour never travels alone.
MARK = {
    "fixed": ("green", "🟢", "✓", "fixed"),
    "not-refound": ("grey", "⚪", "?", "not re-found"),
    "new": ("red", "🔴", "✚", "new"),
    "open": ("amber", "🟠", "●", "still open"),
    "needs-human": ("blue", "🔵", "⚑", "needs a human"),
}

# ---- K4: what RAKSHA may not or cannot close itself --------------------------------------------

_HUMAN = {
    "rotate-credential": ("A live credential is exposed; only its owner can rotate it.",
                          ["Revoke the exposed credential at its issuer",
                           "Issue a replacement and store it in the secret store, not the code",
                           "Remove it from the file (and from history if it was committed)",
                           "Re-run RAKSHA: the secret check must no longer match"]),
    "policy-decision": ("An authorisation or exposure decision belongs to the system owner.",
                        ["Decide who may call this endpoint", "Add the authorisation requirement to the spec/code",
                         "Re-run RAKSHA: the spec check must pass"]),
    "dependency-bump": ("A dependency upgrade is prepared but needs a build to verify.",
                        ["Apply the prepared version bump", "Build and run the project's tests",
                         "Re-run RAKSHA: the version match must no longer fire"]),
    "crypto-migration": ("A cryptographic choice needs an owner's migration decision.",
                         ["Pick the approved replacement primitive", "Plan key/data migration",
                          "Re-run RAKSHA: the crypto check must no longer match"]),
    "gate-could-not-certify": ("The weakness is proven, but no fix cleared all five gate checks.",
                               ["Read the gate record: which check refused each candidate",
                                "Write or approve a fix", "Re-run RAKSHA so the gate can certify it"]),
    "recommend-only": ("The fix is proven, but this asset's rules of engagement allow only a "
                       "recommendation: a human approves before it is applied.",
                       ["Review the proven patch and its evidence bundle", "Approve (two signatures on a "
                        "mission-critical asset) and apply in a maintenance window",
                        "Re-run RAKSHA: the finding must be gone"]),
}


def _family(bug_class: str | None) -> str | None:
    from .cwe import family
    try:
        return family(bug_class)
    except Exception:  # noqa: BLE001
        return None


def human_reason(f: Finding, tier: str | None) -> str | None:
    """The K4 reason code this finding needs a person for, or None when RAKSHA can close it."""
    o = f.oracle or ""
    if o.startswith(("secrets", "githistory", "git-secret")):
        return "rotate-credential"
    if o.startswith("service") or f.bug_class in ("CWE-862", "CWE-489", "CWE-306"):
        return "policy-decision"
    if o.startswith("crypto"):
        return "crypto-migration"
    if o.startswith(("osv", "binary:version")) and f.status is not Status.VERIFIED:
        return "dependency-bump"
    if f.status is Status.REPORT_ONLY:
        return "gate-could-not-certify"
    if f.status is Status.VERIFIED and (tier == "mission-critical" or f.roe_level.value in ("R0", "R1")):
        return "recommend-only"
    return None


def finding_key(f: Finding) -> str:
    """Stable identity of a weakness across versions: what and where, not when or which line number
    a patch elsewhere in the file moved it to."""
    site = f.fix_site_set[0] if f.fix_site_set else None
    file = site.uri if site else (f.frames[0].uri if f.frames and f.frames[0].uri else "")
    sym = (site.symbol if site and site.symbol else (f.frames[0].symbol if f.frames else "")) or ""
    msg = re.sub(r"\d+", "#", (f.message or "")[:160])
    return f"{f.oracle}|{file}|{sym}|{f.bug_class}|{msg}"


def _state(f: Finding) -> str:
    if f.status is Status.VERIFIED:
        return "fix-proven"
    if f.status is Status.REPORT_ONLY:
        return "referred"
    return "open"


def _row(f: Finding, tier: str | None) -> dict:
    site = f.fix_site_set[0] if f.fix_site_set else None
    reason = human_reason(f, tier)
    rep = f.reproducer
    return {
        "key": finding_key(f), "finding": f.id, "bug_class": f.bug_class, "family": _family(f.bug_class),
        "severity": (f.severity or "medium").lower(), "status": f.status.value, "state": _state(f),
        "title": f"{f.bug_class}: {(f.message or '').splitlines()[0][:120]}",
        "file": site.uri if site else None, "line": site.start_line if site else None,
        "symbol": site.symbol if site else None, "oracle": f.oracle, "language": f.language,
        "lane": f.repair_lane.value if f.repair_lane else None,
        "evidence": rep.kind if rep else None, "reproducer_sha256": rep.artifact_sha256 if rep else None,
        "patch_diff": f.patch_diff if f.status is Status.VERIFIED else None,
        "gate": {c.value: g.passed for c, g in f.gate.items()},
        "needs_human": ({"reason": reason, "why": _HUMAN[reason][0], "checklist": _HUMAN[reason][1]}
                        if reason else None),
    }


# ---- history ------------------------------------------------------------------------------------

def versions(store: Store, pid: str) -> list[int]:
    d = store.dir(pid) / "reports"
    if not d.is_dir():
        return []
    return sorted(int(p.name[1:]) for p in d.iterdir() if p.is_dir() and re.fullmatch(r"v\d+", p.name))


def load(store: Store, pid: str, version: int) -> dict:
    return signdoc.read(store.dir(pid) / "reports" / f"v{version}", STEM)


def history(store: Store, pid: str) -> list[dict]:
    return [load(store, pid, v) for v in versions(store, pid)]


def verify_chain(store: Store, pid: str) -> tuple[bool, list[str]]:
    """Every version verifies and chains to the one before it."""
    prev = signdoc.ZERO
    problems = []
    for v in versions(store, pid):
        d = store.dir(pid) / "reports" / f"v{v}"
        ok, ps = signdoc.verify(d, STEM, expect_prev=prev)
        if not ok:
            problems += [f"v{v}: {p}" for p in ps]
        prev = signdoc.doc_hash(d, STEM)
    return not problems, problems


# ---- the diff, score, exposure ------------------------------------------------------------------

def diff(prev: dict | None, rows: list[dict]) -> dict:
    """K3: v(N-1) → vN, each entry with its mark."""
    before = {r["key"]: r for r in (prev or {}).get("findings", [])}
    now = {r["key"]: r for r in rows}
    out = {k: [] for k in MARK}
    for k, r in now.items():
        if r.get("needs_human"):
            out["needs-human"].append(k)
        if k in before:
            out["open"].append(k)
        elif prev is not None:
            out["new"].append(k)
    for k, r in before.items():
        if k in now:
            continue
        # a deterministic re-check that no longer matches IS the proof; a crash not seen again is not
        out["fixed" if r.get("evidence") == "deterministic-match" else "not-refound"].append(k)
    return out


def _open_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["state"] in ("open", "referred", "fix-proven")]


def posture_score(rows: list[dict], *, tier: str | None, files_scanned: int) -> dict:
    """K16: 100 minus weighted deductions; the breakdown sums exactly to 100 - score. A proven but
    unapplied fix still counts half (the weakness is in the code until someone applies it)."""
    if files_scanned < EVIDENCE_FLOOR_FILES:
        return {"score": None, "why": "below the evidence floor: nothing was scanned", "breakdown": []}
    mult = _TIER_MULT.get(tier or "", 1.0)
    items = []
    for r in _open_rows(rows):
        w = _SEV_WEIGHT.get(r["severity"], 5.0) * mult * (0.5 if r["state"] == "fix-proven" else 1.0)
        if w:
            items.append({"key": r["key"], "title": r["title"], "deduction": w})
    total = sum(i["deduction"] for i in items)
    if total > 100.0:                              # scale so the parts still sum to the whole
        for i in items:
            i["deduction"] = i["deduction"] * 100.0 / total
        total = 100.0
    for i in items:
        i["deduction"] = round(i["deduction"], 3)
    if items:                                      # rounding residue goes on the largest item, so
        resid = round(round(total, 3) - sum(i["deduction"] for i in items), 3)   # the parts sum exactly
        max(items, key=lambda i: i["deduction"])["deduction"] = round(
            max(items, key=lambda i: i["deduction"])["deduction"] + resid, 3)
    score = round(100.0 - round(total, 3), 3)
    return {"score": score, "tier_multiplier": mult, "breakdown": items,
            "why": "100 minus the weighted open weaknesses (severity × asset tier; a proven, unapplied "
                   "fix counts half)"}


def sla_days(severity: str, tier: str | None) -> float:
    return _SLA_DAYS.get(severity, 90) * _SLA_TIER.get(tier or "", 1.0)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def exposure(hist: list[dict], rows: list[dict], *, tier: str | None, now: datetime) -> list[dict]:
    """K13: days each weakness has been (or was) open, against its deadline. Computed from the
    version history: the clock starts at the first version holding it and stops at the version
    whose run proves it gone."""
    first: dict[str, datetime] = {}
    closed: dict[str, datetime] = {}
    seen_prev: set[str] = set()
    for rep in hist:
        t = _parse(rep["created"])
        keys = {r["key"] for r in rep["findings"]}
        for k in keys:
            first.setdefault(k, t)
            closed.pop(k, None)
        for k in seen_prev - keys:
            closed.setdefault(k, t)
        seen_prev = keys
    rows_by = {r["key"]: r for r in rows}
    for k in rows_by:
        first.setdefault(k, now)
        closed.pop(k, None)
    for k in seen_prev - set(rows_by):
        closed.setdefault(k, now)
    sev_of = {r["key"]: r["severity"] for rep in hist for r in rep["findings"]}
    sev_of.update({k: r["severity"] for k, r in rows_by.items()})
    out = []
    for k, t0 in first.items():
        sev = sev_of.get(k, "medium")
        if sev not in ("critical", "high"):
            continue
        end = closed.get(k, now)
        days = round((end - t0).total_seconds() / 86400.0, 2)
        deadline = sla_days(sev, tier)
        out.append({"key": k, "severity": sev, "open": k not in closed, "days": days,
                    "deadline_days": deadline, "breached": days > deadline})
    return sorted(out, key=lambda e: -e["days"])


def secrets_tracker(hist: list[dict], rows: list[dict], *, now: datetime) -> list[dict]:
    """K19: each exposed credential, rotated or not, and days exposed."""
    is_secret = lambda r: (r.get("oracle") or "").startswith(("secrets", "githistory", "git-secret"))
    first: dict[str, datetime] = {}
    gone: dict[str, datetime] = {}
    title: dict[str, str] = {}
    prev: set[str] = set()
    for rep in hist:
        t = _parse(rep["created"])
        keys = {r["key"] for r in rep["findings"] if is_secret(r)}
        for r in rep["findings"]:
            if is_secret(r):
                first.setdefault(r["key"], t); title[r["key"]] = r["title"]
        for k in prev - keys:
            gone.setdefault(k, t)
        prev = keys
    cur = {r["key"] for r in rows if is_secret(r)}
    for r in rows:
        if is_secret(r):
            first.setdefault(r["key"], now); title[r["key"]] = r["title"]; gone.pop(r["key"], None)
    for k in prev - cur:
        gone.setdefault(k, now)
    return [{"key": k, "title": title.get(k), "rotated": k in gone,
             "days_exposed": round(((gone.get(k, now)) - t0).total_seconds() / 86400.0, 2)}
            for k, t0 in sorted(first.items(), key=lambda kv: kv[1])]


# ---- writing a version --------------------------------------------------------------------------

def record_run(store: Store, project: Project, findings: list[Finding], root: str | Path, *,
               run: dict | None = None, extra_privileged: list[str] = (),
               now: datetime | None = None, key: bytes | None = None) -> dict:
    """Write Report vN for `project` from this run's `findings`. Returns the body."""
    now = now or datetime.now(timezone.utc)
    vs = versions(store, project.id)
    n = (vs[-1] + 1) if vs else 1
    prev = load(store, project.id, vs[-1]) if vs else None
    prev_hash = signdoc.doc_hash(store.dir(project.id) / "reports" / f"v{vs[-1]}", STEM) if vs else signdoc.ZERO
    hist = history(store, project.id)
    rows = [_row(f, project.tier) for f in findings if f.is_reportable]
    rows.sort(key=lambda r: (SEVERITIES.index(r["severity"]) if r["severity"] in SEVERITIES else 9, r["key"]))
    run = dict(run or {})
    files = int(run.get("files_scanned", len(project.structure)))
    d = diff(prev, rows)
    # K4: anything a person marked done is re-checked against this run, never taken on trust
    marks = store.marks(project.id)
    present = {r["key"] for r in rows}
    rechecked = [{"key": k, "marked_by": m["actor"], "closed": k not in present,
                  "verdict": "confirmed closed by this run" if k not in present
                  else "still present — marked done, but this run found it again"}
                 for k, m in sorted(marks.items())]
    for r in rechecked:
        if r["closed"]:
            store.clear_mark(project.id, r["key"])
    opens_count = {r["key"]: sum(1 for rep in hist if r["key"] in {x["key"] for x in rep["findings"]}) + 1
                   for r in rows}
    surf = surface(root, extra_privileged=extra_privileged)
    counts = {s: sum(1 for r in _open_rows(rows) if r["severity"] == s) for s in SEVERITIES}
    prev_counts = (prev or {}).get("counts")
    body = {
        "schema": SCHEMA, "version": n, "created": now.isoformat(timespec="seconds"),
        "project": project.as_dict(), "prev_version": vs[-1] if vs else None,
        "run": run, "findings": rows, "counts": counts,
        "trend": ({s: [prev_counts.get(s, 0), counts[s]] for s in ("critical", "high")}
                  if prev_counts else None),
        "diff": d, "versions_open": opens_count,
        "gone_titles": {r["key"]: r["title"] for r in (prev or {}).get("findings", [])
                        if r["key"] in set(d["fixed"]) | set(d["not-refound"])},
        "needs_human": [{"key": r["key"], "title": r["title"], **r["needs_human"]}
                        for r in rows if r["needs_human"]],
        "marks_rechecked": rechecked,
        "score": posture_score(rows, tier=project.tier, files_scanned=files),
        "exposure": exposure(hist, rows, tier=project.tier, now=now),
        "secrets": secrets_tracker(hist, rows, now=now),
        "inventory": inventory(root),
        "surface": surf,
        "drift": drift((prev or {}).get("surface"), surf),
        "data_statement": _data_statement(run, files),
    }
    out = store.dir(project.id) / "reports" / f"v{n}"
    signdoc.write(out, STEM, body, render_markdown(body), kind="project-report",
                  doc_id=f"{project.id}/v{n}", prev=prev_hash, key=key)
    return body


def _data_statement(run: dict, files: int) -> dict:
    """K29: what was read, where it stayed, and the measured egress for the run."""
    eg = run.get("egress") or {}
    return {"files_read": files, "bytes_read": run.get("bytes_read"),
            "stayed_on": "this machine (read in place or in a private scratch copy; nothing uploaded)",
            "raksha_egress_calls": eg.get("raksha_egress_calls"),
            "host_tx_packets_delta": eg.get("tx_packets_delta"),
            "journal_head": run.get("journal_head"),
            "statement": ("No code or finding left this machine during this run."
                          if eg.get("raksha_egress_calls") == 0 else
                          "RAKSHA's own egress counter was not available for this run; no claim is made."
                          if eg.get("raksha_egress_calls") is None else
                          "RAKSHA recorded egress calls during this run — investigate before relying on it.")}


# ---- renderings ---------------------------------------------------------------------------------

def _line(kind: str, text: str) -> str:
    _c, emoji, icon, word = MARK[kind]
    return f"- {emoji} {icon} **{word}** — {text}"


def render_markdown(b: dict) -> str:
    p = b["project"]
    by = {r["key"]: r for r in b["findings"]}
    L = [f"# {p['name']} ({p['id']}) — security report v{b['version']}", "",
         f"Issued {b['created']} · tier: {p.get('tier') or 'unclassified'} · owner: {p.get('owner_unit') or '—'}"
         + (f" · previous: v{b['prev_version']}" if b["prev_version"] else " · first report"), ""]
    sc = b["score"]
    L.append(f"**Posture score:** {sc['score'] if sc['score'] is not None else 'n/a'}"
             + (f" ({sc['why']})" if sc.get("why") else ""))
    if b.get("trend"):
        L.append("**Trend:** " + ", ".join(f"{s.title()} {a} → {c}" for s, (a, c) in b["trend"].items()))
    L += ["", "## What changed since the last report", ""]
    d = b["diff"]
    for kind in ("fixed", "not-refound", "new", "open", "needs-human"):
        for k in d.get(kind, []):
            r = by.get(k)
            title = r["title"] if r else b.get("gone_titles", {}).get(k, k.split("|")[3])
            extra = f" (open {b['versions_open'].get(k, 1)} versions)" if kind == "open" else ""
            L.append(_line(kind, title + extra))
    if not any(d.values()):
        L.append("- nothing found in this run")
    if b["needs_human"]:
        L += ["", "## Needs a human", ""]
        for h in b["needs_human"]:
            L.append(f"- 🔵 ⚑ **{h['title']}** — {h['why']}")
            L += [f"  - [ ] {c}" for c in h["checklist"]]
    if b["marks_rechecked"]:
        L += ["", "## Items marked done, re-checked", ""]
        L += [f"- {'🟢 ✓' if m['closed'] else '🔴 ✚'} {m['verdict']} ({m['key'].split('|')[3]})"
              for m in b["marks_rechecked"]]
    if b["drift"]:
        L += ["", "## New attack surface", ""] + [f"- ⚠ {a['detail']}" for a in b["drift"]]
    ds = b["data_statement"]
    L += ["", "## Data handling", "", f"{ds['files_read']} files read; {ds['statement']}", ""]
    return "\n".join(L)


_HI = {"report": "सुरक्षा रिपोर्ट", "fixed": "ठीक हुआ", "not-refound": "दोबारा नहीं मिला",
       "new": "नया", "open": "अब भी खुला", "needs-human": "मानवीय निर्णय आवश्यक",
       "score": "सुरक्षा स्कोर", "what changed": "पिछली रिपोर्ट से क्या बदला",
       "needs a human": "मानवीय निर्णय आवश्यक", "data": "डेटा प्रबंधन",
       "statement": "इस रन के दौरान कोई कोड या निष्कर्ष इस मशीन से बाहर नहीं गया।",
       "first": "पहली रिपोर्ट", "nothing": "इस रन में कुछ नहीं मिला"}


def summary_html(b: dict, *, lang: str = "en") -> str:
    """K6: one page, phone- and print-friendly, colour + icon + word on every line."""
    hi = lang == "hi"
    t = (lambda k, en: _HI.get(k, en)) if hi else (lambda k, en: en)
    p = b["project"]
    by = {r["key"]: r for r in b["findings"]}
    css = {"green": "#2c6540", "grey": "#666", "red": "#a3271b", "amber": "#9c5f14", "blue": "#2f5f86"}
    rows = []
    for kind in ("fixed", "not-refound", "new", "open", "needs-human"):
        colour, emoji, icon, word = MARK[kind]
        for k in b["diff"].get(kind, []):
            r = by.get(k)
            title = r["title"] if r else b.get("gone_titles", {}).get(k, k.split("|")[3])
            rows.append(f'<li style="border-left:6px solid {css[colour]}"><b style="color:{css[colour]}">'
                        f'{icon} {html.escape(t(kind, word))}</b> {html.escape(title)}</li>')
    sc = b["score"]["score"]
    trend = " · ".join(f"{s} {a}→{c}" for s, (a, c) in (b.get("trend") or {}).items())
    return f"""<!doctype html><html lang="{'hi' if hi else 'en'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(p['name'])} v{b['version']}</title>
<style>body{{font-family:-apple-system,"Segoe UI",Roboto,"Noto Sans Devanagari",sans-serif;margin:16px;max-width:760px;color:#111;background:#fff}}
h1{{font-size:20px;margin:0 0 4px}} .m{{color:#555;font-size:13px}} .s{{font-size:30px;font-weight:700}}
ul{{list-style:none;padding:0}} li{{padding:6px 10px;margin:4px 0;background:#f6f6f4}}
@media print{{body{{margin:0}} li{{break-inside:avoid}}}}</style></head><body>
<h1>{html.escape(p['name'])} — {t('report', 'security report')} v{b['version']}</h1>
<div class="m">{html.escape(p['id'])} · {html.escape(b['created'])} · {html.escape(p.get('tier') or '—')}
{' · v' + str(b['prev_version']) + ' →' if b['prev_version'] else ' · ' + t('first', 'first report')}</div>
<p>{t('score', 'Posture score')}: <span class="s">{sc if sc is not None else 'n/a'}</span> {html.escape(trend)}</p>
<h2>{t('what changed', 'What changed')}</h2><ul>{''.join(rows) or '<li>' + t('nothing', 'nothing found in this run') + '</li>'}</ul>
<p class="m">{t('data', 'Data handling')}: {html.escape(t('statement', b['data_statement']['statement']) if b['data_statement']['raksha_egress_calls'] == 0 else b['data_statement']['statement'])}</p>
</body></html>"""


# ---- K15 readiness certificate -----------------------------------------------------------------

CERT_STEM = "certificate"


def issue_certificate(store: Store, pid: str, version: int | None = None, *,
                      key: bytes | None = None) -> dict:
    """Issue only when the record supports it: no open critical weakness, every fix shown as
    proven actually carries a full gate pass, and the chain verifies."""
    vs = versions(store, pid)
    if not vs:
        return {"ok": False, "error": "no report for this project"}
    v = version or vs[-1]
    ok_chain, problems = verify_chain(store, pid)
    if not ok_chain:
        return {"ok": False, "error": "report chain does not verify: " + "; ".join(problems[:3])}
    b = load(store, pid, v)
    crit = [r for r in _open_rows(b["findings"]) if r["severity"] == "critical" and r["state"] != "fix-proven"]
    if crit:
        return {"ok": False, "error": f"{len(crit)} open critical weakness(es); certificate refused"}
    unproven = [r for r in b["findings"] if r["state"] == "fix-proven"
                and not (r["gate"] and all(r["gate"].values()) and len(r["gate"]) >= 5)]
    if unproven:
        return {"ok": False, "error": "a fix marked proven lacks a full gate record"}
    rd = store.dir(pid) / "reports" / f"v{v}"
    body = {"schema": "raksha-readiness-certificate/1", "project": b["project"], "version": v,
            "report_hash": signdoc.doc_hash(rd, STEM),
            "issued": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "statement": f"As of report v{v}: no open critical weakness; every fix shown as proven passed "
                         f"all five gate checks; {len(b['needs_human'])} item(s) await a human decision.",
            "awaiting_human": len(b["needs_human"]), "score": b["score"]["score"]}
    out = store.dir(pid) / "certificates" / f"v{v}"
    if out.exists():
        import shutil
        shutil.rmtree(out)
    signdoc.write(out, CERT_STEM, body, f"# Readiness certificate — {b['project']['name']} v{v}\n\n"
                  + body["statement"] + "\n", kind="readiness-certificate",
                  doc_id=f"{pid}/v{v}/certificate", key=key)
    return {"ok": True, "path": str(out), "statement": body["statement"]}


def report_json(store: Store, pid: str, version: int) -> str:
    return json.dumps(load(store, pid, version), indent=2, ensure_ascii=False)
