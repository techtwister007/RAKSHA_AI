"""Console-facing views over a Session (Wave 3): narration, two voices, lane trust, estate map, exports.

Everything here is a pure rendering of the record: no new fact is computed and no status is changed,
so the console can never show more than the gate proved. Exports are stdlib-only: CSV, a minimal but
valid Office Open XML workbook (zip + XML), and a single-font PDF built by hand.
"""

from __future__ import annotations

import csv
import io
import zipfile
from xml.sax.saxutils import escape

from .finding import Finding, Status

# ---------------------------------------------------------------- F1: narration

_QUIET = {"checkpoint", "finding_added", "session_open"}

_TEMPLATES = {
    "autofuzz_started": ("info", "{t}: looking for an entry point to fuzz (no harness shipped)"),
    "harness_synthesized": ("info", "{t}: harness synthesized for {symbol} ({language}); quality gate passed"),
    "autofuzz_no_crash": ("dim", "{t}: no crash within the budget"),
    "crash_confirmed": ("alert", "{t}: {bug_class} confirmed at {site}; reproducer of {size} bytes replays"),
    "candidate_refused": ("warn", "{t}: a candidate was refused before any build ({reason})"),
    "build_free_scanned": ("info", "{t}: build-free scan complete ({count} findings, {proven} proven)"),
    "operator_approved": ("ok", "operator {actor} approved the fix for {finding}"),
    "operator_rejected": ("warn", "operator {actor} rejected the fix for {finding} ({reason})"),
    "operator_false_positive": ("warn", "operator {actor} marked {finding} a false positive ({reason})"),
    "operator_red_team_rerun": ("info", "operator {actor} re-ran the red team on {finding}"),
    "operator_exported": ("ok", "operator {actor} exported the evidence bundle for {finding}"),
    "campaign_budget_spent": ("warn", "{t}: per-target budget spent; reporting what was found"),
    "campaign_clean": ("ok", "{t}: no further crash found"),
}


def narrate(ev: dict) -> dict | None:
    """One event as a sentence an operator can read, with a level for colour. None = not shown."""
    k = ev.get("kind", "")
    if k in _QUIET:
        return None
    fields = {**ev, "t": ev.get("target") or ""}
    fields.setdefault("site", ev.get("site") or "?")
    if k == "candidate_gated":
        lane = (ev.get("lane") or "?").lower()
        if ev.get("passed"):
            level, text = "ok", f"{fields['t']}: candidate {ev.get('round')} ({lane} lane) cleared all five gate checks"
        else:
            check = (ev.get("failed_check") or "?").replace("_", " ").lower()
            reason = f" ({ev.get('reason')})" if ev.get("reason") else ""
            level, text = "warn", f"{fields['t']}: candidate {ev.get('round')} ({lane} lane) rejected at {check}{reason}"
        return {"seq": ev.get("seq"), "at": ev.get("at"), "level": level, "text": text}
    if k == "finding_status":
        st = ev.get("status")
        lane = (ev.get("lane") or "").lower()
        if st == "VERIFIED":
            level, text = "ok", f"{fields['t']}: {ev.get('bug_class')} VERIFIED; fix proven ({lane} lane)"
        elif st == "REPORT_ONLY":
            level, text = "warn", f"{fields['t']}: {ev.get('bug_class')} proven but no fix cleared the gate; referred"
        else:
            level, text = "info", f"{fields['t']}: {ev.get('bug_class')} is {st}"
        return {"seq": ev.get("seq"), "at": ev.get("at"), "level": level, "text": text}
    if k == "red_team_round":
        held = ev.get("held")
        verb = "held; no input broke it" if held else (f"BROKEN by {ev.get('wins')} input(s)" if held is False else "ran")
        return {"seq": ev.get("seq"), "at": ev.get("at"), "level": "ok" if held else "warn",
                "text": f"{fields['t']}: independent red team {verb} ({ev.get('attempts')} attempts)"}
    tmpl = _TEMPLATES.get(k)
    if tmpl is None:
        return None
    level, pattern = tmpl
    try:
        text = pattern.format(**fields)
    except (KeyError, IndexError):
        text = f"{fields['t']}: {k.replace('_', ' ')}"
    return {"seq": ev.get("seq"), "at": ev.get("at"), "level": level, "text": text}


def event_log(session) -> list[dict]:
    """The session's events as narrated lines, most recent first, blank ones dropped."""
    out = [n for ev in session.events if (n := narrate(ev)) is not None]
    out.reverse()
    return out


# ---------------------------------------------------------------- F13: two voices per finding

def _facts(f: Finding) -> dict:
    site = f.fix_site_set[0] if f.fix_site_set else None
    return {
        "id": f.id, "bug_class": f.bug_class, "severity": f.severity, "status": f.status.value,
        "target": f.target, "language": f.language,
        "where": (f"{site.uri}:{site.start_line}" if site and site.start_line else (site.uri if site else f.target)),
        "evidence": f.reproducer.kind if f.reproducer else None,
    }


def staff_view(f: Finding) -> dict:
    """The staff officer's rendering: what it is, how sure, what to do — no code."""
    from .brief import plain_summary
    fa = _facts(f)
    if f.status is Status.VERIFIED:
        action = "Fix proven and staged with a one-command rollback; authorise deployment per ROE."
    elif f.status is Status.REPORT_ONLY:
        action = "Proven real; no fix could be proven safe. Refer to a software authority."
    else:
        action = "Proven real; a fix is in preparation."
    vector = (f.proof_block().get("severity_vector") or {}).get("cvss31") or {}
    return {"voice": "staff", "summary": plain_summary(f), "action": action,
            "severity": f.severity, "cvss31": vector.get("base_score"), "disputed": f.disputed, **fa}


def engineer_view(f: Finding) -> dict:
    """The engineer's rendering: the same facts as mechanism — site, evidence, gate, diff, proofs."""
    fa = _facts(f)
    gate = {c.value: {"passed": g.passed, "detail": g.detail} for c, g in f.gate.items()}
    pb = f.proof_block()
    return {"voice": "engineer", "oracle": f.oracle, "repair_lane": f.repair_lane.value if f.repair_lane else None,
            "gate": gate, "patch_diff": f.patch_diff, "reach_proof": f.reach_proof, "bound_proof": f.bound_proof,
            "reproducer": pb.get("reproducer"), "frontier": list(f.frontier), "disputed": f.disputed, **fa}


def two_voices(f: Finding) -> dict:
    """Both renderings of one finding; they draw on the same facts and must agree on them."""
    return {"staff": staff_view(f), "engineer": engineer_view(f)}


# ---------------------------------------------------------------- F14: lane trust on this estate

def lane_trust(findings) -> dict:
    """Per lane (the oracle prefix): findings seen, proven, and operator-disputed, on this estate."""
    out: dict[str, dict] = {}
    for f in findings:
        lane = f.oracle.split(":", 1)[0]
        row = out.setdefault(lane, {"lane": lane, "findings": 0, "proven": 0, "disputed": 0})
        row["findings"] += 1
        if f.is_reportable:
            row["proven"] += 1
        if f.disputed:
            row["disputed"] += 1
    return out


# ---------------------------------------------------------------- F9: estate map (tier x status)

_TIER_ORDER = ["mission-critical", "operational", "support", "test", "unknown"]


def estate_map(session) -> dict:
    """Targets grouped by asset tier against finding status, plus the top three risks pinned."""
    findings = session.findings
    tiers: dict[str, dict] = {}
    for t in session.targets:
        mine = [findings[i] for i in t.finding_ids if i in findings]
        tier = (mine[0].mission_impact if mine and mine[0].mission_impact else "unknown")
        bucket = tiers.setdefault(tier, {"tier": tier, "targets": [], "verified": 0, "reportable": 0, "findings": 0})
        bucket["targets"].append(t.name)
        bucket["findings"] += len(mine)
        bucket["verified"] += sum(1 for f in mine if f.status is Status.VERIFIED)
        bucket["reportable"] += sum(1 for f in mine if f.is_reportable)
    order = {name: i for i, name in enumerate(_TIER_ORDER)}
    rows = sorted(tiers.values(), key=lambda b: order.get(b["tier"], 99))
    top = [{"id": r["id"], "message": r["message"], "severity": r["severity"], "score": r["score"]}
           for r in session.risk_register()[:3]]
    return {"tiers": rows, "top_risks": top}


# ---------------------------------------------------------------- F12: exports

def findings_csv(session) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "bug_class", "language", "status", "target", "lane",
                "evidence", "cvss31", "disputed", "message"])
    for f in session.findings.values():
        vector = (f.proof_block().get("severity_vector") or {}).get("cvss31") or {}
        w.writerow([f.id, f.severity, f.bug_class, f.language, f.status.value, f.target,
                    f.oracle.split(":", 1)[0], f.reproducer.kind if f.reproducer else "",
                    vector.get("base_score", ""), (f.disputed or ""), f.message])
    return buf.getvalue()


def _sheet_xml(rows: list[list[str]]) -> str:
    def cell(ref: str, val: str) -> str:
        return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(str(val))}</t></is></c>'
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>']
    for r, row in enumerate(rows, start=1):
        cells = "".join(cell(f"{chr(65 + c)}{r}", v) for c, v in enumerate(row[:26]))
        out.append(f'<row r="{r}">{cells}</row>')
    out.append("</sheetData></worksheet>")
    return "".join(out)


def findings_xlsx(session) -> bytes:
    """A minimal, valid .xlsx (Open XML) of the findings — stdlib zip + XML, no third-party library."""
    rows = [r.split("\x00") for r in _csv_rows(session)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                   "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   "</Relationships>")
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                   '<sheets><sheet name="Findings" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                   "</Relationships>")
        z.writestr("xl/worksheets/sheet1.xml", _sheet_xml(rows))
    return buf.getvalue()


def _csv_rows(session) -> list[str]:
    import csv as _csv
    buf = io.StringIO()
    w = _csv.writer(buf, delimiter="\x00", quoting=_csv.QUOTE_NONE, escapechar="\\")
    w.writerow(["id", "severity", "bug_class", "language", "status", "target", "lane", "cvss31", "message"])
    for f in session.findings.values():
        vector = (f.proof_block().get("severity_vector") or {}).get("cvss31") or {}
        w.writerow([f.id[:8], f.severity, f.bug_class, f.language, f.status.value, f.target,
                    f.oracle.split(":", 1)[0], vector.get("base_score", ""),
                    f.message.replace("\n", " ")[:200]])
    return buf.getvalue().splitlines()


def brief_pdf(text: str, *, title: str = "Commander's Brief") -> bytes:
    """A single-font (Courier) PDF of a brief — hand-built, so no third-party PDF library is needed.
    Latin text only; the Hindi brief is offered as text/markdown, since embedding a Devanagari font
    would mean carrying a font blob this build deliberately does not."""
    lines: list[str] = []
    for raw in text.split("\n"):
        ascii_line = raw.encode("ascii", "replace").decode("ascii").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        while len(ascii_line) > 95:
            lines.append(ascii_line[:95]); ascii_line = ascii_line[95:]
        lines.append(ascii_line)
    body = ["BT", "/F1 9 Tf", "54 760 Td", "11 TL"]
    for i, ln in enumerate(lines[:72]):
        body.append(f"({ln}) Tj" + (" T*" if i < len(lines[:72]) - 1 else ""))
    body.append("ET")
    stream = "\n".join(body).encode("latin-1", "replace")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF").encode()
    return bytes(out)


SHORTCUTS = [
    {"keys": "1 – 9", "action": "switch screen"},
    {"keys": "j / k", "action": "move down / up the finding list"},
    {"keys": "Enter", "action": "open the selected finding"},
    {"keys": "/", "action": "focus the search box"},
    {"keys": "h", "action": "toggle high-contrast (projector) mode"},
    {"keys": "e", "action": "toggle English / Hindi"},
    {"keys": "?", "action": "show this help"},
]
