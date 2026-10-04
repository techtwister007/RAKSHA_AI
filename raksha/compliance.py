"""K28 — the compliance pack: a period's signed reports and certificates, as verifier media.

``build_pack(store, out, since=..., until=...)`` gathers, for every project, each report version
issued in the period and every readiness certificate for those versions, and writes them as
self-contained verifier media (J7): an auditor runs ``python3 verify.py`` on their own machine and
every report's signature AND its chain are re-checked — the first version in the period is checked
against the hash of the version before it, so a pack cannot quietly start after an inconvenient one.

``quarter_bounds("2026-Q4")`` gives the ISO bounds of a calendar quarter.
"""

from __future__ import annotations

from pathlib import Path

from . import reports, signdoc
from .projects import Store


def quarter_bounds(q: str) -> tuple[str, str]:
    year, part = q.upper().split("-Q")
    start_month = (int(part) - 1) * 3 + 1
    end_year, end_month = (int(year) + 1, 1) if start_month == 10 else (int(year), start_month + 3)
    return f"{year}-{start_month:02d}-01T00:00:00", f"{end_year}-{end_month:02d}-01T00:00:00"


def build_pack(store: Store, out: str | Path, *, since: str, until: str) -> dict:
    from .verifiermedia import build_media
    docs: list[dict] = []
    summary = []
    for p in store.all():
        vs = reports.versions(store, p.id)
        chosen = [v for v in vs if since <= reports.load(store, p.id, v)["created"][:19] < until]
        if not chosen:
            continue
        first = chosen[0]
        prev_dir = store.dir(p.id) / "reports" / f"v{first - 1}"
        first_prev = signdoc.doc_hash(prev_dir, reports.STEM) if first > 1 and prev_dir.is_dir() else signdoc.ZERO
        for v in chosen:
            docs.append({"src": store.dir(p.id) / "reports" / f"v{v}", "dest": f"reports/{p.id}/v{v}",
                         "stem": reports.STEM, "chain": p.id, "first_prev": first_prev})
            cert = store.dir(p.id) / "certificates" / f"v{v}"
            if cert.is_dir():
                docs.append({"src": cert, "dest": f"certificates/{p.id}/v{v}", "stem": reports.CERT_STEM})
        summary.append({"project": p.id, "name": p.name, "versions": chosen})
    if not docs:
        return {"ok": False, "error": "no report issued in that period"}
    build_media(out, [], documents=docs)
    return {"ok": True, "path": str(out), "projects": summary, "documents": len(docs)}
