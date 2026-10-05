"""The console web server — stdlib only, served entirely offline.

No framework, no third-party dependency, no external asset: a console that phoned out would
contradict the whole air-gap pitch, so it is served from one self-contained HTML file and a tiny
JSON API over Python's own http.server. The air-gap guard checks this directory ships nothing
external.

Read routes (GET):
  /                          the console (console/index.html, with the session token injected)
  /api/snapshot              board + findings + scorecard + events + estate map + lane trust
  /api/finding/<id>          one finding's full proof block
  /api/voices/<id>           the staff-officer and engineer renderings of one finding (F13)
  /api/brief/<id>            the bilingual Commander's Brief (F10)
  /api/verify/<id>           re-verify the sealed evidence bundle
  /api/labels                Hindi console labels (F10)
  /api/projects, /api/project/<id>[/v/<n>|/summary/<n>?lang=|/role/<r>|/fixes?q=]  (K5, K6, K25, K23)
  /api/mission, /api/heatmap, /api/learning   (K12, K14, K7-K10)
  /api/timelapse[?n=|?t=]    J9: frames of the journal (or the recorded run), or the state at t seconds
  /api/help                  keyboard shortcuts (F12)
  /api/export/findings.csv   | findings.xlsx | brief/<id>.pdf   (F12)

Write routes (POST, operator actions — F7), each requiring the session token in X-RAKSHA-Token:
  /api/action/approve|reject|false_positive|rerun_red_team|export   {finding, actor, reason}
  /api/action/advisory    {finding}            issue a signed internal-CERT advisory (J8)
  /api/action/mark_done|certificate|guideline|lesson_rollback   Wave 5 owner and learning actions
  /api/action/saysno                       run the "it says no" beat (J1)
  /api/action/intake      {path, name, deep}   ingest a judge's media without a restart (J2)
  /api/action/egress_reset                 zero the egress counter for the air-gap beat (J6)

The token is minted per process, injected into the served page, and required on every POST, so a
stray local page cannot drive operator actions. `serve(session, port)` blocks; `make_handler` returns
a handler class for tests (its token is on the class as TOKEN).
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, unquote
from pathlib import Path

CONSOLE_DIR = Path(__file__).parent
INDEX = CONSOLE_DIR / "index.html"


_STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".mjs": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
                 ".jpg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon",
                 ".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".json": "application/json"}


def _static_file(path: str):
    """A file under console/ with a known static type, or None. Lets a redesigned console ship its
    own stylesheets, scripts, fonts and images (all offline). Never leaves console/; never serves
    Python or dotfiles."""
    rel = path.lstrip("/")
    if not rel or rel.startswith(".") or "/." in rel or "\\" in rel:
        return None
    try:
        f = (CONSOLE_DIR / rel).resolve()
        f.relative_to(CONSOLE_DIR.resolve())
    except (ValueError, OSError):
        return None
    ctype = _STATIC_TYPES.get(f.suffix.lower())
    return (f, ctype) if ctype and f.is_file() else None


def make_handler(session, *, token: str | None = None):
    tok = token or secrets.token_urlsafe(16)

    class Handler(BaseHTTPRequestHandler):
        TOKEN = tok

        def log_message(self, *args):  # keep the demo output clean
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            # No-egress posture is also a header promise: nothing here references an external origin.
            self.send_header("Content-Security-Policy",
                             "default-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _download(self, name: str, body: bytes, ctype: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (http.server API)
            try:
                self._get(urlsplit(self.path).path)
            except Exception as e:  # noqa: BLE001 — a 500 the console can show, never a dropped socket
                self._json(500, {"error": f"{type(e).__name__}: {e}"})

        def do_POST(self):  # noqa: N802
            try:
                self._post(urlsplit(self.path).path)
            except Exception as e:  # noqa: BLE001
                self._json(500, {"error": f"{type(e).__name__}: {e}"})

        # ---- reads -------------------------------------------------------------------------
        def _get(self, path: str) -> None:
            from raksha import console_api
            if path in ("/", "/index.html"):
                if INDEX.exists():
                    html = INDEX.read_text(encoding="utf-8").replace("__RAKSHA_TOKEN__", tok)
                    self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                else:
                    self._send(500, b"console/index.html missing", "text/plain")
                return
            if path == "/app.js":
                js = CONSOLE_DIR / "app.js"
                if js.exists():
                    self._send(200, js.read_bytes(), "text/javascript; charset=utf-8")
                else:
                    self._send(404, b"app.js missing", "text/plain")
                return
            static = _static_file(path)
            if static is not None:
                self._send(200, static[0].read_bytes(), static[1]); return
            if path == "/api/snapshot":
                self._json(200, session.snapshot()); return
            if path == "/api/timelapse":
                from raksha.timelapse import for_session
                rec = for_session(session)
                if rec is None:
                    self._json(404, {"error": "no journal and no recorded run"}); return
                q = parse_qs(urlsplit(self.path).query)
                if "t" in q:
                    self._json(200, rec.at(float(q["t"][0]))); return
                self._json(200, {"summary": rec.summary(), "frames": rec.frames(int(q.get("n", ["60"])[0]))})
                return
            if path.startswith("/api/projects") or path.startswith("/api/project/") or path in (
                    "/api/mission", "/api/heatmap", "/api/learning"):
                q = parse_qs(urlsplit(self.path).query)
                res = _projects_get(session, path, q)
                if isinstance(res, tuple):          # (html, code)
                    self._send(res[1], res[0].encode("utf-8"), "text/html; charset=utf-8"); return
                self._json(200 if "error" not in res else 404, res); return
            if path == "/api/labels":
                from raksha.brief import console_labels_hi
                self._json(200, console_labels_hi()); return
            if path == "/api/help":
                self._json(200, {"shortcuts": console_api.SHORTCUTS}); return
            if path.startswith("/api/finding/"):
                d = session.finding_detail(_id(path)); self._json(200, d) if d else self._json(404, {"error": "not found"})
                return
            if path.startswith("/api/voices/"):
                d = session.two_voices(_id(path)); self._json(200, d) if d else self._json(404, {"error": "not found"})
                return
            if path.startswith("/api/brief/"):
                d = session.commanders_brief(_id(path)); self._json(200, d) if d else self._json(404, {"error": "not reportable"})
                return
            if path.startswith("/api/verify/"):
                d = session.verify_bundle(_id(path)); self._json(200, d) if d else self._json(404, {"error": "not found"})
                return
            if path == "/api/export/findings.csv":
                self._download("raksha-findings.csv", console_api.findings_csv(session).encode(), "text/csv"); return
            if path == "/api/export/findings.xlsx":
                self._download("raksha-findings.xlsx", console_api.findings_xlsx(session),
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"); return
            if path.startswith("/api/export/brief/") and path.endswith(".pdf"):
                fid = _id(path[: -len(".pdf")])
                brief = session.commanders_brief(fid)
                if not brief:
                    self._json(404, {"error": "not reportable"}); return
                self._download(f"brief-{fid[:8]}.pdf", console_api.brief_pdf(brief["en"]["jssd"]), "application/pdf"); return
            self._send(404, b"not found", "text/plain")

        # ---- writes (operator actions, token-guarded) --------------------------------------
        def _post(self, path: str) -> None:
            if self.headers.get("X-RAKSHA-Token") != tok:
                self._json(403, {"error": "missing or wrong session token"}); return
            if not path.startswith("/api/action/"):
                self._send(404, b"not found", "text/plain"); return
            action = path.rsplit("/", 1)[-1]
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, TypeError):
                self._json(400, {"error": "bad JSON body"}); return
            if action in _JOBS:
                res = _JOBS[action](session, body)
                self._json(200 if res.get("ok") else 400, res); return
            fid = body.get("finding", "")
            actor = body.get("actor") or "operator"
            reason = body.get("reason")
            fns = {
                "approve": lambda: session.approve(fid, actor=actor, reason=reason),
                "reject": lambda: session.reject(fid, actor=actor, reason=reason or ""),
                "false_positive": lambda: session.mark_false_positive(fid, actor=actor, reason=reason or ""),
                "rerun_red_team": lambda: session.rerun_red_team(fid, actor=actor),
                "export": lambda: session.export_bundle(fid, actor=actor),
                "advisory": lambda: session.issue_advisory(fid, actor=actor),
            }
            fn = fns.get(action)
            if fn is None:
                self._json(404, {"error": f"unknown action {action!r}"}); return
            res = fn()
            self._json(200 if res.get("ok") else 400, res)

    return Handler


_SAYSNO_BUSY = threading.Lock()


def _saysno(session, body: dict) -> dict:
    """J1: run the "it says no" beat in a worker; the console narrates it from the event stream."""
    if not _SAYSNO_BUSY.acquire(blocking=False):
        return {"ok": False, "error": "the beat is already running"}

    def work():
        try:
            from raksha import saysno
            saysno.run(session)
        finally:
            _SAYSNO_BUSY.release()
    session.saysno = {"running": True, "beats": []}
    threading.Thread(target=work, daemon=True, name="raksha-saysno").start()
    return {"ok": True, "started": True}


def _intake(session, body: dict) -> dict:
    """J2: accept a judge's media path; ingestion runs in the intake worker."""
    path = body.get("path") or ""
    return session.intake().submit(path, name=body.get("name") or None, deep=bool(body.get("deep")))


def _egress_reset(session, body: dict) -> dict:
    """J6: zero the egress counter at the start of the air-gap beat."""
    from raksha.airgap import egress_counter
    session.emit("egress_reset", actor=body.get("actor") or "operator")
    return {"ok": True, "egress": egress_counter(reset=True)}


def _projects_get(session, path: str, q: dict):
    """K5/K12/K14/K25 and the learning dashboard (K10): read-only views of the project store."""
    from raksha import reports, views
    from raksha.learning import Learning
    st = session.store()
    if path == "/api/projects":
        rows = []
        for p in st.all():
            b = views.latest(st, p.id)
            if b is None:
                continue
            rows.append({"id": p.id, "name": p.name, "tier": p.tier, "owner_unit": p.owner_unit,
                         "version": b["version"], "created": b["created"], "score": b["score"]["score"],
                         "counts": b["counts"], "needs_human": len(b["needs_human"]),
                         "diff": {k: len(v) for k, v in b["diff"].items()}})
        return {"projects": rows}
    if path == "/api/mission":
        return {"mission": views.mission_view(st)}
    if path == "/api/heatmap":
        return {"heatmap": views.heatmap(st)}
    if path == "/api/learning":
        L = Learning(st)
        return {"health": L.health(), "analytics": L.analytics()}
    parts = path.strip("/").split("/")          # api project <pid> [v <n> | summary <n> | role <r>]
    if len(parts) < 3:
        return {"error": "not found"}
    pid = unquote(parts[2])
    vs = reports.versions(st, pid)
    if not vs:
        return {"error": "no report for this project"}
    if len(parts) == 3:
        ok, problems = reports.verify_chain(st, pid)
        return {"project": pid, "versions": vs, "chain_verified": ok, "chain_problems": problems,
                "latest": reports.load(st, pid, vs[-1])}
    if parts[3] == "v" and len(parts) == 5:
        return reports.load(st, pid, int(parts[4]))
    if parts[3] == "summary" and len(parts) == 5:
        return (reports.summary_html(reports.load(st, pid, int(parts[4])), lang=q.get("lang", ["en"])[0]), 200)
    if parts[3] == "role" and len(parts) == 5:
        return views.role_view(st, pid, parts[4])
    if parts[3] == "fixes":
        return {"fixes": views.kb_search(st, q.get("q", [""])[0])}
    return {"error": "not found"}


def _mark_done(session, body: dict) -> dict:
    """K4: a person marks a needs-human item done; the next run re-checks it."""
    pid, key = body.get("project") or "", body.get("key") or ""
    if not pid or not key:
        return {"ok": False, "error": "project and key are required"}
    m = session.store().mark_done(pid, key, actor=body.get("actor") or "operator", note=body.get("note") or "")
    session.emit("project_mark_done", project=pid, actor=m["actor"])
    return {"ok": True, "mark": m, "note": "re-checked on the next run, not taken on trust"}


def _certificate(session, body: dict) -> dict:
    from raksha import reports
    res = reports.issue_certificate(session.store(), body.get("project") or "")
    session.emit("certificate_requested", project=body.get("project"), issued=res.get("ok"))
    return res


def _guideline(session, body: dict) -> dict:
    from raksha.learning import Learning
    L = Learning(session.store())
    if body.get("propose"):
        return {"ok": True, "guidelines": L.propose_guidelines()}
    return L.decide_guideline(body.get("id") or "", approver=body.get("actor") or "",
                              approve=bool(body.get("approve")))


def _lesson_rollback(session, body: dict) -> dict:
    from raksha.learning import Learning
    L = Learning(session.store())
    if (body.get("id") or "") not in L.state["lessons"]:
        return {"ok": False, "error": "no such lesson"}
    return {"ok": True, "lesson": L.rollback(body["id"], actor=body.get("actor") or "operator",
                                             note=body.get("reason") or "")}


_JOBS = {"saysno": _saysno, "intake": _intake, "egress_reset": _egress_reset,
         "mark_done": _mark_done, "certificate": _certificate, "guideline": _guideline,
         "lesson_rollback": _lesson_rollback}


def _id(path: str) -> str:
    return unquote(path.rsplit("/", 1)[-1])


def serve(session, *, port: int = 8080, host: str = "127.0.0.1") -> int:
    handler = make_handler(session)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    print(f"RAKSHA console on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0
