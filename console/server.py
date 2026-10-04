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
  /api/help                  keyboard shortcuts (F12)
  /api/export/findings.csv   | findings.xlsx | brief/<id>.pdf   (F12)

Write routes (POST, operator actions — F7), each requiring the session token in X-RAKSHA-Token:
  /api/action/approve|reject|false_positive|rerun_red_team|export   {finding, actor, reason}

The token is minted per process, injected into the served page, and required on every POST, so a
stray local page cannot drive operator actions. `serve(session, port)` blocks; `make_handler` returns
a handler class for tests (its token is on the class as TOKEN).
"""

from __future__ import annotations

import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote
from pathlib import Path

CONSOLE_DIR = Path(__file__).parent
INDEX = CONSOLE_DIR / "index.html"


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
            if path == "/api/snapshot":
                self._json(200, session.snapshot()); return
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
            fid = body.get("finding", "")
            actor = body.get("actor") or "operator"
            reason = body.get("reason")
            fns = {
                "approve": lambda: session.approve(fid, actor=actor, reason=reason),
                "reject": lambda: session.reject(fid, actor=actor, reason=reason or ""),
                "false_positive": lambda: session.mark_false_positive(fid, actor=actor, reason=reason or ""),
                "rerun_red_team": lambda: session.rerun_red_team(fid, actor=actor),
                "export": lambda: session.export_bundle(fid, actor=actor),
            }
            fn = fns.get(action)
            if fn is None:
                self._json(404, {"error": f"unknown action {action!r}"}); return
            res = fn()
            self._json(200 if res.get("ok") else 400, res)

    return Handler


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
