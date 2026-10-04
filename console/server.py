"""The console web server — stdlib only, served entirely offline.

No framework, no third-party dependency, no external asset: a console that phoned out would
contradict the whole air-gap pitch, so it is served from one self-contained HTML file and a tiny
JSON API over Python's own http.server. The air-gap guard checks this directory ships nothing
external.

Routes:
  GET /                      the console (console/index.html)
  GET /api/snapshot          board + findings + scorecard, as one JSON document
  GET /api/finding/<id>      one finding's full proof block

`serve(session, port)` blocks; `make_handler(session)` returns a handler class for tests.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from pathlib import Path

CONSOLE_DIR = Path(__file__).parent
INDEX = CONSOLE_DIR / "index.html"


def make_handler(session):
    class Handler(BaseHTTPRequestHandler):
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

        def do_GET(self):  # noqa: N802 (http.server API)
            # A failure while building a response is a 500 the console can show — never a dropped
            # connection that looks like the system died.
            try:
                self._route(urlsplit(self.path).path)
            except Exception as e:  # noqa: BLE001
                self._json(500, {"error": f"{type(e).__name__}: {e}"})

        def _route(self, path: str) -> None:
            if path in ("/", "/index.html"):
                if INDEX.exists():
                    self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
                else:
                    self._send(500, b"console/index.html missing", "text/plain")
                return
            if path == "/api/snapshot":
                self._json(200, session.snapshot())
                return
            if path.startswith("/api/finding/"):
                detail = session.finding_detail(path.rsplit("/", 1)[-1])
                self._json(200, detail) if detail else self._json(404, {"error": "not found"})
                return
            if path.startswith("/api/brief/"):
                brief = session.commanders_brief(path.rsplit("/", 1)[-1])
                self._json(200, brief) if brief else self._json(404, {"error": "not found"})
                return
            if path.startswith("/api/verify/"):
                res = session.verify_bundle(path.rsplit("/", 1)[-1])
                self._json(200, res) if res else self._json(404, {"error": "not found"})
                return
            self._send(404, b"not found", "text/plain")

    return Handler


def serve(session, *, port: int = 8080, host: str = "127.0.0.1") -> int:
    httpd = ThreadingHTTPServer((host, port), make_handler(session))
    httpd.daemon_threads = True
    print(f"RAKSHA console on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0
