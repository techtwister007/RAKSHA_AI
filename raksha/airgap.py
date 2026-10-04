"""The air-gap guard — proves the no-egress claim mechanically.

Two badges never change at the finale: NETWORK INTERFACES: 0 and CLOUD CALLS: 0. A claim like that
has to be enforced, not promised. This module scans every shipped source tree (raksha/, console/,
deploy/) and reports violations:

  - any egress-capable client import (`requests`, `httpx`, `socket`, `urllib.request`,
    `http.client`, `ftplib`, `smtplib`, the model SDKs, ...) OUTSIDE the one allowlisted module,
    `raksha/inference.py`. Server modules (`http.server`, `socketserver`) are not egress and are
    allowed — the console binds a local port;
  - shelling out to a network tool (`curl`, `wget`, `scp`, ...) via subprocess;
  - any external asset reference in shipped HTML — an http(s):// or protocol-relative src/href, a
    CSS `@import`, or a `fetch`/XHR to an absolute URL. A page that phones out contradicts the pitch.

Run as a test (see tests/test_airgap.py) so a regression fails CI, and runnable directly
(`python -m raksha.airgap`) as the check you run before building the bundle.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PKG = Path(__file__).parent
REPO = PKG.parent

#: Only this module may perform network I/O.
_ALLOWLISTED = {PKG / "inference.py"}

#: Python trees that ship and so must be egress-free (all but the one allowlisted module).
_SCAN_DIRS = (PKG, REPO / "console", REPO / "deploy")

#: Egress-capable CLIENT imports that must not appear outside inference.py. Deliberately excludes
#: server modules (http.server, socketserver): binding a local port is not egress, and the console
#: serves on one. Covers the HTTP/FTP/mail/RPC clients and raw sockets an exfiltration path needs.
_NET_MODULES = (
    "requests", "httpx", "aiohttp", "socket", "ssl", "urllib.request", "urllib.error",
    "http.client", "ftplib", "smtplib", "telnetlib", "poplib", "imaplib", "nntplib",
    "xmlrpc.client", "webbrowser", "openai", "anthropic",
)
_NET_IMPORT = re.compile(
    r"^\s*(?:import\s+(?:" + "|".join(re.escape(m) for m in _NET_MODULES) + r")"
    r"|from\s+(?:" + "|".join(re.escape(m) for m in (*_NET_MODULES, "urllib")) + r")\s+import)",
    re.MULTILINE,
)

#: Shelling out to a network tool is egress too, even without a net import. Matched only at a real
#: call site (subprocess/os.system/Popen with a network tool in the command), never in prose.
_SHELL_CALL = re.compile(r"(?:subprocess\.\w+|os\.system|os\.popen|check_output|Popen)\s*\(")
_SHELL_TOOL = re.compile(r"\b(?:curl|wget|ncat|netcat|scp|sftp|rsync|telnet)\b")

#: External resources in HTML: src/href http(s), protocol-relative //host, CSS @import url(),
#: and a fetch/XHR to an absolute URL. Relative /api calls (the console's own) are not matched.
_EXTERNAL_URL = re.compile(
    r"""(?:(?:src|href)\s*=\s*["']\s*(?:https?:)?//"""          # src/href to http(s) or //host
    r"""|@import\s+(?:url\()?["']?\s*(?:https?:)?//"""          # CSS @import
    r"""|(?:fetch|XMLHttpRequest|open)\s*\(\s*["']\s*https?://)""",  # JS fetch/XHR to absolute URL
    re.IGNORECASE,
)


@dataclass
class Violation:
    file: str
    line: int
    kind: str
    text: str


@dataclass
class AirgapReport:
    violations: list[Violation] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        if self.clean:
            return "air-gap clean: no network imports outside inference.py, no external assets in shipped HTML"
        return "\n".join(f"  {v.file}:{v.line}  [{v.kind}]  {v.text.strip()[:90]}" for v in self.violations)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO))
    except ValueError:
        return str(p)


def check_python(dirs: tuple[Path, ...] | Path = _SCAN_DIRS) -> list[Violation]:
    out: list[Violation] = []
    seen: set[Path] = set()
    if isinstance(dirs, Path):
        dirs = (dirs,)
    for base in dirs:
        if not base.exists():
            continue
        for py in sorted(base.rglob("*.py")):
            if py in _ALLOWLISTED or py in seen or "__pycache__" in py.parts:
                continue
            seen.add(py)
            for i, line in enumerate(py.read_text(errors="replace").splitlines(), 1):
                if _NET_IMPORT.match(line):
                    out.append(Violation(_rel(py), i, "network-import", line))
                elif _SHELL_CALL.search(line) and _SHELL_TOOL.search(line):
                    out.append(Violation(_rel(py), i, "shell-egress", line))
    return out


def check_shipped_html(dirs: list[Path] | None = None) -> list[Violation]:
    """Shipped HTML (the console) must reference no external origin at all."""
    out: list[Violation] = []
    search = dirs if dirs is not None else [REPO / "console"]
    for base in search:
        if not base.exists():
            continue
        for html in sorted(base.rglob("*.html")):
            for i, line in enumerate(html.read_text(errors="replace").splitlines(), 1):
                if _EXTERNAL_URL.search(line):
                    out.append(Violation(_rel(html), i, "external-asset", line))
    return out


def audit(dirs: tuple[Path, ...] = _SCAN_DIRS, html_dirs: list[Path] | None = None) -> AirgapReport:
    return AirgapReport(violations=check_python(dirs) + check_shipped_html(html_dirs))


if __name__ == "__main__":
    report = audit()
    print(report.summary())
    sys.exit(0 if report.clean else 1)
