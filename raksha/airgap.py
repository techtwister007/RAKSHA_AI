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

import ast
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
_NET_SET = frozenset(_NET_MODULES)
_SHELL_FUNCS = frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call",
                          "subprocess.check_output", "subprocess.Popen", "os.system", "os.popen",
                          "run", "call", "check_call", "check_output", "Popen", "system", "popen"})
#: Shelling out to a network tool is egress too, even without a net import.
_SHELL_TOOL = re.compile(r"\b(?:curl|wget|ncat|netcat|scp|sftp|rsync|telnet)\b")


def _is_net_module(name: str) -> bool:
    """`socket` and `socket.x` are network modules; `socketserver` is not (exact path components)."""
    parts = name.split(".")
    return any(".".join(parts[:i]) in _NET_SET for i in range(1, len(parts) + 1))


def _call_name(node) -> str:
    f = node.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return f"{f.value.id}.{f.attr}"
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _scan_source(text: str):
    """Yield (line, kind, snippet) for every egress path in one Python file, found by parsing it:
    imports in any form (aliases, comma lists, `from http import client`), dynamic imports of a
    network module, and calls that shell out to a network tool — across lines, ignoring comments."""
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_net_module(alias.name):
                    yield node.lineno, "network-import", f"import {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            if _is_net_module(node.module):
                yield node.lineno, "network-import", f"from {node.module} import ..."
            else:
                for alias in node.names:
                    if _is_net_module(f"{node.module}.{alias.name}"):
                        yield node.lineno, "network-import", f"from {node.module} import {alias.name}"
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            consts = [a.value for a in ast.walk(node) if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if name in ("__import__", "importlib.import_module", "import_module"):
                if any(_is_net_module(c) for c in consts[:1]):
                    yield node.lineno, "network-import", f"{name}({consts[0]!r})"
            elif name in _SHELL_FUNCS and any(_SHELL_TOOL.search(c) for c in consts):
                yield node.lineno, "shell-egress", f"{name}(... network tool ...)"


#: External resources in HTML: src/href http(s), protocol-relative //host, CSS @import url(),
#: and a fetch/XHR to an absolute URL. Relative /api calls (the console's own) are not matched.
_EXTERNAL_URL = re.compile(
    r"""(?:\b(?:src|href|action|poster|data|srcset)\s*=\s*["']?\s*(?:https?:)?//"""  # attributes, quoted or not
    r"""|\burl\(\s*["']?\s*(?:https?:)?//"""                     # CSS url(), incl. @import url()
    r"""|@import\s+["']\s*(?:https?:)?//"""                       # CSS @import "..."
    r"""|\b(?:fetch|open|EventSource|WebSocket|sendBeacon)\s*\([^)]*["'`]\s*(?:https?|wss?):)""",  # JS calls
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
            text = py.read_text(errors="replace")
            try:
                hits = list(_scan_source(text))
            except SyntaxError as e:
                # a file the guard cannot read is a file it cannot vouch for
                out.append(Violation(_rel(py), e.lineno or 0, "unparseable", str(e)))
                continue
            out.extend(Violation(_rel(py), line, kind, snippet) for line, kind, snippet in hits)
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


# ---- J6: the live egress counter the air-gap beat shows ---------------------------------------
_EGRESS_BASE: dict | None = None


def _read_netdev(path: str = "/proc/net/dev") -> dict[str, tuple[int, int]]:
    """{interface: (tx_bytes, tx_packets)} from the kernel's own counters (Linux)."""
    out: dict[str, tuple[int, int]] = {}
    try:
        lines = Path(path).read_text().splitlines()[2:]
    except OSError:
        return out
    for ln in lines:
        if ":" not in ln:
            continue
        name, rest = ln.split(":", 1)
        cols = rest.split()
        if len(cols) >= 10:
            out[name.strip()] = (int(cols[8]), int(cols[9]))
    return out


def _link(name: str, sys_net: str = "/sys/class/net") -> dict:
    def rd(f):
        try:
            return (Path(sys_net) / name / f).read_text().strip()
        except OSError:
            return None
    carrier = rd("carrier")
    return {"operstate": rd("operstate"), "carrier": None if carrier is None else carrier == "1"}


def egress_counter(*, reset: bool = False, netdev: str = "/proc/net/dev",
                   sys_net: str = "/sys/class/net") -> dict:
    """Transmit counters on every non-loopback interface, as a delta since the first reading (or
    the last `reset`), plus RAKSHA's own counted egress calls.

    This is the kernel's count, not RAKSHA's: it moves for ANY traffic the host sends (ARP, DHCP,
    router solicitations included) while a link is up. With the cable pulled the carrier drops and
    the delta stays flat — that is the beat. `available` is False off Linux, and nothing is claimed.
    """
    global _EGRESS_BASE
    now = {k: v for k, v in _read_netdev(netdev).items() if k != "lo"}
    if _EGRESS_BASE is None or reset:
        _EGRESS_BASE = dict(now)
    ifaces = []
    for name, (tb, tp) in sorted(now.items()):
        b0, p0 = _EGRESS_BASE.get(name, (tb, tp))
        ifaces.append({"name": name, **_link(name, sys_net), "tx_bytes_delta": tb - b0,
                       "tx_packets_delta": tp - p0})
    try:
        from .metrics import live_counters
        calls = live_counters().get("egress_calls", 0)
    except Exception:  # noqa: BLE001
        calls = None
    return {"available": bool(now) or Path(netdev).exists(), "interfaces": ifaces,
            "links_up": sum(1 for i in ifaces if i["carrier"]),
            "tx_packets_delta": sum(i["tx_packets_delta"] for i in ifaces),
            "tx_bytes_delta": sum(i["tx_bytes_delta"] for i in ifaces),
            "raksha_egress_calls": calls}
