"""The air-gap guard — proves the no-egress claim mechanically.

Two badges never change at the finale: NETWORK INTERFACES: 0 and CLOUD CALLS: 0. A claim like that
has to be enforced, not promised. This module scans the source tree and reports violations:

  - any network-capable import (`requests`, `httpx`, `socket`, `urllib.request`, the model SDKs)
    OUTSIDE the one allowlisted module, `raksha/inference.py`;
  - any external asset reference (http(s):// URL, CDN link, remote <script>/<link>) in the console
    or any shipped HTML — a page that phones out would contradict the whole pitch.

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

#: Network-capable imports that must not appear elsewhere in the package.
_NET_IMPORT = re.compile(
    r"^\s*(?:import\s+(requests|httpx|aiohttp|socket|urllib\.request|openai|anthropic)"
    r"|from\s+(requests|httpx|aiohttp|socket|urllib\.request|urllib|openai|anthropic)\s+import"
    r"|import\s+urllib\.request)",
    re.MULTILINE,
)

#: External resources in HTML. Google Fonts is allowed ONLY in scratch/preview artifacts, never in
#: the shipped console, so the console check forbids every external origin.
_EXTERNAL_URL = re.compile(r"""(?:src|href)\s*=\s*["']https?://[^"']+""", re.IGNORECASE)


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


def check_python(pkg: Path = PKG) -> list[Violation]:
    out: list[Violation] = []
    for py in sorted(pkg.rglob("*.py")):
        if py in _ALLOWLISTED:
            continue
        for i, line in enumerate(py.read_text(errors="replace").splitlines(), 1):
            if _NET_IMPORT.match(line):
                out.append(Violation(_rel(py), i, "network-import", line))
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


def audit(pkg: Path = PKG, html_dirs: list[Path] | None = None) -> AirgapReport:
    return AirgapReport(violations=check_python(pkg) + check_shipped_html(html_dirs))


if __name__ == "__main__":
    report = audit()
    print(report.summary())
    sys.exit(0 if report.clean else 1)
