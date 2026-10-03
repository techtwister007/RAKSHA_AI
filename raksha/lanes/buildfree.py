"""The build-free runner — ingest a target directory, produce proven findings, no build.

Walks a target, runs the build-free lanes (supply chain, secrets) on the files that match, dedups,
and returns CONFIRMED findings. This is the opening move on any target: it needs no build, no
language runtime and no network, so it produces proven findings within seconds — including on a
target in a language we never wrote an adapter for, because a dependency CVE and a hardcoded secret
are language-agnostic.

This is the capability the dossier calls the single choice that turns 36% into 85%: when the build
fails, this lane still delivers real, proven findings.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ..finding import Finding, dedup
from . import secrets, service, supply, vulndb

#: Files worth reading for secrets. Skips binaries and the usual noise directories.
_SECRET_EXT = {".java", ".py", ".js", ".ts", ".go", ".rb", ".php", ".xml", ".yaml", ".yml",
               ".json", ".properties", ".env", ".cfg", ".ini", ".conf", ".txt", ".sh", ".tf", ".toml"}
_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}
_MAX_FILE_BYTES = 2_000_000


@dataclass
class BuildFreeResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    manifests_found: int = 0
    seconds: float = 0.0

    def by_lane(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            lane = f.oracle.split(":", 1)[0]
            out[lane] = out.get(lane, 0) + 1
        return out


def scan_target(root: str | Path, *, db: vulndb.VulnDB | None = None, secrets_on: bool = True) -> BuildFreeResult:
    root = Path(root)
    db = db or vulndb.load()
    started = time.monotonic()
    deps: list[supply.Dependency] = []
    findings: list[Finding] = []
    files = manifests = 0

    for path in _walk(root):
        rel = str(path.relative_to(root))
        name = path.name
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        files += 1
        if name in supply._PARSERS:
            manifests += 1
            deps.extend(supply.parse_manifest(name, text, rel))
        if secrets_on and path.suffix in _SECRET_EXT:
            findings.extend(secrets.scan_text(text, rel))
        if _looks_like_openapi(name, text):
            findings.extend(service.scan_openapi(text, rel))

    findings.extend(supply.scan_dependencies(deps, db))
    findings = dedup(findings)
    return BuildFreeResult(findings=findings, files_scanned=files, manifests_found=manifests,
                           seconds=round(time.monotonic() - started, 3))


def _looks_like_openapi(name: str, text: str) -> bool:
    n = name.lower()
    if not (n.endswith(".json") and ("openapi" in n or "swagger" in n or "api" in n)):
        return False
    return '"openapi"' in text or '"swagger"' in text


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
            yield path
