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
from . import crypto, githistory, iac, kev, secrets, service, supply, transitive, vulndb

#: Files worth reading for secrets. Covers every language with source here (C/C++, Rust, C#,
#: Kotlin, Scala, Swift included, not only the three with deep adapters), config, and the files
#: that most often hold key material. "Secrets in any file" must mean any file.
_SECRET_EXT = {
    # source
    ".java", ".kt", ".scala", ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".cs", ".swift", ".m", ".pl", ".lua", ".groovy",
    # config / text
    ".xml", ".yaml", ".yml", ".json", ".properties", ".env", ".cfg", ".ini", ".conf", ".txt",
    ".sh", ".bash", ".zsh", ".ps1", ".tf", ".tfvars", ".toml", ".md",
    # key material
    ".pem", ".key", ".crt", ".p12", ".pfx", ".keystore", ".jks", ".ovpn",
}
#: Secret-bearing files identified by exact name rather than extension (often extensionless).
_SECRET_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc",
    ".git-credentials", ".htpasswd", "credentials", "Dockerfile", ".dockercfg",
}
_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}
_MAX_FILE_BYTES = 2_000_000


@dataclass
class BuildFreeResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    manifests_found: int = 0
    seconds: float = 0.0
    #: Cryptographic primitives in use (not findings) for the post-quantum migration plan.
    crypto_uses: list = field(default_factory=list)
    unpinned: list = field(default_factory=list)   # C2: open-range deps (exposure of unknown status)

    def by_lane(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            lane = f.oracle.split(":", 1)[0]
            out[lane] = out.get(lane, 0) + 1
        return out


def scan_target(root: str | Path, *, db: vulndb.VulnDB | None = None, secrets_on: bool = True,
                crypto_on: bool = True) -> BuildFreeResult:
    root = Path(root)
    db = db or vulndb.load()
    started = time.monotonic()
    deps: list[supply.Dependency] = []
    findings: list[Finding] = []
    crypto_uses: list = []
    unpinned: list = []
    imports = supply.ImportIndex()
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
            unpinned.extend(supply.unpinned_in_manifest(name, text, rel))
        imports.add(path, text)
        if secrets_on and (path.suffix in _SECRET_EXT or name in _SECRET_NAMES):
            findings.extend(secrets.scan_text(text, rel))
        if crypto_on and (path.suffix in _SECRET_EXT or name in _SECRET_NAMES):
            findings.extend(crypto.scan_text(text, rel))
            crypto_uses.extend(crypto.inventory(text, rel))
        if _looks_like_openapi(name, text):
            findings.extend(service.scan_openapi(text, rel))

    dep_findings = supply.scan_dependencies(deps, db)
    # Transitive hits (C1): the full tree, where a lockfile or an offline tree tool is available.
    # Deduped against the direct deps by the shared DETERMINISTIC_MATCH location key.
    try:
        dep_findings.extend(transitive.scan_transitive(root, db=db))
    except Exception:  # noqa: BLE001 — a tree we cannot resolve is not a crash
        pass
    supply.annotate_reachability(dep_findings, imports)   # present is not reached; say which
    try:
        kev.annotate_exploit_intel(dep_findings, db=db)   # C6: known-exploited + EPSS metadata
    except Exception:  # noqa: BLE001
        pass
    findings.extend(dep_findings)
    # Config / IaC hardening (C8) and secrets in git history (C3) — each returns [] with no error
    # when its prerequisite (a Dockerfile/manifest, a git repo) is absent.
    try:
        findings.extend(iac.scan_iac(root))
    except Exception:  # noqa: BLE001
        pass
    try:
        findings.extend(githistory.scan_git_history(root))
    except Exception:  # noqa: BLE001
        pass
    pinned_pkgs = {d.package for d in deps}
    unpinned = [u for u in unpinned if u["package"] not in pinned_pkgs]
    findings = dedup(findings)
    return BuildFreeResult(findings=findings, files_scanned=files, manifests_found=manifests,
                           seconds=round(time.monotonic() - started, 3), crypto_uses=crypto_uses,
                           unpinned=unpinned)


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
