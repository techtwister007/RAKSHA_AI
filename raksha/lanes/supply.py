"""Supply-chain lane — vulnerable dependencies, in every ecosystem, with no build.

This is the lane that makes "all languages" and "findings fast" true at once. It parses dependency
manifests (Maven, npm, PyPI, Go), matches each pinned version against the offline vuln DB, and emits
a CONFIRMED finding for every hit. The confirmation is a deterministic match, not an exploit, and
the record says so (`kind="deterministic-match"`), so precision stays honest: the finding is real
and replayable (re-run the match), we simply do not claim an exploit we do not have.

No build, no network, no language runtime — just reading files. On an unknown target this produces
proven findings within seconds, which is the opening move when speed is scored.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..finding import DETERMINISTIC_MATCH, Finding, Frame, Reproducer, ReplayResult, utcnow
from . import vulndb
from .version import in_range

_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    package: str
    version: str
    manifest: str          # path, relative to the scanned root
    line: int | None = None


# ---------------------------------------------------------------- manifest parsers

def parse_maven(text: str, path: str) -> list[Dependency]:
    props = dict(re.findall(r"<([\w.\-]+)>([^<]+)</\1>", text))
    deps: list[Dependency] = []
    for m in re.finditer(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*"
        r"<version>([^<]+)</version>", text, re.S):
        gid, aid, ver = (x.strip() for x in m.groups())
        if ver.startswith("${") and ver.endswith("}"):
            ver = props.get(ver[2:-1], ver)
        line = text[: m.start()].count("\n") + 1
        deps.append(Dependency("Maven", f"{gid}:{aid}", ver, path, line))
    return deps


def parse_requirements(text: str, path: str) -> list[Dependency]:
    deps = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)", line)
        if m:
            deps.append(Dependency("PyPI", m.group(1).lower().replace("_", "-"), m.group(2), path, i))
    return deps


def parse_package_lock(text: str, path: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    # npm lockfile v2/v3: "packages": {"node_modules/x": {"version": ...}}
    for key, meta in (data.get("packages") or {}).items():
        if key.startswith("node_modules/") and isinstance(meta, dict) and "version" in meta:
            deps.append(Dependency("npm", key.split("node_modules/")[-1], meta["version"], path))
    # lockfile v1: "dependencies": {"x": {"version": ...}}
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and "version" in meta:
            deps.append(Dependency("npm", name, meta["version"], path))
    return deps


def parse_go_mod(text: str, path: str) -> list[Dependency]:
    deps = []
    for i, raw in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*([\w./\-]+)\s+v([0-9][\w.\-+]*)", raw)
        if m and m.group(1) != "go":
            deps.append(Dependency("Go", m.group(1), m.group(2), path, i))
    return deps


_PARSERS = {
    "pom.xml": parse_maven,
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
}


def parse_manifest(name: str, text: str, path: str) -> list[Dependency]:
    fn = _PARSERS.get(name)
    return fn(text, path) if fn else []


# ---------------------------------------------------------------- the lane

def scan_dependencies(deps: list[Dependency], db: vulndb.VulnDB | None = None) -> list[Finding]:
    """Match each dependency against the vuln DB; return CONFIRMED findings for every hit."""
    db = db or vulndb.load()
    findings: list[Finding] = []
    for dep in deps:
        for adv in db.for_package(dep.ecosystem, dep.package):
            if not in_range(dep.version, adv["introduced"], adv.get("fixed")):
                continue
            findings.append(_finding(dep, adv))
    return findings


def _finding(dep: Dependency, adv: dict) -> Finding:
    fixed = adv.get("fixed")
    detail = (f"{dep.package}@{dep.version} vulnerable per {adv['id']}"
              + (f"/{adv['aka']}" if adv.get('aka') else "")
              + (f"; fixed in {fixed}" if fixed else "; no fixed version"))
    f = Finding(
        oracle="osv:version-match",
        bug_class=adv.get("cwe", "CWE-1104"),
        language=_LANG.get(dep.ecosystem, dep.ecosystem.lower()),
        target=dep.manifest,
        message=f"Vulnerable dependency: {detail}. {adv.get('summary', '')}".strip(),
        severity=_SEVERITY.get(adv.get("severity", "medium"), "medium"),
        frames=[Frame(symbol=dep.package, uri=dep.manifest, line=dep.line)],
    )
    from ..finding import FixSite
    f.add_fix_site(FixSite(uri=dep.manifest, rank=0, start_line=dep.line, symbol=dep.package,
                           rationale=f"bump {dep.package} to {fixed}" if fixed else "no fixed version available"))
    # Deterministic-match evidence: the version is, verifiably, in the vulnerable range.
    repro = Reproducer.from_bytes(
        f"{dep.ecosystem} {dep.package} {dep.version} :: {adv['id']}".encode(),
        ["raksha", "match", dep.ecosystem, dep.package, dep.version, "--advisory", adv["id"]],
        artifact_path=dep.manifest, minimised=True, kind=DETERMINISTIC_MATCH, detail=detail,
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=adv["id"], exit_code=0))
    f.confirm(reason="dependency version deterministically matches the advisory's vulnerable range")
    return f


_LANG = {"Maven": "java", "npm": "javascript", "PyPI": "python", "Go": "go"}
