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
from pathlib import Path
from dataclasses import dataclass

from ..finding import DETERMINISTIC_MATCH, Finding, Frame, Reproducer, ReplayResult, utcnow
from . import vulndb

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
    """Every <dependency> block with a groupId, artifactId and version, in any tag order.

    A version inherited from a parent POM / BOM / dependencyManagement is not in the block and so
    cannot be matched deterministically from this file alone; such dependencies are skipped rather
    than guessed.
    """
    props = dict(re.findall(r"<([\w.\-]+)>([^<]+)</\1>", text))
    deps: list[Dependency] = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        block = m.group(1)
        tags = {t: v.strip() for t, v in re.findall(r"<(groupId|artifactId|version)>([^<]+)</\1>", block)}
        if not {"groupId", "artifactId", "version"} <= tags.keys():
            continue
        ver = tags["version"]
        if ver.startswith("${") and ver.endswith("}"):
            ver = props.get(ver[2:-1], ver)
        if ver.startswith("${"):
            continue                                  # unresolved property: unknown version
        line = text[: m.start()].count("\n") + 1
        deps.append(Dependency("Maven", f"{tags['groupId']}:{tags['artifactId']}", ver, path, line))
    return deps


def _norm_pypi(name: str) -> str:
    return vulndb.normalise_package("PyPI", name)


#: An exact version pin with no range operator ("4.17.20", "=4.17.20", "v1.2.3", "1.0.0-rc.1").
_EXACT = re.compile(r"^\s*(?:={1,3}\s*)?v?(\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.\-+]*)?)\s*$")


def exact_pin(spec: str | None) -> str | None:
    """The version if `spec` pins exactly one version, else None.

    Only an exact pin is evidence of what is installed. A range ("^4.17.20", ">=2.25.1") says what
    is *allowed*; a resolver may well install a fixed version, so matching its lower bound would
    report a CONFIRMED finding on a dependency that is not vulnerable. Ranges are left to the
    lockfile, which records what was actually resolved.
    """
    if not isinstance(spec, str):
        return None
    m = _EXACT.match(spec)
    return m.group(1) if m else None


def parse_requirements(text: str, path: str) -> list[Dependency]:
    deps = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        # name, optional [extras], then an exact == / === pin (the only form a version can be read from)
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9_.\-+!]+)\s*$", line)
        if m:
            deps.append(Dependency("PyPI", _norm_pypi(m.group(1)), m.group(2), path, i))
    return deps


def _toml_sections(text: str):
    """Yield (section header, line number, line) for every line of a TOML file."""
    section = ""
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if s.startswith("[") and not s.startswith("[["):
            section = s.strip("[]").strip()
        yield section, i, raw


def parse_pyproject(text: str, path: str) -> list[Dependency]:
    """Exact pins from the runtime dependency tables of a pyproject.toml.

    PEP 621: the `dependencies = [...]` array of [project] only — not [build-system] requires, not
    optional extras (not installed by default). Poetry: [tool.poetry.dependencies], where a bare
    version string is an exact pin. Regex-parsed to stay dependency-free.
    """
    deps: list[Dependency] = []
    in_array = False
    for section, i, raw in _toml_sections(text):
        s = raw.split("#", 1)[0]
        if section == "project":
            opening = re.match(r"^\s*dependencies\s*=\s*\[", s)
            if opening:
                in_array = True
            if in_array:
                for name, ver in re.findall(
                        r"""["']\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][\w.\-+!]*)\s*(?:;[^"']*)?["']""", s):
                    deps.append(Dependency("PyPI", _norm_pypi(name), ver, path, i))
                # the array closes at a "]" outside any quoted string (extras like pkg[x] are quoted)
                unquoted = re.sub(r"\"[^\"]*\"|'[^']*'", "", s)
                body = unquoted[opening.end():] if opening else unquoted
                if "]" in body:
                    in_array = False
        else:
            in_array = False
        if section == "tool.poetry.dependencies":
            pm = re.match(r"""^\s*([A-Za-z0-9_.\-]+)\s*=\s*["']([^"']+)["']""", s)
            if pm and pm.group(1).lower() != "python":
                ver = exact_pin(pm.group(2))
                if ver:
                    deps.append(Dependency("PyPI", _norm_pypi(pm.group(1)), ver, path, i))
    return deps


def parse_package_json(text: str, path: str) -> list[Dependency]:
    """Exact pins from an npm manifest. Ranges are resolved by the lockfile, not guessed here."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            ver = exact_pin(spec)
            if ver:
                deps.append(Dependency("npm", name, ver, path))
    return deps


def parse_package_lock(text: str, path: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    seen: set[tuple[str, str]] = set()
    deps: list[Dependency] = []
    # npm lockfile v2/v3: "packages": {"node_modules/x": {"version": ...}}
    for key, meta in (data.get("packages") or {}).items():
        if key.startswith("node_modules/") and isinstance(meta, dict) and "version" in meta:
            name = key.split("node_modules/")[-1]
            if (name, meta["version"]) not in seen:
                seen.add((name, meta["version"]))
                deps.append(Dependency("npm", name, meta["version"], path))
    # lockfile v1: "dependencies": {"x": {"version": ...}} (v2 carries both; do not double-count)
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and "version" in meta and (name, meta["version"]) not in seen:
            seen.add((name, meta["version"]))
            deps.append(Dependency("npm", name, meta["version"], path))
    return deps


def parse_go_mod(text: str, path: str) -> list[Dependency]:
    """require directives (single-line and block), with `replace` directives applied.

    A module replaced by another versioned module is reported at the replacement; one replaced by a
    local path has no published version and is skipped. `exclude` blocks are not dependencies.
    """
    required: list[tuple[str, str, int]] = []
    replaced: dict[str, tuple[str, str] | None] = {}
    block = None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
                continue
            directive, body = block, line
        else:
            m = re.match(r"^(require|replace|exclude|retract)\s*(\(?)\s*(.*)$", line)
            if not m:
                continue
            if m.group(2) == "(":
                block = m.group(1)
                continue
            directive, body = m.group(1), m.group(3)
        if directive == "require":
            r = re.match(r"^([\w./\-~]+)\s+v([0-9][\w.\-+]*)", body)
            if r:
                required.append((r.group(1), r.group(2), i))
        elif directive == "replace":
            r = re.match(r"^([\w./\-~]+)(?:\s+v[\w.\-+]+)?\s*=>\s*([^\s]+)(?:\s+v([0-9][\w.\-+]*))?", body)
            if r:
                replaced[r.group(1)] = (r.group(2), r.group(3)) if r.group(3) else None
    deps = []
    for mod, ver, line in required:
        if mod in replaced:
            target = replaced[mod]
            if target is None:
                continue                              # replaced by a local path: no version to match
            mod, ver = target
        deps.append(Dependency("Go", mod, ver, path, line))
    return deps


#: When several manifests in one directory name the same dependency, the most authoritative wins:
#: a lockfile records what was resolved; a manifest only what was asked for.
_MANIFEST_RANK = {"package-lock.json": 0, "go.mod": 0, "pom.xml": 0, "requirements.txt": 1,
                  "pyproject.toml": 2, "package.json": 3}


def prefer_authoritative(deps: list[Dependency]) -> list[Dependency]:
    """Per (ecosystem, package, directory), keep only the most authoritative manifest's entries.

    package.json pinning 4.17.20 beside a lockfile that resolved 4.17.21 must not yield a finding —
    the lockfile is what is installed. A lockfile can legitimately hold several versions of one
    package (nested installs); all of them are kept.
    """
    def key(d: Dependency) -> tuple[str, str, str]:
        directory = d.manifest.rsplit("/", 1)[0] if "/" in d.manifest else ""
        return d.ecosystem, d.package, directory

    def rank(d: Dependency) -> int:
        return _MANIFEST_RANK.get(d.manifest.rsplit("/", 1)[-1], 9)

    best: dict[tuple[str, str, str], int] = {}
    for d in deps:
        best[key(d)] = min(best.get(key(d), 99), rank(d))
    out, seen = [], set()
    for d in deps:
        ident = (*key(d), d.version, d.manifest)
        if rank(d) == best[key(d)] and ident not in seen:
            seen.add(ident)
            out.append(d)
    return out


_PARSERS = {
    "pom.xml": parse_maven,
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
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
    for dep in prefer_authoritative(deps):
        for adv in db.for_package(dep.ecosystem, dep.package):
            hit = vulndb.affected_range(adv, dep.version)
            if hit is None:
                continue
            findings.append(_finding(dep, adv, hit.get("fixed")))
    return findings


def _finding(dep: Dependency, adv: dict, fixed: str | None) -> Finding:
    """`fixed` is the fix on the dependency's own release line (the range that matched)."""
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
        ["raksha", "match", dep.ecosystem, dep.package, dep.version, "--advisory", adv["id"],
         "--manifest", dep.manifest],
        artifact_path=dep.manifest, minimised=True, kind=DETERMINISTIC_MATCH, detail=detail,
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=adv["id"], exit_code=0))
    f.confirm(reason="dependency version deterministically matches the advisory's vulnerable range")
    return f


_LANG = {"Maven": "java", "npm": "javascript", "PyPI": "python", "Go": "go"}


# ---- Reachability: proven present is not proven reached ----------------------------------------

#: Source extensions per ecosystem, and the import statement shapes that name a package.
_IMPORT_EXT = {
    "PyPI": {".py"},
    "npm": {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"},
    "Go": {".go"},
    "Maven": {".java", ".kt", ".scala", ".groovy"},
}
_IMPORT_RE = {
    "PyPI": re.compile(r"^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import)", re.M),
    "npm": re.compile(r"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"]+)['"]""", re.M),
    "Go": re.compile(r'"([A-Za-z0-9_.\-/~]+)"'),
    "Maven": re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M),
}
#: PyPI distributions whose import name differs from the distribution name.
_PY_MODULE = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
              "python-dateutil": "dateutil", "pycryptodome": "Crypto", "msgpack-python": "msgpack",
              "opencv-python": "cv2", "attrs": "attr", "pyjwt": "jwt", "python-jose": "jose"}

REACH_IMPORTED, REACH_NOT_IMPORTED, REACH_UNKNOWN = "imported", "not-imported", "unknown"


class ImportIndex:
    """Import statements seen while walking a target, per ecosystem. Built in the same pass as the
    secrets scan, so reachability costs one regex per source file and no second walk."""

    def __init__(self) -> None:
        self.names: dict[str, set[str]] = {eco: set() for eco in _IMPORT_EXT}
        self.files: dict[str, int] = {eco: 0 for eco in _IMPORT_EXT}

    def add(self, path: Path | str, text: str) -> None:
        suffix = Path(path).suffix
        for eco, exts in _IMPORT_EXT.items():
            if suffix not in exts:
                continue
            self.files[eco] += 1
            if eco == "Go":                        # only the import block / import lines
                body = "\n".join(l for l in text.splitlines() if l.lstrip().startswith(("import", '"', "_ ")))
                self.names[eco].update(_IMPORT_RE[eco].findall(body))
                continue
            for m in _IMPORT_RE[eco].finditer(text):
                self.names[eco].add(next(g for g in m.groups() if g))

    def reaches(self, ecosystem: str, package: str) -> str:
        if ecosystem not in self.names:
            return REACH_UNKNOWN
        if self.files[ecosystem] == 0:
            return REACH_UNKNOWN                   # no source in that language was seen at all
        return REACH_IMPORTED if any(_names_package(ecosystem, package, n) for n in self.names[ecosystem]) \
            else REACH_NOT_IMPORTED


def _names_package(ecosystem: str, package: str, imported: str) -> bool:
    if ecosystem == "PyPI":
        mod = _PY_MODULE.get(_norm_pypi(package), _norm_pypi(package).replace("-", "_"))
        return imported == mod or imported.startswith(mod + ".")
    if ecosystem == "npm":
        return imported == package or imported.startswith(package + "/")
    if ecosystem == "Go":
        return imported == package or imported.startswith(package + "/")
    if ecosystem == "Maven":
        group = package.split(":", 1)[0]
        prefixes = {group, ".".join(group.split(".")[:3])}
        return any(imported == p or imported.startswith(p + ".") for p in prefixes if p)
    return False


def annotate_reachability(findings: list[Finding], index: ImportIndex) -> None:
    """Stamp each dependency-match finding with whether the codebase imports the package."""
    for f in findings:
        if f.oracle != "osv:version-match" or not f.frames:
            continue
        eco = _ECO_BY_LANG.get(f.language)
        if eco is None:
            continue
        f.reachability = index.reaches(eco, f.frames[0].symbol)


_ECO_BY_LANG = {v: k for k, v in _LANG.items()}


# ---- C2: dependencies that are NOT exact-pinned ------------------------------------------------
# An open range ("^4.17.20", ">=2.25.1", "*", "latest") is deliberately NOT flagged as vulnerable —
# a resolver may install a fixed version, and matching the lower bound would be a false positive.
# But "not flagged" must not mean "invisible": an unpinned dependency is an exposure of UNKNOWN
# status, and the assurance boundary reports it as such rather than letting it vanish.

def unpinned_in_manifest(name: str, text: str, path: str) -> list[dict]:
    """Dependencies in this manifest whose version is an open range, not an exact pin. Each entry:
    {package, spec, manifest}. A lockfile pins exactly, so a target WITH a lockfile reports none."""
    fn = _PARSERS.get(name)
    if fn is None:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    # Re-parse the manifest leniently: the normal parsers drop non-exact specs, so we read the raw
    # (package, spec) pairs the same way each parser's regex does, and keep the ones exact_pin rejects.
    for pkg, spec in _raw_specs(name, text):
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)
        if exact_pin(spec) is None and spec is not None and str(spec).strip() not in ("", "*"):
            out.append({"package": pkg, "spec": str(spec).strip(), "manifest": path})
        elif str(spec).strip() in ("", "*", "latest"):
            out.append({"package": pkg, "spec": str(spec).strip() or "*", "manifest": path})
    return out


def _raw_specs(name: str, text: str):
    """(package, spec) pairs straight from a manifest, pins and ranges alike. Best-effort per
    ecosystem; only the pairs the exact-pin parsers discard matter for the unpinned view."""
    import json as _json
    import re as _re
    if name == "package.json":
        try:
            d = _json.loads(text)
        except ValueError:
            return
        for sect in ("dependencies", "devDependencies", "optionalDependencies"):
            for pkg, spec in (d.get(sect) or {}).items():
                yield pkg, spec
    elif name == "requirements.txt":
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = _re.match(r"([A-Za-z0-9._-]+)\s*(.*)$", line)
            if m:
                yield _norm_pypi(m.group(1)), (m.group(2).strip() or None)
    elif name == "go.mod":
        for m in _re.finditer(r"^\s*([A-Za-z0-9._/~-]+)\s+(v\S+)", text, _re.M):
            yield m.group(1), m.group(2)
