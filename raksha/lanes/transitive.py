"""Transitive-dependency lane — the full dependency tree, offline, where the ecosystem allows it.

The build-free supply lane (``supply.py``) reads what a manifest *pins*: direct dependencies only.
A vulnerable library is, more often than not, pulled in **indirectly** — a safe direct dependency
drags in a vulnerable one three levels down. This lane resolves that full tree and matches every
node, direct or transitive, against the same offline vuln DB via ``supply.scan_dependencies``.

What is measured vs heuristic
-----------------------------
*Measured*: for npm/yarn the lockfile records the resolved tree exactly, so the whole tree — and
each node's direct/transitive classification — is read straight from the file, no tool, no network.
For Maven and Go the package manager's own offline tree command is shelled against a **warm local
cache** (``mvn -o dependency:tree``, ``go mod graph``); its output is the measured tree.

*Heuristic / honestly-degraded*: when that tool (or its warm cache) is absent, there is no way to
resolve the transitive closure offline, so this lane falls back to **direct dependencies only** and
says so — a note is appended to the ``notes`` out-list, and ``resolve_tree`` never guesses a tree it
could not observe. The ``via`` chain for a transitive node is best-effort (the first parent found
that requires it); it names *a* path, not necessarily the only one.

Nothing here touches the network. The only subprocesses are the local ``mvn`` / ``go`` toolchains,
each optional and each degrading to direct-only when unavailable. A root with no manifest at all
yields ``[]``.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..finding import Finding
from . import supply, vulndb

_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}
_TOOL_TIMEOUT = 60


@dataclass(frozen=True)
class ResolvedDependency(supply.Dependency):
    """A ``supply.Dependency`` that also records whether it was reached directly or transitively.

    Subclasses the frozen ``Dependency`` so it drops straight into ``supply.scan_dependencies`` /
    ``prefer_authoritative`` unchanged, while carrying the extra classification this lane produces.
    """

    transitive: bool = False
    #: One dependency chain, root → … → this package, as package names. Best-effort; may be empty
    #: when the resolver cannot name a parent (e.g. a flat/hoisted lockfile entry).
    via: tuple[str, ...] = ()


# ---------------------------------------------------------------- subprocess shim

def _run(cmd: list[str], cwd: Path, timeout: int = _TOOL_TIMEOUT) -> str | None:
    """Run a local toolchain command offline; stdout on success, None on any failure.

    Isolated so the Maven/Go paths have exactly one place that can fail, and so tests can simulate a
    missing tool by monkeypatching this function.
    """
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


# ---------------------------------------------------------------- npm / yarn (lockfile = the tree)

def _direct_names(pkg_json_text: str | None, root_entry: dict | None) -> set[str]:
    """The directly-declared dependency names, from the lockfile's root entry and/or package.json."""
    names: set[str] = set()
    for src in (root_entry, _json_or_none(pkg_json_text)):
        if not isinstance(src, dict):
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            block = src.get(section)
            if isinstance(block, dict):
                names.update(block.keys())
    return names


def _json_or_none(text: str | None) -> dict | None:
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _npm_tree(lock_text: str, pkg_json_text: str | None, manifest: str) -> list[ResolvedDependency]:
    data = _json_or_none(lock_text)
    if data is None:
        return []
    deps: list[ResolvedDependency] = []
    seen: set[tuple[str, str]] = set()

    packages = data.get("packages")
    if isinstance(packages, dict):                       # npm lockfile v2 / v3
        root_entry = packages.get("")
        direct = _direct_names(pkg_json_text, root_entry if isinstance(root_entry, dict) else None)
        # child → a parent that requires it, for the best-effort via chain.
        parent_of: dict[str, str] = {}
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            owner = _npm_name(key) if key else "(root)"
            for child in (meta.get("dependencies") or {}):
                parent_of.setdefault(child, owner)
        for key, meta in packages.items():
            if key == "" or not key.startswith("node_modules/") or not isinstance(meta, dict):
                continue
            if "version" not in meta:
                continue
            name = _npm_name(key)
            top_level = key.count("node_modules/") == 1
            is_direct = top_level and name in direct
            if (name, meta["version"]) in seen:
                continue
            seen.add((name, meta["version"]))
            deps.append(ResolvedDependency(
                "npm", name, meta["version"], manifest, None,
                transitive=not is_direct, via=_via(name, is_direct, parent_of)))
        return deps

    # npm lockfile v1: a nested "dependencies" tree.
    direct = _direct_names(pkg_json_text, None)
    tree = data.get("dependencies")
    if isinstance(tree, dict):
        _npm_v1_walk(tree, direct, manifest, (), deps, seen, top=True)
    return deps


def _npm_name(key: str) -> str:
    return key.split("node_modules/")[-1]


def _via(name: str, is_direct: bool, parent_of: dict[str, str]) -> tuple[str, ...]:
    if is_direct:
        return ()
    parent = parent_of.get(name)
    return (parent, name) if parent and parent != name else ()


def _npm_v1_walk(tree: dict, direct: set[str], manifest: str, chain: tuple[str, ...],
                 out: list[ResolvedDependency], seen: set[tuple[str, str]], *, top: bool) -> None:
    for name, meta in tree.items():
        if not isinstance(meta, dict) or "version" not in meta:
            continue
        is_direct = top and name in direct
        if (name, meta["version"]) not in seen:
            seen.add((name, meta["version"]))
            out.append(ResolvedDependency(
                "npm", name, meta["version"], manifest, None,
                transitive=not is_direct, via=() if is_direct else (*chain, name)))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _npm_v1_walk(nested, direct, manifest, (*chain, name), out, seen, top=False)


_YARN_HEADER = re.compile(r'^(?!\s)(?P<specs>[^\n]+):\s*$')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _yarn_tree(lock_text: str, pkg_json_text: str | None, manifest: str) -> list[ResolvedDependency]:
    """Parse a yarn.lock (v1 and the Berry YAML-ish form) into resolved dependencies."""
    direct = _direct_names(pkg_json_text, None)
    deps: list[ResolvedDependency] = []
    seen: set[tuple[str, str]] = set()
    cur_names: list[str] = []
    cur_version: str | None = None

    def flush() -> None:
        if cur_version and cur_names:
            name = cur_names[0]
            is_direct = name in direct
            if (name, cur_version) not in seen:
                seen.add((name, cur_version))
                deps.append(ResolvedDependency(
                    "npm", name, cur_version, manifest, None,
                    transitive=not is_direct, via=() if is_direct else (name,)))

    for raw in lock_text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        header = _YARN_HEADER.match(raw)
        if header:
            flush()
            cur_names = [_yarn_pkg_name(s) for s in header.group("specs").split(",")]
            cur_version = None
            continue
        ver = _YARN_VERSION.match(raw)
        if ver:
            cur_version = ver.group(1)
    flush()
    return deps


def _yarn_pkg_name(spec: str) -> str:
    spec = spec.strip().strip('"')
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


# ---------------------------------------------------------------- Maven (mvn -o dependency:tree)

_MVN_NODE = re.compile(r"^\[INFO\]\s*(?P<prefix>[ |+\\`-]*)(?P<coord>[\w.\-]+:[\w.\-]+:[\w.\-]+:.+)$")


def _maven_tree(pom_dir: Path, manifest: str, notes: list[str]) -> list[ResolvedDependency] | None:
    """Resolve via ``mvn -o dependency:tree`` against the warm local cache, or None to fall back."""
    out = _run(["mvn", "-q", "-o", "org.apache.maven.plugins:maven-dependency-plugin:tree",
                "-DoutputType=text"], pom_dir)
    if out is None:
        return None
    deps: list[ResolvedDependency] = []
    seen: set[tuple[str, str]] = set()
    stack: list[str] = []
    saw_root = False
    for line in out.splitlines():
        m = _MVN_NODE.match(line)
        if not m:
            continue
        depth = _maven_depth(m.group("prefix"))
        parsed = _maven_coord(m.group("coord"))
        if parsed is None:
            continue
        pkg, ver = parsed
        if depth == 0:
            saw_root = True
            stack = [pkg]
            continue
        stack = stack[:depth] + [pkg]
        if (pkg, ver) in seen:
            continue
        seen.add((pkg, ver))
        deps.append(ResolvedDependency(
            "Maven", pkg, ver, manifest, None,
            transitive=depth > 1, via=() if depth == 1 else tuple(stack)))
    if not saw_root and not deps:
        return None
    return deps


def _maven_depth(prefix: str) -> int:
    # The tree draws each level as roughly three characters ("+- ", "|  ", "\- ").
    return (len(prefix) + 2) // 3 if prefix.strip() else 0


def _maven_coord(coord: str) -> tuple[str, str] | None:
    parts = coord.split(":")
    if len(parts) < 4:
        return None
    group, artifact, version = parts[0], parts[1], parts[3]
    return f"{group}:{artifact}", version


# ---------------------------------------------------------------- Go (go mod graph)

def _go_tree(mod_dir: Path, mod_text: str, manifest: str, notes: list[str]) -> list[ResolvedDependency] | None:
    out = _run(["go", "mod", "graph"], mod_dir)
    if out is None:
        return None
    main = _go_main_module(mod_text)
    deps: list[ResolvedDependency] = []
    seen: set[tuple[str, str]] = set()
    direct_mods: set[str] = set()
    edges: list[tuple[str, str, str]] = []            # (parent, module, version)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        left, right = parts
        parent = left.split("@", 1)[0]
        mod, _, ver = right.partition("@")
        if not ver:
            continue
        edges.append((parent, mod, ver))
        if main and parent == main:
            direct_mods.add(mod)
    for parent, mod, ver in edges:
        if (mod, ver) in seen:
            continue
        seen.add((mod, ver))
        is_direct = mod in direct_mods and parent == main
        deps.append(ResolvedDependency(
            "Go", mod, ver, manifest, None,
            transitive=not is_direct, via=() if is_direct else (parent, mod)))
    return deps or None


def _go_main_module(mod_text: str) -> str | None:
    m = re.search(r"^\s*module\s+(\S+)", mod_text, re.M)
    return m.group(1) if m else None


# ---------------------------------------------------------------- the lane

def _walk_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def _read(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def resolve_tree(root: str | Path, notes: list[str] | None = None) -> list[supply.Dependency]:
    """Resolve the full dependency tree under ``root``, offline, where the ecosystem allows it.

    Returns ``ResolvedDependency`` records (a ``supply.Dependency`` subtype) each flagged
    ``transitive`` or direct. npm/yarn trees come straight from the lockfile; Maven and Go shell the
    package manager's own offline tree command against a warm cache and, when it or the cache is
    absent, fall back to **direct dependencies only**, appending a note to ``notes`` to say so.
    """
    root = Path(root)
    notes = notes if notes is not None else []
    deps: list[supply.Dependency] = []

    pkg_json_by_dir: dict[str, str] = {}
    for path in _walk_files(root):
        if path.name == "package.json":
            text = _read(path)
            if text is not None:
                pkg_json_by_dir[str(path.parent)] = text

    for path in _walk_files(root):
        name = path.name
        rel = str(path.relative_to(root)) if path != root else name
        text = _read(path)
        if text is None:
            continue
        if name == "package-lock.json":
            deps.extend(_npm_tree(text, pkg_json_by_dir.get(str(path.parent)), rel))
        elif name == "yarn.lock":
            deps.extend(_yarn_tree(text, pkg_json_by_dir.get(str(path.parent)), rel))
        elif name == "pom.xml":
            tree = _maven_tree(path.parent, rel, notes)
            if tree is None:
                notes.append(f"{rel}: mvn offline dependency:tree unavailable (no mvn or cold cache); "
                             "reporting direct dependencies only")
                deps.extend(ResolvedDependency(d.ecosystem, d.package, d.version, d.manifest, d.line,
                                               transitive=False)
                            for d in supply.parse_maven(text, rel))
            else:
                deps.extend(tree)
        elif name == "go.mod":
            tree = _go_tree(path.parent, text, rel, notes)
            if tree is None:
                notes.append(f"{rel}: `go mod graph` unavailable (no go or cold module cache); "
                             "reporting direct dependencies only")
                deps.extend(ResolvedDependency(d.ecosystem, d.package, d.version, d.manifest, d.line,
                                               transitive=False)
                            for d in supply.parse_go_mod(text, rel))
            else:
                deps.extend(tree)
    return deps


def scan_transitive(root: str | Path, db: vulndb.VulnDB | None = None,
                    notes: list[str] | None = None) -> list[Finding]:
    """Resolve the tree and match every node against the vuln DB, flagging transitive hits.

    Each returned finding is produced by ``supply.scan_dependencies`` (so the match, reproducer and
    status are identical to the direct lane) and then stamped — ``finding.transitive`` (bool) and
    ``finding.dep_via`` (the chain), with a parenthetical in the message — so the walk and the
    scorecard can rank an exploitable transitive hit against a direct one. A node reached only
    transitively is still a real, replayable finding.
    """
    db = db or vulndb.load()
    deps = resolve_tree(root, notes)
    index: dict[tuple[str, str, str, str], ResolvedDependency] = {}
    for d in deps:
        if isinstance(d, ResolvedDependency):
            index[(d.ecosystem, d.package, d.version, d.manifest)] = d
    findings = supply.scan_dependencies(deps, db)
    for f in findings:
        rd = _match_back(f, index)
        transitive = bool(rd.transitive) if rd else False
        f.transitive = transitive                                # instance attribute (not a Finding field)
        f.dep_via = list(rd.via) if rd and rd.via else []
        if transitive:
            via = " via " + " → ".join(rd.via) if rd and rd.via else ""
            f.message += f" (transitive dependency{via})"
        else:
            f.message += " (direct dependency)"
    return findings


def _match_back(f: Finding, index: dict) -> ResolvedDependency | None:
    """Recover the resolved dependency a supply finding came from, via its replay command."""
    repro = f.reproducer
    if repro is None or len(repro.replay_cmd) < 5 or repro.replay_cmd[1] != "match":
        return None
    eco, pkg, ver = repro.replay_cmd[2], repro.replay_cmd[3], repro.replay_cmd[4]
    return index.get((eco, pkg, ver, f.target))
