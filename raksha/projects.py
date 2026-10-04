"""K1 project identity, the project store, and the per-version facts reports compare (K17, K18).

**Identity.** A project keeps one ID across runs, paths and patches. The ID is minted from the
project's name the first time it is seen; on later runs a tree is matched to an existing project by
its *structure fingerprint* — the set of its source and manifest file paths — not by where it sits on
disk and not by file contents (a patch changes contents, never the project). A tree whose name
matches but whose file set is mostly different (Jaccard below 0.5) is a different project and gets
its own ID; so does a same-structure tree under a different name. The asset registry supplies the
owner unit, mission function and tier when it knows the project.

**Store.** Everything a project accumulates lives on the box under ``$RAKSHA_HOME/projects/<ID>/``
(default ``~/.raksha``): the registry entry, signed report versions (``reports/vN/``), human
"marked done" notes, and the last advisory-check state. Nothing leaves the machine.

**Facts per version** (read-only scans, never executing anything):
  * the component inventory (K18) — every dependency the manifests pin;
  * the attack surface (K17) — network listeners, file-upload handlers, privileged calls, and the
    external dependencies, so a version that grows its surface is flagged before any bug is found.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_SRC_EXT = {".c", ".h", ".cc", ".cpp", ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php"}
_MANIFESTS = {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "go.mod",
              "pom.xml", "Cargo.toml", "build.gradle"}
_SKIP = {".git", "node_modules", "__pycache__", "target", "build", "dist", ".venv", "venv"}
SAME_PROJECT_JACCARD = 0.5


def home() -> Path:
    return Path(os.environ.get("RAKSHA_HOME") or Path.home() / ".raksha")


def _files(root: Path) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in _SKIP or part.startswith(".raksha") for part in rel.parts):
            continue
        if p.is_file() and (p.suffix in _SRC_EXT or p.name in _MANIFESTS):
            out.append(p)
    return out


def structure(root: str | Path) -> list[str]:
    root = Path(root)
    return [str(p.relative_to(root)) for p in _files(root)]


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "project"


@dataclass
class Project:
    id: str
    name: str
    created: str
    structure: list[str] = field(default_factory=list)
    owner_unit: str | None = None
    mission_function: str | None = None
    tier: str | None = None
    aliases: list[str] = field(default_factory=list)     # paths it has been scanned from

    def as_dict(self) -> dict:
        d = asdict(self)
        d["files"] = len(self.structure)
        d.pop("structure")
        return d


class Store:
    """The on-box project store. `home` defaults to $RAKSHA_HOME (or ~/.raksha)."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else home()
        self.projects_dir = self.root / "projects"

    # -- registry --------------------------------------------------------------------------
    def all(self) -> list[Project]:
        out = []
        if self.projects_dir.is_dir():
            for d in sorted(self.projects_dir.iterdir()):
                f = d / "project.json"
                if f.is_file():
                    out.append(Project(**json.loads(f.read_text())))
        return out

    def get(self, pid: str) -> Project | None:
        f = self.projects_dir / pid / "project.json"
        return Project(**json.loads(f.read_text())) if f.is_file() else None

    def save(self, p: Project) -> None:
        d = self.projects_dir / p.id
        d.mkdir(parents=True, exist_ok=True)
        (d / "project.json").write_text(json.dumps(asdict(p), indent=2, sort_keys=True))

    def dir(self, pid: str) -> Path:
        return self.projects_dir / pid

    def identify(self, root: str | Path, *, name: str | None = None, registry=None,
                 save: bool = True) -> Project:
        """The project this tree is (K1): matched by name + structure, minted when new."""
        root = Path(root).resolve()
        name = name or root.name
        struct = structure(root)
        mine = set(struct)
        best, best_j = None, 0.0
        for p in self.all():
            j = _jaccard(mine, set(p.structure))
            if p.name == name and j >= SAME_PROJECT_JACCARD and j > best_j:
                best, best_j = p, j
        if best is None:
            digest = hashlib.sha256((name + "\0" + "\n".join(struct)).encode()).hexdigest()[:8].upper()
            pid = f"PRJ-{_slug(name)[:24]}-{digest}"
            while (self.projects_dir / pid).exists():          # same name, different project
                digest = hashlib.sha256((pid + "+").encode()).hexdigest()[:8].upper()
                pid = f"PRJ-{_slug(name)[:24]}-{digest}"
            best = Project(id=pid, name=name, created=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        if not save:                                           # read-only: match, never record
            return best
        best.structure = struct                                # track the project as it evolves
        if str(root) not in best.aliases:
            best.aliases.append(str(root))
        if registry is not None:
            a = registry.lookup(name)
            if a is not None:
                best.owner_unit, best.mission_function, best.tier = a.owner_unit, a.mission_function, a.tier
        self.save(best)
        return best

    # -- human notes (K4) ------------------------------------------------------------------
    def marks(self, pid: str) -> dict:
        f = self.dir(pid) / "marks.json"
        return json.loads(f.read_text()) if f.is_file() else {}

    def mark_done(self, pid: str, key: str, *, actor: str, note: str = "") -> dict:
        m = self.marks(pid)
        m[key] = {"actor": actor, "note": note, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.dir(pid).mkdir(parents=True, exist_ok=True)
        (self.dir(pid) / "marks.json").write_text(json.dumps(m, indent=2, sort_keys=True))
        return m[key]

    def clear_mark(self, pid: str, key: str) -> None:
        m = self.marks(pid)
        if m.pop(key, None) is not None:
            (self.dir(pid) / "marks.json").write_text(json.dumps(m, indent=2, sort_keys=True))


# ---- K18 component inventory -------------------------------------------------------------------

def inventory(root: str | Path) -> list[dict]:
    """Every pinned dependency the project's manifests declare (read-only)."""
    from .lanes import supply
    root = Path(root)
    deps = []
    for p in _files(root):
        if p.name in supply._PARSERS:
            try:
                deps += supply.parse_manifest(p.name, p.read_text(errors="replace"), str(p.relative_to(root)))
            except Exception:  # noqa: BLE001 — an unparseable manifest is skipped, not fatal
                continue
    seen, out = set(), []
    for d in deps:
        k = (d.ecosystem, d.package, d.version)
        if k not in seen:
            seen.add(k)
            out.append({"ecosystem": d.ecosystem, "package": d.package, "version": d.version,
                        "manifest": d.manifest})
    return out


# ---- K17 attack surface ------------------------------------------------------------------------

#: Read-only patterns for surface a version exposes. These describe what the code *offers* an
#: attacker (a listener, an upload), not a bug; a growth in them is a review prompt, not a finding.
SURFACE_RULES: dict[str, list[str]] = {
    "network-listener": [r"\.listen\s*\(", r"\bbind\s*\(", r"\bHTTPServer\s*\(", r"\bapp\.run\s*\(",
                         r"\bnet\.Listen\s*\(", r"\bServerSocket\s*\(", r"\bcreateServer\s*\(",
                         r"\bListenAndServe\s*\(", r"\bsocketserver\.", r"\buvicorn\.run\s*\("],
    "file-upload": [r"request\.files\b", r"\bmultipart\b", r"\bUploadFile\b", r"\bmulter\s*\(",
                    r"\bFormFile\s*\(", r"\bMultipartFile\b"],
    "privileged-call": [r"\bsetuid\s*\(", r"\bsetgid\s*\(", r"\bchmod\s*\(", r"\bchown\s*\(",
                        r"\bos\.system\b", r"\bsubprocess\.", r"\bexec[lv]p?e?\s*\(", r"\bRuntime\.getRuntime\b",
                        r"\bchild_process\b", r"\bexec\.Command\b", r"\bptrace\s*\("],
}


def surface(root: str | Path, *, extra_privileged: list[str] = ()) -> dict:
    """The attack surface of one version: per category, the (file, line) sites; plus dependencies.
    `extra_privileged` carries calls a promoted lesson (K9) taught RAKSHA to watch."""
    root = Path(root)
    rules = {k: [re.compile(p) for p in v] for k, v in SURFACE_RULES.items()}
    rules["privileged-call"] += [re.compile(r"\b" + re.escape(c) + r"\s*\(") for c in extra_privileged]
    out: dict[str, list[str]] = {k: [] for k in rules}
    for p in _files(root):
        if p.suffix not in _SRC_EXT:
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        rel = str(p.relative_to(root))
        for i, ln in enumerate(lines, 1):
            for cat, rxs in rules.items():
                if any(rx.search(ln) for rx in rxs):
                    out[cat].append(f"{rel}:{i}")
    out["external-dependency"] = sorted(f"{d['ecosystem']}:{d['package']}" for d in inventory(root))
    return out


def _site_key(site: str) -> str:
    """A site without its line number: a moved line is not new surface."""
    return site.rsplit(":", 1)[0] if re.search(r":\d+$", site) else site


def drift(previous: dict | None, current: dict) -> list[dict]:
    """K17: what the current version exposes that the previous one did not. Counts per file, so a
    second listener added to a file that already had one is caught, and a line move is not."""
    if previous is None:
        return []
    alerts = []
    for cat, sites in current.items():
        if cat == "external-dependency":
            for dep in sorted(set(sites) - set(previous.get(cat, []))):
                alerts.append({"category": cat, "site": dep, "detail": f"new external dependency {dep}"})
            continue
        before: dict[str, int] = {}
        for s in previous.get(cat, []):
            before[_site_key(s)] = before.get(_site_key(s), 0) + 1
        now: dict[str, list[str]] = {}
        for s in sites:
            now.setdefault(_site_key(s), []).append(s)
        for f, ss in sorted(now.items()):
            if len(ss) > before.get(f, 0):
                for s in ss[before.get(f, 0):]:
                    alerts.append({"category": cat, "site": s,
                                   "detail": f"new {cat.replace('-', ' ')} at {s}"})
    return alerts
