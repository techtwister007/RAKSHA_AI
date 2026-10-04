"""B10 — binary lane: a compiled artifact with no source, build-free.

What an air-gapped estate actually hands over is often a binary: a vendor's ELF, a shaded jar, a
Go service with no repository. This lane reads the artifact's bytes and nothing else — it never
executes it — and produces four things, each a deterministic re-match with its own replay
(`python -m raksha binary-match RULE PATH [OFFSET]`):

* **Embedded component versions.** A Go binary carries its module list (`dep <module> v<x.y.z>`
  in the build-info blob); a jar carries `META-INF/maven/<group>/<artifact>/pom.properties`
  (one per shaded dependency); native libraries announce themselves in strings ("OpenSSL 1.0.2k",
  "inflate 1.2.11"). Each component goes into the artifact's SBOM.
* **Known-vulnerable components.** Every Go/Maven component is checked against the same offline
  advisory DB as the manifest lane; a hit is a CONFIRMED finding (CWE from the advisory) whose
  replay re-extracts the version from the bytes and re-checks the range. Native-library versions
  have no advisory feed offline, so they are SBOM entries only — never a guessed CVE.
* **Weak-crypto implementations.** The initialisation constants of MD5, SHA-1, DES and RC2 are
  byte patterns that only appear when the algorithm is compiled in. A hit says the implementation is
  PRESENT (severity `info`, CWE-327); it does not claim it is used for security — presence, never
  more than the bytes show.
* **An SBOM** (CycloneDX 1.5 JSON) of every component found, for the bundle.

Strings extraction is the classic `strings(1)` rule (printable ASCII runs of >= 6 bytes). Files
over 200 MB are skipped; nothing is decompressed beyond the jar's own zip directory.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow
from . import vulndb

_MAX_BYTES = 200 * 1024 * 1024
_ELF, _PE, _MACHO = b"\x7fELF", b"MZ", (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
_JAR_EXT = {".jar", ".war", ".ear"}


@dataclass(frozen=True)
class Component:
    ecosystem: str          # "Go" | "Maven" | "native"
    name: str
    version: str
    evidence: str           # what in the bytes established it
    offset: int = -1        # byte offset of the evidence (-1 inside a jar member)


@dataclass
class BinaryResult:
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)


def kind_of(data: bytes, name: str = "") -> str | None:
    """'elf' | 'pe' | 'macho' | 'jar' | None — by magic bytes (and the jar extension)."""
    if data.startswith(_ELF):
        return "elf"
    if data.startswith(_MACHO):
        return "macho"
    if data.startswith(_PE) and len(data) > 0x40:
        return "pe"
    if Path(name).suffix.lower() in _JAR_EXT and data.startswith(b"PK"):
        return "jar"
    return None


def strings(data: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    """(offset, text) for each printable-ASCII run of at least `min_len` bytes."""
    return [(m.start(), m.group(0).decode("ascii"))
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]


# ---------------------------------------------------------------- embedded versions

# Go build info: "dep\t<module>\tv<version>[\t<sum>]" (and "mod\t..." for the main module).
_GO_DEP = re.compile(rb"\bdep\t([A-Za-z0-9.\-_~/]+)\tv([0-9][0-9A-Za-z.\-+]*)")
_GO_VERSION = re.compile(rb"\bgo1\.[0-9]+(?:\.[0-9]+)?\b")
#: Native libraries whose banner string carries a version. SBOM evidence only (no offline feed).
_NATIVE = [
    ("openssl", re.compile(rb"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b")),
    ("zlib", re.compile(rb"(?:inflate|deflate) ([0-9]+\.[0-9]+(?:\.[0-9]+)*) Copyright")),
    ("sqlite", re.compile(rb"SQLite version ([0-9]+\.[0-9]+\.[0-9]+)")),
    ("libcurl", re.compile(rb"libcurl/([0-9]+\.[0-9]+\.[0-9]+)")),
    ("libpng", re.compile(rb"libpng version ([0-9]+\.[0-9]+\.[0-9]+)")),
    ("busybox", re.compile(rb"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)")),
]


def components_in(data: bytes, name: str = "") -> list[Component]:
    """Every component version the bytes establish, in a stable order."""
    out: list[Component] = []
    if kind_of(data, name) == "jar":
        out.extend(_jar_components(data))
        return out
    for m in _GO_DEP.finditer(data):
        out.append(Component("Go", m.group(1).decode(), "v" + m.group(2).decode(),
                             "go build info dep line", m.start()))
    for lib, rx in _NATIVE:
        m = rx.search(data)
        if m:
            out.append(Component("native", lib, m.group(1).decode(), f"banner string: {m.group(0)[:60]!r}",
                                 m.start()))
    return out


def _jar_components(data: bytes) -> list[Component]:
    out: list[Component] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    for info in sorted(zf.infolist(), key=lambda i: i.filename):
        n = info.filename
        if not (n.startswith("META-INF/maven/") and n.endswith("/pom.properties")):
            continue
        if info.file_size > 64 * 1024:
            continue
        props = {}
        for line in zf.read(info).decode("utf-8", "replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
        if {"groupId", "artifactId", "version"} <= props.keys():
            out.append(Component("Maven", f"{props['groupId']}:{props['artifactId']}", props["version"],
                                 f"jar member {n}"))
    return out


def _version_for_db(c: Component) -> str:
    return c.version[1:] if c.ecosystem == "Go" and c.version.startswith("v") else c.version


# ---------------------------------------------------------------- weak-crypto constants

#: Word-census rules (findcrypt style): compilers emit hash constants as instruction immediates,
#: so they are rarely contiguous. A rule fires when at least `need` of its distinctive 32-bit words
#: occur anywhere in the bytes (either endianness). MD5's T-table words and SHA-1's round
#: constants are what make the rule specific: the init words MD5 and SHA-1 share never decide it.
_WORD_RULES = [
    ("bin-md5-impl", "MD5", [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                             0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501], 6),
    ("bin-sha1-impl", "SHA-1", [0xc3d2e1f0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6], 4),
]
#: Table rules: DES's initial permutation and RC2's PITABLE are data arrays, so they ARE contiguous.
_TABLE_RULES = [
    ("bin-des-impl", "DES", bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4])),
    ("bin-rc2-impl", "RC2", bytes.fromhex("d978f9c419ddb5ed28e9fd794aa0d89d")),
]
_CRYPTO = [(r, a, None) for r, a, _, _ in _WORD_RULES] + [(r, a, t) for r, a, t in _TABLE_RULES]


def crypto_hits(data: bytes) -> list[tuple[str, str, int]]:
    """(rule, algorithm, offset) for each weak-crypto implementation present; the offset is that of
    the first distinctive constant found, so a replay can re-check the same evidence."""
    hits: list[tuple[str, str, int]] = []
    for rule, algo, words, need in _WORD_RULES:
        offs = []
        for w in words:
            le, be = w.to_bytes(4, "little"), w.to_bytes(4, "big")
            i = data.find(le)
            j = data.find(be)
            found = [k for k in (i, j) if k >= 0]
            if found:
                offs.append(min(found))
        if len(offs) >= need:
            hits.append((rule, algo, min(offs)))
    for rule, algo, table in _TABLE_RULES:
        i = data.find(table)
        if i >= 0:
            hits.append((rule, algo, i))
    return hits


# ---------------------------------------------------------------- findings

def _repro(rule: str, rel: str, offset: int, detail: str, payload: str) -> Reproducer:
    argv = ["raksha", "binary-match", rule, rel] + ([str(offset)] if offset >= 0 else [])
    return Reproducer.from_bytes(payload.encode(), argv, artifact_path=rel, minimised=True,
                                 kind=DETERMINISTIC_MATCH, detail=detail)


def _advisory_findings(c: Component, rel: str, db: vulndb.VulnDB) -> list[Finding]:
    out = []
    version = _version_for_db(c)
    for adv in db.for_package(c.ecosystem, c.name):
        hit = vulndb.affected_range(adv, version)
        if hit is None:
            continue
        fixed = hit.get("fixed")
        detail = (f"{c.name}@{version} embedded in {rel} ({c.evidence}) vulnerable per {adv['id']}"
                  + (f"/{adv['aka']}" if adv.get("aka") else "")
                  + (f"; fixed in {fixed}" if fixed else "; no fixed version"))
        f = Finding(oracle="binary:version-match", bug_class=adv.get("cwe", "CWE-1104"),
                    language="binary", target=rel,
                    message=f"Vulnerable embedded component: {detail}. {adv.get('summary', '')}".strip(),
                    severity={"critical": "critical", "high": "high", "low": "low"}.get(
                        adv.get("severity", "medium"), "medium"),
                    frames=[Frame(symbol=c.name, uri=rel, line=None)])
        f.add_fix_site(FixSite(uri=rel, rank=0, symbol=c.name,
                               rationale=(f"rebuild {rel} with {c.name} {fixed}" if fixed
                                          else "no fixed version; isolate or replace the artifact")))
        f.attach_reproducer(_repro(f"advisory:{adv['id']}", rel, -1, detail,
                                   f"{rel} :: {c.name} {version} :: {adv['id']}"))
        f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=adv["id"],
                                            exit_code=0))
        f.confirm(reason="embedded component version deterministically matches the advisory range")
        out.append(f)
    return out


def _crypto_finding(rule: str, algo: str, offset: int, rel: str) -> Finding:
    detail = f"{algo} implementation constants at byte offset {offset} of {rel}"
    f = Finding(oracle=f"binary:{rule}", bug_class="CWE-327", language="binary", target=rel,
                message=(f"Weak-crypto implementation present in binary: {algo} "
                         f"(init constants at offset {offset}); presence only — use not established"),
                severity="info", frames=[Frame(symbol=rule, uri=rel, line=None)])
    f.add_fix_site(FixSite(uri=rel, rank=0, symbol=rule,
                           rationale=f"confirm with the vendor whether {algo} protects anything"))
    f.attach_reproducer(_repro(rule, rel, offset, detail, f"{rule}@{rel}+{offset}"))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=rule, exit_code=0))
    f.confirm(reason="the algorithm's constants deterministically re-match at this offset")
    return f


def scan_bytes(data: bytes, rel: str, *, db: vulndb.VulnDB | None = None) -> BinaryResult:
    res = BinaryResult(artifacts=[rel])
    if kind_of(data, rel) is None:
        return BinaryResult()
    db = db or vulndb.load()
    comps = components_in(data, rel)
    res.components.extend(comps)
    for c in comps:
        if c.ecosystem in ("Go", "Maven"):
            res.findings.extend(_advisory_findings(c, rel, db))
    if kind_of(data, rel) != "jar":
        for rule, algo, off in crypto_hits(data):
            res.findings.append(_crypto_finding(rule, algo, off, rel))
    return res


def scan_artifacts(root: str | Path, *, db: vulndb.VulnDB | None = None) -> BinaryResult:
    """Every binary artifact under `root` (by magic bytes), merged."""
    root = Path(root)
    out = BinaryResult()
    paths = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    db = db or vulndb.load()
    for p in paths:
        if any(part in {".git", "node_modules", "__pycache__"} for part in p.parts):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            with p.open("rb") as fh:
                head = fh.read(8)
            if kind_of(head + b"\0" * 64, p.name) is None:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        rel = str(p.relative_to(root)) if p != root else p.name
        r = scan_bytes(data, rel, db=db)
        out.findings.extend(r.findings)
        out.components.extend(r.components)
        out.artifacts.extend(r.artifacts)
    return out


def sbom(result: BinaryResult) -> dict:
    """CycloneDX 1.5 JSON for the components the bytes established (deterministic order)."""
    purl_type = {"Go": "golang", "Maven": "maven", "native": "generic"}
    comps = []
    for c in sorted(set(result.components), key=lambda c: (c.ecosystem, c.name, c.version)):
        if c.ecosystem == "Maven" and ":" in c.name:
            g, a = c.name.split(":", 1)
            purl = f"pkg:maven/{g}/{a}@{c.version}"
        else:
            purl = f"pkg:{purl_type[c.ecosystem]}/{c.name}@{c.version}"
        comps.append({"type": "library", "name": c.name, "version": c.version, "purl": purl,
                      "bom-ref": purl,
                      "properties": [{"name": "raksha:evidence", "value": c.evidence}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"tools": [{"name": "raksha-binary-lane"}],
                         "component": {"type": "application", "name": ",".join(result.artifacts) or "-"}},
            "components": comps}


# ---------------------------------------------------------------- replay

def replay(rule: str, path: str, offset: int | None = None, root: str | Path = ".",
           *, db: vulndb.VulnDB | None = None) -> bool:
    """Re-read the artifact and re-run one rule. True = the finding still reproduces.

    `advisory:<ID>` re-extracts every embedded component and re-checks the advisory's range;
    a crypto rule re-checks its constants at `offset` (or anywhere, when no offset is given)."""
    file = Path(root) / path
    if not file.exists():
        raise FileNotFoundError(str(file))
    data = file.read_bytes()
    if rule.startswith("advisory:"):
        db = db or vulndb.load()
        adv = db.by_id(rule.split(":", 1)[1])
        if adv is None:
            raise ValueError(f"unknown advisory {rule}")
        for c in components_in(data, file.name):
            if (c.ecosystem == adv["ecosystem"]
                    and vulndb.normalise_package(c.ecosystem, c.name)
                    == vulndb.normalise_package(adv["ecosystem"], adv["package"])
                    and vulndb.affected_range(adv, _version_for_db(c)) is not None):
                return True
        return False
    if rule not in {r for r, _, _ in _CRYPTO}:
        raise ValueError(f"unknown binary rule {rule!r}")
    return any(r == rule and (offset is None or off == offset) for r, _, off in crypto_hits(data))
