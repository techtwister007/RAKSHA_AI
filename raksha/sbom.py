"""D9 — a software bill of materials for RAKSHA itself.

A defence acceptance board asks "what is in this thing?" and the honest answer is a machine-readable
SBOM, not prose. This module emits a CycloneDX 1.5-shaped JSON document covering three layers:

  * RAKSHA's own package (the subject, in ``metadata.component``);
  * the Python standard-library runtime it is built on (its only runtime dependency by design); and
  * the optional / bundled open-source components the full deployment assembles, read from
    ``THIRD_PARTY.md`` when it can be parsed, and from a curated in-module list otherwise.

Real vs fallback
----------------
*Real:* the CycloneDX structure, the parse of ``THIRD_PARTY.md`` tables, and the deterministic
serial number derived from the document's own content. *Fallback:* when ``THIRD_PARTY.md`` is absent
or unparseable, ``_CURATED`` (a hand-kept snapshot of that file's components) is used instead, and
``metadata.properties`` records which source produced the document.

Determinism: no wall-clock timestamp is written and components are sorted by (type, name, version),
so two runs on the same tree produce byte-identical JSON. Pass ``timestamp=`` to opt a timestamp in.
Stdlib only; no network.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path

SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"

_REPO = Path(__file__).resolve().parent.parent
_THIRD_PARTY = _REPO / "THIRD_PARTY.md"
_PYPROJECT = _REPO / "pyproject.toml"

# A dotted version token (so "Python 3.11+" -> "3.11" but "Qwen3-Coder-Next 32B" yields nothing).
_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")
_SEP_RE = re.compile(r"^:?-+:?$")

#: Hand-kept snapshot of THIRD_PARTY.md, used only when the file cannot be parsed. Each entry is
#: (name, type, licence). Kept deliberately short — the parse is the real source of truth.
_CURATED: tuple[tuple[str, str, str], ...] = (
    ("gcc + AddressSanitizer, gcov", "application", "GPL (toolchain)"),
    ("JDK 17+, Apache Maven", "application", "GPL+CE / Apache-2.0"),
    ("Go toolchain", "application", "BSD-3-Clause"),
    ("git, patch", "application", "GPL-2.0"),
    ("OASIS SARIF 2.1.0 schema", "data", "OASIS, royalty-free"),
    ("Qwen3-Coder-Next 32B", "machine-learning-model", "Apache-2.0"),
    ("Foundation-sec-8B-Reasoning", "machine-learning-model", "Llama-3.1 community licence"),
    ("Semgrep", "application", "LGPL-2.1"),
    ("OSV-Scanner", "application", "Apache-2.0"),
    ("vLLM", "application", "Apache-2.0"),
    ("cosign / in-toto", "application", "Apache-2.0"),
    ("Syft (CycloneDX)", "application", "Apache-2.0"),
    ("pytest, jsonschema", "library", "MIT"),
)

# Heuristic: map a THIRD_PARTY row to a CycloneDX component type from keywords in its name/role.
_MODEL_HINT = re.compile(r"\b(32B|8B|weights|Qwen|Llama|Foundation-sec|model)\b", re.I)
_DATA_HINT = re.compile(r"\b(schema|corpus|corpora|dataset|bench|ARVO|SARIF)\b", re.I)


def _raksha_version() -> str:
    """RAKSHA's own version, parsed from pyproject.toml (stdlib tomllib); '0.0.0' if unreadable."""
    try:
        import tomllib
        data = tomllib.loads(_PYPROJECT.read_text())
        return str(data.get("project", {}).get("version", "0.0.0"))
    except Exception:  # noqa: BLE001 — a missing/garbled pyproject must not break the SBOM
        return "0.0.0"


def _python_version_floor() -> str:
    """The required Python floor (e.g. '3.11'), deterministic across machines unlike the running
    interpreter. Parsed from requires-python; defaults to '3.11'."""
    try:
        import tomllib
        req = str(tomllib.loads(_PYPROJECT.read_text()).get("project", {}).get("requires-python", ""))
        m = _VERSION_RE.search(req)
        if m:
            return m.group(1)
    except Exception:  # noqa: BLE001
        pass
    return "3.11"


def _classify(name: str, role: str) -> str:
    if _MODEL_HINT.search(name):
        return "machine-learning-model"
    if _DATA_HINT.search(name + " " + role):
        return "data"
    return "application"


def _parse_third_party(path: Path) -> list[tuple[str, str, str]]:
    """Parse the markdown tables of THIRD_PARTY.md into (name, type, licence) rows.

    Every table in that file is ``| Component | Role/Used by | Licence |``; we take the first cell as
    the name, the last as the licence, and a middle cell (if any) as the role used to classify. Rows
    whose first cell is a header ("Component") or a ``---`` separator are skipped. Returns [] if the
    file cannot be read, which signals the caller to use the curated list.
    """
    try:
        text = path.read_text()
    except OSError:
        return []
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        if all(_SEP_RE.match(c) for c in cells):
            continue
        name = cells[0].replace("`", "").strip()
        if not name or name.lower() == "component":
            continue
        licence = cells[-1].strip()
        role = cells[1] if len(cells) >= 3 else ""
        rows.append((name, _classify(name, role), licence))
    return rows


def _bom_ref(type_: str, name: str, version: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return f"{type_}/{slug}@{version}" if version else f"{type_}/{slug}"


def _component(name: str, type_: str, *, version: str = "", licence: str = "",
               description: str = "") -> dict:
    comp: dict = {"type": type_, "bom-ref": _bom_ref(type_, name, version), "name": name}
    if version:
        comp["version"] = version
    if description:
        comp["description"] = description
    if licence and licence != "-":
        comp["licenses"] = [{"license": {"name": licence}}]
    return comp


def _components(third_party: Path | None = None) -> tuple[list[dict], str]:
    """Build the sorted component list plus a source tag ('THIRD_PARTY.md' or 'curated')."""
    path = third_party if third_party is not None else _THIRD_PARTY
    parsed = _parse_third_party(path)
    if parsed:
        rows, source = parsed, "THIRD_PARTY.md"
    else:
        rows = list(_CURATED)
        source = "curated"

    comps: list[dict] = [
        _component("Python standard library", "platform",
                   version=_python_version_floor(), licence="PSF",
                   description="the sole runtime dependency by design — every runtime import is "
                               "stdlib or a tool invoked as a subprocess"),
    ]
    seen = {"python standard library"}
    for name, type_, licence in rows:
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        version = ""
        m = _VERSION_RE.search(name)
        if m:
            version = m.group(1)
        comps.append(_component(name, type_, version=version, licence=licence))
    comps.sort(key=lambda c: (c["type"], c["name"], c.get("version", "")))
    return comps, source


def generate_sbom(*, third_party: Path | str | None = None, timestamp: str | None = None) -> dict:
    """Return a CycloneDX 1.5 document describing RAKSHA, its runtime, and its bundled components.

    Deterministic: no timestamp is written unless ``timestamp`` is passed, components are sorted, and
    the ``serialNumber`` is a UUID derived from the document's own content, so repeated calls on the
    same tree are byte-identical. ``third_party`` overrides the THIRD_PARTY.md path (tests).
    """
    tp = Path(third_party) if third_party is not None else None
    comps, source = _components(tp)
    version = _raksha_version()
    subject = _component(
        "raksha", "application", version=version,
        description="RAKSHA AI — an offline cyber-reasoning system: find, fix, prove",
    )

    metadata: dict = {
        "component": subject,
        "tools": [{"vendor": "RAKSHA AI", "name": "raksha.sbom", "version": version}],
        "properties": [{"name": "raksha:sbom:source", "value": source}],
    }
    if timestamp is not None:
        metadata["timestamp"] = timestamp

    doc = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": metadata,
        "components": comps,
    }
    # A content-addressed serial number: deterministic, and changes when any component changes.
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).digest()
    doc["serialNumber"] = "urn:uuid:" + str(uuid.UUID(bytes=digest[:16]))
    return doc


def write_sbom(path: str | Path, **kwargs) -> Path:
    """Write ``generate_sbom(**kwargs)`` to ``path`` as indented JSON (deterministic). Returns path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(generate_sbom(**kwargs), indent=2, sort_keys=True) + "\n")
    return out
