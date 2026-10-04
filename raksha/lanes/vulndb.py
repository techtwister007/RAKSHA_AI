"""Loader for the offline vulnerability database.

The full product carries the OSV offline mirror; this loads the bundled curated slice
(`raksha/data/vulndb.json`). Nothing here touches the network — that is the whole point.

Each advisory carries a list of affected ranges (OSV publishes one per patched release line). A
legacy entry with a single `introduced`/`fixed` pair is normalised to a one-range list.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .version import in_any_range

_DEFAULT = Path(__file__).parents[1] / "data" / "vulndb.json"


def normalise_package(ecosystem: str, package: str) -> str:
    """Canonical package name per ecosystem (PEP 503 for PyPI: case-fold, runs of -_. → -)."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", package).lower()
    return package


def _ranges(adv: dict) -> list[dict]:
    if adv.get("ranges"):
        return list(adv["ranges"])
    return [{"introduced": adv.get("introduced", "0"), "fixed": adv.get("fixed")}]


@dataclass
class VulnDB:
    advisories: list[dict]
    _index: dict[tuple[str, str], list[dict]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for adv in self.advisories:
            adv["ranges"] = _ranges(adv)
            key = (adv["ecosystem"], normalise_package(adv["ecosystem"], adv["package"]))
            self._index.setdefault(key, []).append(adv)

    def for_package(self, ecosystem: str, package: str) -> list[dict]:
        return self._index.get((ecosystem, normalise_package(ecosystem, package)), [])

    def by_id(self, advisory_id: str) -> dict | None:
        return next((a for a in self.advisories if a["id"] == advisory_id), None)


def affected_range(adv: dict, version: str) -> dict | None:
    """The advisory range containing `version` (so the fix offered is on the same release line)."""
    return in_any_range(version, _ranges(adv))


def load(path: Path | None = None) -> VulnDB:
    data = json.loads((path or _DEFAULT).read_text())
    return VulnDB(advisories=data.get("advisories", []))
