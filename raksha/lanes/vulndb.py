"""Loader for the offline vulnerability database.

The full product carries the OSV offline mirror; this loads the bundled curated slice
(`raksha/data/vulndb.json`). Nothing here touches the network — that is the whole point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_DEFAULT = Path(__file__).parents[1] / "data" / "vulndb.json"


@dataclass
class VulnDB:
    advisories: list[dict]
    _index: dict[tuple[str, str], list[dict]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for adv in self.advisories:
            self._index.setdefault((adv["ecosystem"], adv["package"]), []).append(adv)

    def for_package(self, ecosystem: str, package: str) -> list[dict]:
        return self._index.get((ecosystem, package), [])


def load(path: Path | None = None) -> VulnDB:
    data = json.loads((path or _DEFAULT).read_text())
    return VulnDB(advisories=data.get("advisories", []))
