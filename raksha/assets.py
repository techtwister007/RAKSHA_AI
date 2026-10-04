"""The asset registry as data — every codebase, its mission function, its criticality tier.

`roe.Asset` objects were built ad hoc in the slices; BUILD_PLAN decision 11 makes the registry a
component that ROE, the vaccine sweep and the attack graph all read. It is a JSON file
(`raksha/data/assets.json`) so an operator edits it without touching code, loaded here into a
`Registry` that answers `lookup(target_name)` by glob on the target's name or any trailing path
suffix ("demo-targets/mixed-estate/tool-py" matches "mixed-estate/tool-py" and "mixed-estate/*").

Tiers and what they mean elsewhere:
  mission-critical  roe.AssetTier.MISSION_CRITICAL (R1: recommend only), multiplier 2.0
  operational       roe.AssetTier.IMPORTANT        (R2: act with approval), multiplier 1.5
  support           roe.AssetTier.ROUTINE          (R3 cap),                multiplier 1.0
  test              roe.AssetTier.ROUTINE,                                   multiplier 0.5

An unknown target is conservative in both directions: its ROE tier defaults to "operational" (a
human approves before anything is applied — `roe.Asset`'s own default), and its scoring multiplier
is 1.0, because a priority we have not classified is not inflated. Both are documented defaults,
not measurements, and `lookup` returns None so a caller can tell "unknown" from "support".
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import roe
from .finding import Finding

_DEFAULT_PATH = Path(__file__).parent / "data" / "assets.json"

TIERS = ("mission-critical", "operational", "support", "test")
DEFAULT_TIER = "operational"
#: Mission-impact weight per tier, used by the risk register / attack graph to scale priority.
_MULTIPLIER = {"mission-critical": 2.0, "operational": 1.5, "support": 1.0, "test": 0.5}
#: The multiplier for a target the registry does not know: never inflated.
UNKNOWN_MULTIPLIER = 1.0
_ROE_TIER = {
    "mission-critical": roe.AssetTier.MISSION_CRITICAL,
    "operational": roe.AssetTier.IMPORTANT,
    "support": roe.AssetTier.ROUTINE,
    "test": roe.AssetTier.ROUTINE,
}


@dataclass(frozen=True)
class Asset:
    name: str
    pattern: str
    tier: str
    mission_function: str
    owner_unit: str

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"asset {self.name}: unknown tier {self.tier!r} (expected one of {TIERS})")

    @property
    def multiplier(self) -> float:
        return _MULTIPLIER[self.tier]

    def as_dict(self) -> dict:
        return {"name": self.name, "pattern": self.pattern, "tier": self.tier,
                "mission_function": self.mission_function, "owner_unit": self.owner_unit}


def mission_multiplier(tier: str | None) -> float:
    """Priority weight for a tier; an unknown / None tier gets the conservative 1.0."""
    return _MULTIPLIER.get(tier or "", UNKNOWN_MULTIPLIER)


def _candidates(target_name: str) -> list[str]:
    """Every contiguous run of path components, longest first: "a/b/c" -> ["a/b/c", "a/b", "b/c",
    "a", "b", "c"], each also with a trailing "/" so a pattern "x/*" covers the directory "x" itself.
    A finding's path inside an estate ("mixed-estate/gateway-go/openapi.json") thus reaches the
    service entry "mixed-estate/gateway-go" before the estate's catch-all glob."""
    parts = [p for p in str(target_name).replace("\\", "/").strip("/").split("/") if p]
    windows = ["/".join(parts[i:j]) for n in range(len(parts), 0, -1)
               for i in range(len(parts) - n + 1) for j in (i + n,)]
    return [c for w in windows for c in (w, w + "/")]


def _specificity(a: Asset) -> tuple[int, int]:
    return (1 if any(ch in a.pattern for ch in "*?[") else 0, -len(a.pattern))


@dataclass
class Registry:
    assets: list[Asset] = field(default_factory=list)
    path: Path | None = None

    def lookup(self, target_name: str) -> Asset | None:
        """The most specific asset whose pattern matches the target's name or a path suffix of it."""
        names = _candidates(target_name)
        for asset in sorted(self.assets, key=_specificity):
            if any(fnmatch.fnmatchcase(n, asset.pattern) for n in names):
                return asset
        return None

    def tier_for(self, target_name: str) -> str:
        asset = self.lookup(target_name)
        return asset.tier if asset else DEFAULT_TIER

    def multiplier_for(self, target_name: str) -> float:
        asset = self.lookup(target_name)
        return asset.multiplier if asset else UNKNOWN_MULTIPLIER

    def to_roe_asset(self, target_name: str, *, operator_cap: roe.Level | None = None) -> roe.Asset:
        """The `roe.Asset` the ROE engine wants; an unknown target gets the operational default."""
        asset = self.lookup(target_name)
        tier = _ROE_TIER[asset.tier if asset else DEFAULT_TIER]
        name = asset.name if asset else str(target_name)
        return roe.Asset(name=name, tier=tier, operator_cap=operator_cap)

    def critical_names(self) -> frozenset[str]:
        """Names of mission-critical assets — what the attack graph treats as a critical asset."""
        return frozenset(a.name for a in self.assets if a.tier == "mission-critical")

    def as_dict(self) -> dict:
        return {"path": str(self.path) if self.path else None, "assets": [a.as_dict() for a in self.assets]}


def load(path: str | Path | None = None) -> Registry:
    p = Path(path) if path else _DEFAULT_PATH
    data = json.loads(p.read_text())
    assets = [Asset(a["name"], a["pattern"], a["tier"], a.get("mission_function", ""), a.get("owner_unit", ""))
              for a in data.get("assets", [])]
    return Registry(assets=assets, path=p)


def annotate(findings: list[Finding], registry: Registry, *, target: str | None = None) -> None:
    """Set `f.mission_impact` to the asset tier. `target` names the scanned target (the estate or
    codebase the findings came from); without it each finding's own path is looked up, and a finding
    on no known asset gets the documented default tier."""
    for f in findings:
        asset = None
        names = ([f"{target}/{f.target}"] if target and f.target else []) + ([target] if target else []) \
            + ([f.target] if f.target else [])
        for name in names:                      # most specific first: the finding's own service
            asset = registry.lookup(name)
            if asset is not None:
                break
        f.mission_impact = asset.tier if asset else DEFAULT_TIER
