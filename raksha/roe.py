"""Rules of Engagement — autonomy as doctrine, not a settings page.

Autonomy is a per-asset authority level the system obeys, and it tightens itself as the signals get
weaker — the same logic as fire control. Three things combine to decide what may be done with a
*verified* fix:

  1. the asset's criticality tier, which CAPS the level (an operator may set lower, never higher);
  2. automatic step-downs, which drop THIS patch below the cap when risk rises
     (touches auth/crypto, came from the mitigation floor, large change, flaky gate, advisor
     disagrees, first sighting of this bug class on this asset);
  3. standing orders, which hold at every level and are never broken.

`effective_roe()` returns the level in force, the reasons it stepped down, and whether the
two-person rule applies. This is the engine behind the ROE-slider demo beat: flip an asset to a
higher tier and the same proven fix now waits for two officers' signatures. In the full deployment
this is a signed OPA policy file; here it is the same decision logic, dependency-free and offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum

from .finding import Finding, RepairLane, RoeLevel


class Level(IntEnum):
    """Ordered so min() picks the most restrictive. Maps 1:1 to RoeLevel."""
    R0 = 0  # observe
    R1 = 1  # recommend
    R2 = 2  # act with approval
    R3 = 3  # act autonomously

    def to_roe(self) -> RoeLevel:
        return RoeLevel[self.name]


class AssetTier(Enum):
    """Criticality tier, with the ROE level it caps at and whether it needs two signatures.

    CRITICAL and IMPORTANT both cap at R2 but are DISTINCT members (critical adds the two-person
    rule), so this is a plain Enum carrying explicit data — an IntEnum with equal values would make
    one an alias of the other.
    """
    ROUTINE = ("routine", Level.R3, False)              # training LMS, internal portal
    IMPORTANT = ("important", Level.R2, False)          # logistics, admin
    CRITICAL = ("critical", Level.R2, True)             # C2, comms — R2 + two-person rule
    MISSION_CRITICAL = ("mission_critical", Level.R1, False)  # fire control — recommend only

    def __init__(self, label: str, cap: Level, two_person: bool) -> None:
        self.label = label
        self._cap = cap
        self._two_person = two_person

    @property
    def cap(self) -> Level:
        return self._cap

    @property
    def two_person(self) -> bool:
        return self._two_person


@dataclass(frozen=True)
class Asset:
    name: str
    tier: AssetTier = AssetTier.IMPORTANT
    #: operator may pin the ceiling LOWER than the tier cap, never higher
    operator_cap: Level | None = None


# Standing orders — never broken, at any level. Enforced as hard invariants elsewhere; listed here
# so the console and the evidence bundle can show them.
STANDING_ORDERS = (
    "no network egress, ever",
    "never deploy a patch that failed any gate",
    "never delete more than a set amount of code",
    "every action logged with the ROE in force and who authorised it",
    "every deployment ships with a rollback",
)

_AUTH_WORDS = ("auth", "authz", "authentication", "authorization", "login", "password", "credential",
               "token", "session", "crypto", "cipher", "tls", "ssl", "access control", "permission",
               "jwt", "oauth", "privilege")
_LARGE_AST_LINES = 40           # a change bigger than this drops a level
_FLAKY_QUARANTINE = 5           # this many quarantined inputs is a weak differential signal


@dataclass
class RoeDecision:
    asset: str
    tier: AssetTier
    cap: Level
    effective: Level
    step_downs: list[str] = field(default_factory=list)
    two_person: bool = False

    @property
    def requires_human(self) -> bool:
        return self.effective <= Level.R2

    @property
    def autonomous(self) -> bool:
        return self.effective >= Level.R3 and not self.two_person

    def as_dict(self) -> dict:
        return {
            "asset": self.asset, "tier": self.tier.name, "cap": self.cap.to_roe().value,
            "effective": self.effective.to_roe().value, "step_downs": list(self.step_downs),
            "two_person": self.two_person, "requires_human": self.requires_human,
            "autonomous": self.autonomous,
        }


def _diff_touches_auth(diff: str | None) -> bool:
    if not diff:
        return False
    low = diff.lower()
    return any(w in low for w in _AUTH_WORDS)


def _diff_size(diff: str | None) -> int:
    if not diff:
        return 0
    return sum(1 for ln in diff.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---"))


def effective_roe(asset: Asset, finding: Finding, *, advisor_disagrees: bool = False,
                  bug_class_seen_on_asset: bool = True) -> RoeDecision:
    """The authority in force for applying `finding`'s verified fix to `asset`.

    Starts at the asset's cap (lowered by any operator ceiling) and steps down for every risk signal.
    Confidence buys autonomy; uncertainty takes it away.
    """
    cap = asset.tier.cap
    if asset.operator_cap is not None:
        cap = min(cap, asset.operator_cap)

    level = cap
    reasons: list[str] = []

    def step_to(target: Level, why: str) -> None:
        nonlocal level
        if level > target:
            level = target
        reasons.append(why)

    if _diff_touches_auth(finding.patch_diff):
        step_to(Level.R2, "patch touches auth / crypto / access control")
    if finding.repair_lane is RepairLane.MITIGATION:
        step_to(Level.R2, "fix came from the mitigation floor, not a real fix")
    if _diff_size(finding.patch_diff) > _LARGE_AST_LINES:
        step_to(Level.R2, "patch is large (change over threshold)")
    quarantined = sum(r.quarantined_inputs for r in finding.gate_history)
    if quarantined >= _FLAKY_QUARANTINE:
        step_to(Level.R2, f"differential gate quarantined {quarantined} flaky inputs")
    if not bug_class_seen_on_asset:
        step_to(Level.R2, "first time this bug class is seen on this asset")
    if advisor_disagrees:
        step_to(Level.R1, "security advisor disagrees with the coding model")

    return RoeDecision(asset.name, asset.tier, cap, level, reasons, two_person=asset.tier.two_person)


@dataclass
class Signature:
    officer: str
    key_id: str


def may_deploy(decision: RoeDecision, signatures: list[Signature]) -> tuple[bool, str]:
    """Whether a verified fix may actually be deployed, given the authority and any signatures."""
    distinct = {s.key_id for s in signatures}
    if decision.effective <= Level.R1:
        return False, f"{decision.effective.name}: recommend only — a human applies this, the system does not"
    if decision.two_person:
        if len(distinct) >= 2:
            return True, "two officers signed; deploying under the two-person rule"
        return False, f"critical asset: needs two officers' signatures, have {len(distinct)}"
    if decision.effective == Level.R2:
        if distinct:
            return True, "approved and signed; deploying"
        return False, "R2: staged, awaiting human approval"
    return True, "R3: deploying verified fix autonomously, within standing orders"
