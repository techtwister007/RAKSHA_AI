"""RAKSHA AI — an offline cyber-reasoning system.

The governing principle: **the LLM is not the brain, the verifier is.** Deterministic
tools find, localise and decide; the model only proposes. See `RAKSHA_AI_Dossier/` for
the full brief and `BUILD_PLAN.md` for what is built and what is next.
"""

from .finding import (
    DETERMINISTIC_MATCH,
    EXPLOIT_REPLAY,
    Finding,
    FixSite,
    Frame,
    GateCheck,
    GateResult,
    InvariantViolation,
    RepairLane,
    ReplayResult,
    Reproducer,
    RoeLevel,
    Signature,
    Status,
    dedup,
    reportable,
    to_sarif_log,
)

__version__ = "0.1.0"

__all__ = [
    "DETERMINISTIC_MATCH",
    "EXPLOIT_REPLAY",
    "Finding",
    "FixSite",
    "Frame",
    "GateCheck",
    "GateResult",
    "InvariantViolation",
    "RepairLane",
    "ReplayResult",
    "Reproducer",
    "RoeLevel",
    "Signature",
    "Status",
    "dedup",
    "reportable",
    "to_sarif_log",
    "__version__",
]
