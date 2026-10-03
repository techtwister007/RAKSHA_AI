"""The five-check gate — the incorruptible inspector."""

from .crossconfirm import cross_confirm
from .differential import Canonicaliser, Mismatch, Quarantined, differential, preflight
from .runner import MAX_REPAIR_ROUNDS, GateVerdict, decide, oracle_fired, run_gate, verify_regression_test
from .target import BuildResult, CommandTarget, RunResult, Target, TestResult

__all__ = [
    "BuildResult", "CommandTarget", "RunResult", "Target", "TestResult",
    "Canonicaliser", "Mismatch", "Quarantined", "differential", "preflight",
    "GateVerdict", "MAX_REPAIR_ROUNDS", "decide", "oracle_fired", "run_gate", "verify_regression_test",
    "cross_confirm",
]
