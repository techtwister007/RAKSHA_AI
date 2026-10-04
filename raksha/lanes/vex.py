"""VEX lane — machine-readable exploitability statements for dependency findings.

A dependency match proves a vulnerable version is *present*. Whether it is *exploitable* here is a
separate question, and the supply lane already answers part of it: the reachability annotation says
whether the codebase actually imports the vulnerable package. VEX (Vulnerability Exploitability
eXchange) is the standard way to publish that answer, so a downstream consumer can suppress noise
without re-deriving it. This lane turns each dependency finding's reachability into a
CycloneDX-VEX-shaped ``analysis`` statement.

What is measured vs heuristic
-----------------------------
*Measured*: the mapping is a direct, deterministic function of the finding's ``reachability`` field
(itself produced by ``supply.annotate_reachability``) — nothing new is inferred here:

  - ``not-imported``  → state ``not_affected``, justification ``code_not_reachable`` (present, but
    the codebase never imports it, so the vulnerable code is not on any execution path here)
  - ``imported``      → state ``affected`` (the package is used; exploitability must be confirmed by
    a human or a deeper lane — this lane does not claim an exploit)
  - ``unknown`` / unset → state ``under_investigation`` (no source for that language was seen, so
    reachability could not be established offline)

The full justification vocabulary this lane can emit is ``code_not_present`` / ``code_not_reachable``
/ ``requires_configuration`` / ``under_investigation``; the first and third are reserved for channels
that can establish them and are not asserted from reachability alone.

*Heuristic*: ``not_affected`` here rests on import-graph reachability, which is a textual
approximation (see ``supply.ImportIndex``); it is a defensible triage default, not a proof of
non-exploitability. The statement says so in its ``detail``.

Stdlib only, offline, no findings created — this lane annotates and summarises existing findings.
"""

from __future__ import annotations

from typing import Iterable

from ..finding import Finding, utcnow
from . import supply

#: reachability value → (CycloneDX analysis state, justification or None, human detail)
_STATE = {
    supply.REACH_NOT_IMPORTED: (
        "not_affected", "code_not_reachable",
        "the vulnerable package is present but the codebase does not import it, so the vulnerable "
        "code is not on any execution path here (reachability by import-graph analysis)"),
    supply.REACH_IMPORTED: (
        "affected", None,
        "the codebase imports this package; the vulnerable code is reachable and exploitability "
        "should be confirmed — no exploit is claimed by this statement"),
    supply.REACH_UNKNOWN: (
        "under_investigation", "under_investigation",
        "no source for this ecosystem was seen in the target, so reachability could not be "
        "established offline"),
}

VEX_SPEC_VERSION = "1.5"


def _dep_findings(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.oracle == "osv:version-match"]


def _advisory_id(f: Finding) -> str | None:
    """The advisory id recorded in the finding's replay command (``raksha match … --advisory ID``)."""
    repro = f.reproducer
    if repro is None:
        return None
    cmd = repro.replay_cmd
    if "--advisory" in cmd:
        i = cmd.index("--advisory")
        if i + 1 < len(cmd):
            return cmd[i + 1]
    return None


def _pkg_ref(f: Finding) -> str:
    pkg = f.frames[0].symbol if f.frames else f.target
    detail = f.reproducer.detail if f.reproducer else ""
    version = ""
    if "@" in (detail or ""):
        version = detail.split("@", 1)[1].split(" ", 1)[0].rstrip(";")
    return f"{pkg}@{version}" if version else pkg


def vex_for(findings: Iterable[Finding]) -> list[dict]:
    """One CycloneDX-VEX ``analysis`` statement per dependency finding, from its reachability."""
    statements: list[dict] = []
    for f in _dep_findings(findings):
        reach = f.reachability or supply.REACH_UNKNOWN
        state, justification, detail = _STATE.get(reach, _STATE[supply.REACH_UNKNOWN])
        analysis: dict = {"state": state, "detail": detail}
        if justification is not None:
            analysis["justification"] = justification
        statements.append({
            "bom-ref": f.id,
            "id": _advisory_id(f),
            "cwe": f.bug_class,
            "affects": [{"ref": _pkg_ref(f)}],
            "source": {"name": f.target},
            "reachability": reach,
            "analysis": analysis,
        })
    return statements


def vex_document(findings: Iterable[Finding]) -> dict:
    """A CycloneDX-shaped VEX document wrapping every dependency finding's statement."""
    vulnerabilities = vex_for(findings)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": VEX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": utcnow().isoformat(),
            "tool": {"name": "RAKSHA AI", "component": "vex"},
        },
        "vulnerabilities": vulnerabilities,
    }
