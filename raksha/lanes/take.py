"""External-scanner "take" lanes — evidence that cross-confirms our own lanes.

RAKSHA's own build-free lanes are the floor: they run with stdlib only, no network, no third-party
binary, and every finding they emit is proven and replayable. These "take" lanes are strictly
additive. When a well-known external scanner happens to be present on the operator's machine AND an
explicit flag enables it, we *take* its output as a second, independent channel of evidence:

  - `semgrep`      — static analysis. Its findings have no reproducer, so they enter as SUSPECTED
                     and are meant to be *cross-confirmed* by one of our own lanes landing a
                     reproducer on the same site + CWE (`gate.crossconfirm.cross_confirm`).
  - `gitleaks`     — secret detection. A hit is a deterministic re-match (the secret is present at a
                     location), so it enters confirmed, as DETERMINISTIC_MATCH evidence.
  - `osv-scanner`  — dependency CVE matching. Also a deterministic re-match against a vuln DB, so it
                     too enters confirmed as DETERMINISTIC_MATCH. On the sealed box set
                     RAKSHA_OSV_OFFLINE=1 and carry its local database.
  - `checkov`      — infrastructure-as-code and configuration checks (Dockerfiles, Kubernetes,
                     Terraform, CI files). A failed check re-matches deterministically.

Semgrep uses the bundled offline ruleset (`raksha/data/semgrep/raksha-offline.yml`) unless
RAKSHA_SEMGREP_RULES names another; its "auto" config needs the internet.

None of these tools is required and none is installed in the sealed runtime by default — they are
carried in the sealed bundle and switched on at the finale on a machine that has them. With nothing
installed and no flag set (the default, and the offline evaluation box), `run_take_lanes` returns an
empty list and never raises. A take lane that is enabled but whose binary is missing is a clean
no-op; a tool whose output cannot be parsed is dropped, not fatal.

Every finding is tagged in its oracle with the source tool (`take:semgrep`, `take:gitleaks`,
`take:osv-scanner`) so cross-confirmation and the risk register can see it came from an external
take lane, never conflating it with our own floor.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

from ..finding import (
    DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow,
)

#: How long an external scanner may run before we give up on it. A take lane must never hang the
#: pipeline; on timeout it is a clean no-op like an absent tool.
_TIMEOUT_S = 120


@dataclass(frozen=True)
class TakeLane:
    """One external scanner, wrapped so it runs only when present AND explicitly enabled.

    `binary` is the executable looked up on PATH; `env_flag` is the environment variable that must be
    truthy to enable it (so a present binary is never run without an operator opting in); `parse`
    turns the tool's stdout into findings.
    """

    tool: str
    binary: str
    env_flag: str
    argv: Callable[[str], list[str]]
    parse: Callable[[str, str], list[Finding]]

    def available(self, enabled: set[str] | None = None) -> bool:
        """True only when the binary is on PATH and this lane is enabled.

        Enablement comes from either an explicit `enabled` set (the tool name), or the lane's env
        flag being set to a truthy value (`1`, `true`, `yes`, `on`). Absent both, the lane is off.
        """
        if shutil.which(self.binary) is None:
            return False
        if enabled is not None and self.tool in enabled:
            return True
        return _truthy(os.environ.get(self.env_flag))

    def scan(self, root: str) -> list[Finding]:
        """Run the tool over `root` and parse its findings, or [] on any failure.

        Never raises: a missing binary, a non-zero exit (scanners exit non-zero when they *find*
        something), a timeout, or unparseable output all degrade to an empty list.
        """
        if shutil.which(self.binary) is None:
            return []
        try:
            proc = subprocess.run(self.argv(root), capture_output=True, text=True,
                                  timeout=_TIMEOUT_S)
        except (OSError, subprocess.SubprocessError):
            return []
        try:
            return self.parse(proc.stdout, root)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return []


def _truthy(value: str | None) -> bool:
    return bool(value) and value.strip().lower() in {"1", "true", "yes", "on"}


def _rel(path: str, root: str) -> str:
    """Path reported relative to the scanned root, matching how our own lanes record locations."""
    root = root.rstrip("/") + "/"
    return path[len(root):] if path.startswith(root) else path


# ---------------------------------------------------------------- parsers

def _semgrep_findings(stdout: str, root: str) -> list[Finding]:
    """Parse `semgrep --json`. Static → SUSPECTED, to be cross-confirmed by our reproducer lanes.

    Semgrep carries the CWE in `extra.metadata.cwe` (a string or a list like
    "CWE-89: SQL Injection"); we normalise it to a bare `CWE-###` so cross-confirmation matches our
    own bug_class.
    """
    data = json.loads(stdout) if stdout.strip() else {}
    out: list[Finding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe = _normalise_cwe(meta.get("cwe"))
        path = _rel(r.get("path", ""), root)
        start = (r.get("start") or {})
        line = start.get("line")
        col = start.get("col")
        check_id = r.get("check_id", "semgrep-rule")
        msg = extra.get("message") or meta.get("message") or check_id
        sev = _SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "medium")
        f = Finding(
            oracle="take:semgrep",
            bug_class=cwe,
            language="any",
            target=path,
            message=f"[semgrep {check_id}] {msg}",
            severity=sev,
            frames=[Frame(symbol=check_id, uri=path, line=line, column=col)],
        )
        f.add_fix_site(FixSite(uri=path, rank=0, start_line=line, symbol=check_id,
                               rationale=f"semgrep rule {check_id}"))
        # No reproducer: a static match stays SUSPECTED until one of our lanes confirms the site.
        out.append(f)
    return out


_OSV_OFFLINE_FLAGS: list[str] | None = None


def _osv_offline_flags() -> list[str]:
    """The offline flag this osv-scanner understands: `--offline` (v2) or `--experimental-offline`
    (v1, which rejects `--offline` and so would fail the lane). Read from its own help, once."""
    global _OSV_OFFLINE_FLAGS
    if _OSV_OFFLINE_FLAGS is None:
        try:
            out = subprocess.run(["osv-scanner", "scan", "--help"], capture_output=True, text=True,
                                 timeout=30)
            text = out.stdout + out.stderr
        except (OSError, subprocess.SubprocessError):
            text = ""
        v2 = "--offline" in text.replace("--experimental-offline", "")
        v1 = "--experimental-offline" in text
        _OSV_OFFLINE_FLAGS = ["--experimental-offline"] if v1 and not v2 else ["--offline"]
    return _OSV_OFFLINE_FLAGS


def _semgrep_rules() -> str:
    """Rules for the Semgrep lane: RAKSHA_SEMGREP_RULES when set, else the bundled offline ruleset
    (Semgrep's "auto" config downloads rules, which a sealed box cannot)."""
    from pathlib import Path
    return os.environ.get("RAKSHA_SEMGREP_RULES") or str(
        Path(__file__).parents[1] / "data" / "semgrep" / "raksha-offline.yml")


def _checkov_findings(stdout: str, root: str) -> list[Finding]:
    """Parse `checkov -o json`. A failed configuration check re-matches deterministically on the
    same file, so each enters as a confirmed DETERMINISTIC_MATCH (CWE-16, configuration)."""
    data = json.loads(stdout) if stdout.strip() else []
    reports = data if isinstance(data, list) else [data]
    out: list[Finding] = []
    for rep in reports:
        for r in (rep.get("results") or {}).get("failed_checks", []) or []:
            path = _rel(str(r.get("file_abs_path") or r.get("file_path", "")).lstrip("/"), root.lstrip("/"))
            lines = r.get("file_line_range") or [None]
            check = r.get("check_id", "CKV")
            name = r.get("check_name") or check
            out.append(_confirmed_match(
                oracle="take:checkov", cwe="CWE-16", language="any", path=path, line=lines[0],
                symbol=check, severity=str(r.get("severity") or "medium").lower(),
                message=f"[checkov {check}] {name} in {path}",
                fix_rationale="change the configuration to satisfy the check",
                signature=check, detail=f"checkov {check} failed at {path}",
                replay_cmd=["checkov", "-f", path, "--check", check]))
    return out


def _gitleaks_findings(stdout: str, root: str) -> list[Finding]:
    """Parse `gitleaks detect --report-format json`. A secret present at a location re-matches
    deterministically, so each hit enters as a confirmed DETERMINISTIC_MATCH (secret redacted)."""
    data = json.loads(stdout) if stdout.strip() else []
    out: list[Finding] = []
    for r in data:
        path = _rel(r.get("File", ""), root)
        line = r.get("StartLine")
        rule = r.get("RuleID", "gitleaks-rule")
        secret = r.get("Secret", "") or r.get("Match", "")
        redacted = _redact(secret)
        f = _confirmed_match(
            oracle="take:gitleaks",
            cwe="CWE-798",
            language="any",
            path=path,
            line=line,
            symbol=rule,
            severity="high",
            message=f"[gitleaks {rule}] hardcoded secret in {path}:{line} — {redacted}",
            fix_rationale="move the secret to a secret store / environment and rotate it",
            signature=rule,
            detail=f"gitleaks rule {rule} matched at {path}:{line} (secret redacted: {redacted})",
            replay_cmd=["gitleaks", "detect", "--no-git", "--source", path],
        )
        out.append(f)
    return out


def _osv_scanner_findings(stdout: str, root: str) -> list[Finding]:
    """Parse `osv-scanner --format json`. A dependency matched against a vuln DB re-matches
    deterministically, so each vulnerable package enters as a confirmed DETERMINISTIC_MATCH."""
    data = json.loads(stdout) if stdout.strip() else {}
    out: list[Finding] = []
    for res in data.get("results", []):
        source = (res.get("source", {}) or {}).get("path", "")
        manifest = _rel(source, root)
        for pkg in res.get("packages", []):
            info = pkg.get("package", {}) or {}
            name = info.get("name", "?")
            version = info.get("version", "?")
            for vuln in pkg.get("vulnerabilities", []):
                vid = vuln.get("id", "OSV")
                cwe = _normalise_cwe((vuln.get("database_specific", {}) or {}).get("cwe_ids"))
                summary = vuln.get("summary", "")
                f = _confirmed_match(
                    oracle="take:osv-scanner",
                    cwe=cwe,
                    language="any",
                    path=manifest,
                    line=None,
                    symbol=name,
                    severity="high",
                    message=f"[osv-scanner] {name}@{version} vulnerable per {vid}. {summary}".strip(),
                    fix_rationale=f"bump {name} past the affected range",
                    signature=vid,
                    detail=f"osv-scanner: {name}@{version} matches {vid}",
                    replay_cmd=["osv-scanner", "--format", "json", "-L", manifest],
                )
                out.append(f)
    return out


def _confirmed_match(*, oracle, cwe, language, path, line, symbol, severity, message,
                     fix_rationale, signature, detail, replay_cmd) -> Finding:
    """Build a CONFIRMED finding backed by DETERMINISTIC_MATCH evidence (shared by the
    re-matching take lanes), mirroring how `supply`/`secrets` shape their own confirmed findings."""
    f = Finding(
        oracle=oracle,
        bug_class=cwe,
        language=language,
        target=path,
        message=message,
        severity=severity,
        frames=[Frame(symbol=symbol, uri=path, line=line)],
    )
    f.add_fix_site(FixSite(uri=path, rank=0, start_line=line, symbol=symbol, rationale=fix_rationale))
    repro = Reproducer.from_bytes(
        f"{oracle}:{signature}@{path}:{line}".encode(), replay_cmd,
        artifact_path=path, minimised=True, kind=DETERMINISTIC_MATCH, detail=detail,
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=signature, exit_code=0))
    f.confirm(reason=f"{oracle} deterministically re-matched at this location")
    return f


_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _normalise_cwe(raw) -> str:
    """A bare `CWE-###` from semgrep/osv-scanner's varied CWE shapes (str, list, "CWE-89: …")."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not isinstance(raw, str):
        return "CWE-1104"
    token = raw.strip().upper()
    if token.startswith("CWE-"):
        return token.split(":", 1)[0].split()[0].rstrip(".,")
    return "CWE-1104"


def _redact(secret: str) -> str:
    if not secret:
        return "(redacted)"
    if len(secret) <= 8:
        return secret[0] + "…"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"


# ---------------------------------------------------------------- the lanes

#: argv builders kept here so a test (or an operator) can see exactly what each tool is invoked with.
LANES: tuple[TakeLane, ...] = (
    TakeLane("semgrep", "semgrep", "RAKSHA_TAKE_SEMGREP",
             lambda root: ["semgrep", "--quiet", "--json", "--metrics=off", "--disable-version-check",
                           "--config", _semgrep_rules(), root],
             _semgrep_findings),
    TakeLane("gitleaks", "gitleaks", "RAKSHA_TAKE_GITLEAKS",
             lambda root: ["gitleaks", "detect", "--no-git", "--report-format", "json",
                           "--report-path", "/dev/stdout", "--source", root],
             _gitleaks_findings),
    TakeLane("osv-scanner", "osv-scanner", "RAKSHA_TAKE_OSV_SCANNER",
             lambda root: ["osv-scanner", "--format", "json", "--recursive",
                           *(_osv_offline_flags() if _truthy(os.environ.get("RAKSHA_OSV_OFFLINE")) else []), root],
             _osv_scanner_findings),
    TakeLane("checkov", "checkov", "RAKSHA_TAKE_CHECKOV",
             lambda root: ["checkov", "-d", root, "-o", "json", "--quiet", "--compact",
                           "--skip-download", "--skip-results-upload"],
             lambda stdout, root: _checkov_findings(stdout, root)),
)

#: Env flag that enables every take lane at once, for the finale run where the tools are present.
_ENABLE_ALL = "RAKSHA_TAKE_ALL"


def available_lanes(enabled: set[str] | None = None) -> list[TakeLane]:
    """The take lanes that are both present on PATH and enabled right now."""
    want = set(enabled) if enabled is not None else None
    if want is None and _truthy(os.environ.get(_ENABLE_ALL)):
        want = {lane.tool for lane in LANES}
    return [lane for lane in LANES if lane.available(want)]


def run_take_lanes(root: str, *, enabled: set[str] | None = None) -> list[Finding]:
    """Run whichever take lanes are present+enabled over `root`; return their findings.

    The default — nothing installed, no flag set — is an empty list and no error, which is the state
    of the offline box. Findings are tagged by tool in their oracle (`take:<tool>`) and are intended
    to be fed into `gate.crossconfirm.cross_confirm` alongside RAKSHA's own findings: our lanes stay
    the floor, these only add independent corroboration.
    """
    findings: list[Finding] = []
    for lane in available_lanes(enabled):
        findings.extend(lane.scan(root))
    return findings


__all__ = ["TakeLane", "LANES", "available_lanes", "run_take_lanes"]
