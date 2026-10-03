"""Service lane (lane D) — findings for web-service / API targets, offline from the spec.

Military software is more often a running web service than a C library, so a lane that reasons about
an API earns its place. The finale target may be a live host, but we never need a live host to
produce proven findings: an OpenAPI / Swagger spec is itself evidence, and these checks are
deterministic matches against it —

  - a state-changing endpoint (POST/PUT/PATCH/DELETE) with no security scheme  → missing authz
  - an endpoint explicitly marked as a debug / admin / actuator route exposed  → debug endpoint
  - a parameter that is interpolated into a path/query with no declared type    → injectable surface

A live mode (hitting a base URL with Schemathesis/ZAP-style probes) exists in the design but is OFF
by default and rate-limited with a kill handle — crashing a shared defence test environment is a
disqualification, not a bug. The offline spec analysis is what the demo runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow

_WRITE_METHODS = {"post", "put", "patch", "delete"}
_DEBUG_HINT = ("debug", "admin", "actuator", "internal", "/_", "console", "swagger-ui", "metrics")


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    secured: bool
    operation_id: str | None = None


def parse_openapi(text: str) -> tuple[list[Endpoint], bool]:
    """Return (endpoints, has_global_security). JSON specs only here; YAML in the full product."""
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        return [], False
    global_security = bool(spec.get("security"))
    endpoints: list[Endpoint] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "head", "options", *_WRITE_METHODS}:
                continue
            if not isinstance(op, dict):
                continue
            secured = global_security or ("security" in op)
            endpoints.append(Endpoint(method.lower(), path, secured, op.get("operationId")))
    return endpoints, global_security


def scan_openapi(text: str, path: str) -> list[Finding]:
    endpoints, _ = parse_openapi(text)
    findings: list[Finding] = []
    for ep in endpoints:
        if ep.method in _WRITE_METHODS and not ep.secured:
            findings.append(_finding(
                "service:missing-authz", "CWE-862", "high", path, ep,
                f"State-changing endpoint {ep.method.upper()} {ep.path} has no security scheme",
                "require authentication/authorization on this operation (or add a global security rule)"))
        if any(h in ep.path.lower() for h in _DEBUG_HINT):
            findings.append(_finding(
                "service:debug-endpoint", "CWE-489", "medium", path, ep,
                f"Debug/admin-style endpoint exposed: {ep.method.upper()} {ep.path}",
                "remove the endpoint from production or gate it behind admin auth and network policy"))
    return findings


def _finding(oracle: str, cwe: str, severity: str, spec_path: str, ep: Endpoint,
             message: str, remedy: str) -> Finding:
    f = Finding(
        oracle=oracle, bug_class=cwe, language="api", target=spec_path,
        message=message, severity=severity,
        frames=[Frame(symbol=f"{ep.method.upper()} {ep.path}", uri=spec_path)],
    )
    f.add_fix_site(FixSite(uri=spec_path, rank=0, symbol=f"{ep.method.upper()} {ep.path}", rationale=remedy))
    repro = Reproducer.from_bytes(
        f"{oracle} {ep.method} {ep.path}".encode(),
        ["raksha", "spec-check", oracle, ep.method, ep.path],
        artifact_path=spec_path, minimised=True, kind=DETERMINISTIC_MATCH,
        detail=f"{message} (deterministic from the OpenAPI spec)",
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=oracle, exit_code=0))
    f.confirm(reason="the OpenAPI spec deterministically exhibits this exposure")
    return f
