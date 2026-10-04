"""Secrets lane — hardcoded credentials, in any file, with no build.

Gitleaks-style regex detectors over text files. A hit is confirmed by deterministic match: the
secret is present at a precise location and the detector re-matches. We never exfiltrate or test
the credential — the evidence is its presence, redacted in the record.

Military software is more often a web app with a hardcoded password than a C parser with a heap
overflow, so this lane earns its place on real targets regardless of language.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    severity: str
    pattern: re.Pattern
    description: str
    min_entropy: float = 0.0  # if >0, the captured group must look random enough


_RULES = [
    Rule("aws-access-key-id", "CWE-798", "high",
         re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS access key id"),
    Rule("aws-secret-access-key", "CWE-798", "critical",
         re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
         "AWS secret access key", min_entropy=3.5),
    Rule("private-key-block", "CWE-321", "critical",
         re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
         "Private key committed in source"),
    # Quotes optional, so unquoted properties/env assignments (db.password=S3cr3t...) are caught
    # too. The entropy and placeholder guards keep this from flooding reviewers with false hits.
    Rule("generic-password-assign", "CWE-798", "high",
         re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\s]{8,})['\"]?"),
         "Hardcoded password", min_entropy=3.0),
    Rule("generic-api-key", "CWE-798", "high",
         re.compile(r"(?i)(?:api[._-]?key|apikey|access[._-]?token|auth[._-]?token|secret|token)"
                    r"\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"),
         "Hardcoded API key or token", min_entropy=3.0),
    Rule("jdbc-password", "CWE-798", "high",
         re.compile(r"(?i)jdbc:[^\s'\"]*password=([^\s'\"&]{4,})"), "Password in JDBC URL"),
]

#: Obvious placeholders that must never be reported — avoids the false positives that flood reviewers.
_PLACEHOLDER = re.compile(r"(?i)^(?:x{3,}|changeme|example|placeholder|your[_-]?\w+|<[^>]+>|\*+|\.+|test|dummy|password|secret|redacted|none|null)$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        for rule in _RULES:
            m = rule.pattern.search(line)
            if not m:
                continue
            secret = m.group(1) if m.groups() else m.group(0)
            if m.groups() and _PLACEHOLDER.match(secret):
                continue
            if rule.min_entropy and _entropy(secret) < rule.min_entropy:
                continue
            findings.append(_finding(rule, path, i, m.start() + 1, secret))
    return findings


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return secret[0] + "…"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"


def _finding(rule: Rule, path: str, line: int, col: int, secret: str) -> Finding:
    redacted = _redact(secret)
    f = Finding(
        oracle=f"secrets:{rule.id}",
        bug_class=rule.cwe,
        language="any",
        target=path,
        message=f"{rule.description} in {path}:{line} — {redacted}",
        severity=rule.severity,
        frames=[Frame(symbol=rule.id, uri=path, line=line, column=col)],
    )
    f.add_fix_site(FixSite(uri=path, rank=0, start_line=line, symbol=rule.id,
                           rationale="move the secret to a secret store / environment and rotate it"))
    repro = Reproducer.from_bytes(
        f"{rule.id}@{path}:{line}".encode(),
        ["raksha", "secret-match", rule.id, path, str(line)],
        artifact_path=path, minimised=True, kind=DETERMINISTIC_MATCH,
        detail=f"{rule.description} matched at {path}:{line} (secret redacted: {redacted})",
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=rule.id, exit_code=0))
    f.confirm(reason="secret pattern deterministically re-matches at this location")
    return f
