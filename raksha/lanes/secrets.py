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


# ---- high-confidence formats: the token shape itself is the evidence, quoted or not ------------
_FORMAT_RULES = [
    Rule("aws-access-key-id", "CWE-798", "high",
         re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "AWS access key id"),
    Rule("aws-secret-access-key", "CWE-798", "critical",
         re.compile(r"(?i)aws_secret_access_key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
         "AWS secret access key", min_entropy=3.5),
    Rule("private-key-block", "CWE-321", "critical",
         re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"), "Private key committed in source"),
    Rule("github-token", "CWE-798", "critical",
         re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), "GitHub token"),
    Rule("gitlab-token", "CWE-798", "critical",
         re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), "GitLab personal access token"),
    Rule("slack-token", "CWE-798", "high",
         re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"), "Slack token"),
    Rule("slack-webhook", "CWE-798", "high",
         re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+)"),
         "Slack incoming webhook URL"),
    Rule("google-api-key", "CWE-798", "high",
         re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})(?![0-9A-Za-z\-_])"), "Google API key"),
    Rule("stripe-live-key", "CWE-798", "critical",
         re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), "Stripe live secret key"),
    Rule("sendgrid-key", "CWE-798", "high",
         re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "SendGrid API key"),
    Rule("url-credentials", "CWE-798", "high",
         re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@'\"]+:([^\s:/@'\"]{4,})@[^\s'\"]+"),
         "Credentials embedded in a connection URL"),
    Rule("jdbc-password", "CWE-798", "high",
         re.compile(r"(?i)jdbc:[^\s'\"]*password=([^\s'\"&;]{4,})"), "Password in JDBC URL"),
]

# ---- assignment rules: a credential-named key assigned a value ---------------------------------
# The key may carry a prefix (DB_PASS, spring.datasource.password, client_secret) and may itself be
# quoted ("password": ...), which covers JSON, YAML and dict literals. What counts as the VALUE is
# what keeps this precise — see `_assignment_value`.
_PASSWORD_KEY = r"(?:password|passwd|pwd|pass)"
_TOKEN_KEY = (r"(?:api[_.\-]?key|apikey|access[_.\-]?token|auth[_.\-]?token|secret[_.\-]?key|"
              r"client[_.\-]?secret|private[_.\-]?key|secret|token)")


def _assign(key: str) -> re.Pattern:
    return re.compile(r"(?i)(?<![\w])(?:[\w.\-]*[_.\-])?" + key + r"[\"']?\s*(?::=|=>|[=:])\s*(.+)$")


_ASSIGN_RULES = [
    (Rule("generic-password-assign", "CWE-798", "high", _assign(_PASSWORD_KEY),
          "Hardcoded password", min_entropy=2.5), 6),
    (Rule("generic-api-key", "CWE-798", "high", _assign(_TOKEN_KEY),
          "Hardcoded API key or token", min_entropy=3.0), 16),
]

#: Files where an unquoted value is a literal (config), as opposed to source code where an unquoted
#: value is an expression (a variable, a call, an environment lookup) and is never a secret itself.
_CONFIG_SUFFIX = {".properties", ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml",
                  ".tfvars", ".npmrc", ".pypirc", ".netrc", ".htpasswd"}
_CONFIG_NAMES = {".env", "credentials", ".npmrc", ".pypirc", ".netrc", "Dockerfile", ".git-credentials"}

#: Obvious placeholders that must never be reported — avoids the false positives that flood reviewers.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|changeme|change_me|example\w*|placeholder|your[_-]?\w+|<[^>]+>|\*+|\.+|test\w*|"
    r"dummy\w*|fake\w*|sample\w*|password\d*|passwd|secret|redacted|none|null|nil|true|false|"
    r"undefined|todo|fixme|tbd|xxx+|0+|1234\w*|abc\w*|foo\w*|bar)$")
#: Values that are references, not literals: ${VAR}, $VAR, %(x)s, {{ x }}, !vault, @Value refs, an
#: ALL_CAPS environment-variable name.
_REFERENCE = re.compile(r"^(?:\$|%\(|\{\{|!|@|ENC\(|vault:|secretsmanager:|arn:|[A-Z][A-Z0-9_]{2,}$)")
_TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|examples?|mocks?)/")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _is_config(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return name in _CONFIG_NAMES or suffix in _CONFIG_SUFFIX


def _assignment_value(rhs: str, config: bool) -> str | None:
    """The literal a credential key is assigned, or None if it is not a literal.

    In source code only a quoted string literal counts: `password = os.environ["X"]`,
    `token = make_token(user)` and `pwd = os.getcwd()` assign expressions, not secrets. In a config
    file an unquoted value is the literal itself, but a reference (`${DB_PASSWORD}`, an ALL_CAPS env
    name, a vault tag) is not.
    """
    rhs = rhs.strip()
    q = re.match(r"""^(?:[rbuf]{0,2})(["'`])([^"'`]*)\1""", rhs, re.I)
    if q:
        value = q.group(2)
    elif config:
        value = re.split(r"[\s#;,]", rhs, maxsplit=1)[0]
    else:
        return None
    value = value.strip()
    if not value or _REFERENCE.match(value) or _PLACEHOLDER.match(value):
        return None
    return value


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    config = _is_config(path)
    in_test = bool(_TEST_PATH.search("/" + path))
    for i, line in enumerate(text.splitlines(), 1):
        claimed = False
        for rule in _FORMAT_RULES:
            m = rule.pattern.search(line)
            if not m:
                continue
            secret = m.group(1) if m.groups() else m.group(0)
            # AWS publishes AKIA…EXAMPLE keys in its documentation; they are never live credentials.
            if m.groups() and (_PLACEHOLDER.match(secret) or secret.endswith("EXAMPLE")):
                continue
            if rule.min_entropy and _entropy(secret) < rule.min_entropy:
                continue
            findings.append(_finding(rule, path, i, m.start() + 1, secret, in_test))
            claimed = True
        if claimed:
            continue  # one credential, one finding: a format hit is not re-reported as an assignment
        for rule, min_len in _ASSIGN_RULES:
            m = rule.pattern.search(line)
            if not m:
                continue
            secret = _assignment_value(m.group(1), config)
            if secret is None or len(secret) < min_len or _entropy(secret) < rule.min_entropy:
                continue
            findings.append(_finding(rule, path, i, m.start() + 1, secret, in_test))
            break
    return findings


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return secret[0] + "…"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"


def _finding(rule: Rule, path: str, line: int, col: int, secret: str, in_test: bool = False) -> Finding:
    redacted = _redact(secret)
    # A secret in a test fixture is still committed, but it is far more often a dummy value: still
    # reported (it replays), ranked low so it never outranks a credential in production code.
    severity = "low" if in_test else rule.severity
    f = Finding(
        oracle=f"secrets:{rule.id}",
        bug_class=rule.cwe,
        language="any",
        target=path,
        message=f"{rule.description} in {path}:{line} — {redacted}",
        severity=severity,
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
