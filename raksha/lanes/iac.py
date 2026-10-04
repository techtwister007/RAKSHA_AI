"""Infrastructure-as-code lane — a deterministic hardening floor over Docker / compose / k8s.

Our own checks, no external scanner, for the hardening misses that show up again and again in
container and orchestration config: a container running as **root**, a **privileged** container,
**host network** / **host PID** namespace sharing, an admin service **bound to 0.0.0.0** to the
world, and **`latest` image tags** (an unpinned, mutable base image). Each hit is one CONFIRMED
finding with a config CWE (CWE-16 misconfiguration, CWE-250 execution with unnecessary privileges,
CWE-1188 insecure default) and a replaying ``["raksha","iac-match",…]`` reproducer that re-reads the
file and re-matches.

What is measured vs heuristic
-----------------------------
*Measured*: every finding is a deterministic re-match of a rule against a specific line of a
specific file; the reproducer replays it. File classification (Dockerfile / compose / k8s) is by
name and by structural markers (``apiVersion:``+``kind:`` for k8s, ``services:`` for compose), so a
plain application config (e.g. a Spring ``application.yml``) is never scanned and never flags.

*Heuristic*: admin-port exposure uses a curated set of well-known management/database ports; a
custom admin port on a non-standard number is not caught. The ``latest``/untagged check skips
multi-stage ``FROM`` aliases and ``scratch``. ``USER root`` fires only when it is the *effective*
(last) user, so a transient privileged build step that later drops privileges is not flagged.

Stdlib only (regex, no YAML dependency — this runs with no network and no build), deterministic. A
root with no IaC files yields ``[]``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow

_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}
_MAX_FILE_BYTES = 2_000_000

#: Well-known management / database / orchestration ports that should not face the world.
ADMIN_PORTS = {22, 23, 2375, 2376, 2379, 2380, 3306, 5432, 5984, 6379, 6443, 8086, 9200, 9300,
               10250, 11211, 15672, 27017, 27018}

DOCKERFILE, COMPOSE, K8S = "dockerfile", "compose", "k8s"


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    severity: str
    kinds: frozenset
    pattern: re.Pattern
    rationale: str
    #: If set, the capture group named here must parse to an int in ADMIN_PORTS for the rule to fire.
    port_group: str | None = None


_RULES: list[Rule] = [
    Rule("privileged-container", "CWE-250", "critical", frozenset({COMPOSE, K8S}),
         re.compile(r"(?i)\bprivileged\s*:\s*true\b"),
         "privileged container: all Linux capabilities and host device access — a container escape "
         "becomes a host compromise"),
    Rule("host-network", "CWE-16", "high", frozenset({COMPOSE, K8S}),
         re.compile(r"(?i)\b(?:hostNetwork\s*:\s*true|network_mode\s*:\s*[\"']?host\b)"),
         "host network namespace: the container shares the host's network stack, bypassing network "
         "isolation and policy"),
    Rule("host-pid", "CWE-16", "high", frozenset({COMPOSE, K8S}),
         re.compile(r"(?i)\b(?:hostPID\s*:\s*true|pid\s*:\s*[\"']?host\b)"),
         "host PID namespace: the container can see and signal host processes, breaking process "
         "isolation"),
    Rule("run-as-root-k8s", "CWE-250", "high", frozenset({K8S}),
         re.compile(r"(?i)\b(?:runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false\b)"),
         "container configured to run as root (runAsUser: 0 / runAsNonRoot: false): a compromise "
         "runs with uid 0 inside the container"),
    Rule("run-as-root-compose", "CWE-250", "high", frozenset({COMPOSE}),
         re.compile(r"(?i)^\s*user\s*:\s*[\"']?(?:root|0)\b"),
         "service configured to run as root (user: root): a compromise runs with uid 0"),
    Rule("latest-image-tag", "CWE-1188", "medium", frozenset({COMPOSE, K8S}),
         re.compile(r"(?i)\bimage\s*:\s*[\"']?\S+:latest\b"),
         "`latest` image tag: an unpinned, mutable base image — the running image is not what was "
         "reviewed and cannot be verified"),
    Rule("world-exposed-admin-port", "CWE-16", "high", frozenset({COMPOSE}),
         re.compile(r"0\.0\.0\.0:(?P<port>\d+):"),
         "admin/database port bound to 0.0.0.0: a management service is reachable from every "
         "network interface, i.e. the world", port_group="port"),
    Rule("world-exposed-admin-port", "CWE-16", "high", frozenset({K8S}),
         re.compile(r"(?i)\bhostPort\s*:\s*(?P<port>\d+)\b"),
         "admin/database port published on the node via hostPort: a management service is reachable "
         "on every node interface", port_group="port"),
]

# Dockerfile instructions handled with file-level logic rather than a single line regex.
_USER = re.compile(r"(?i)^\s*USER\s+(\S+)")
_FROM = re.compile(r"(?i)^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?", re.I)
_EXPOSE = re.compile(r"(?i)^\s*EXPOSE\s+(.+)$")


# ---------------------------------------------------------------- classification

def classify(name: str, text: str) -> str | None:
    """Which IaC kind this file is, or None if it is not infrastructure-as-code we scan."""
    low = name.lower()
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith((".dockerfile",)):
        return DOCKERFILE
    if low.endswith((".yml", ".yaml")):
        if re.search(r"(?m)^\s*apiVersion\s*:", text) and re.search(r"(?m)^\s*kind\s*:", text):
            return K8S
        if (low.startswith(("docker-compose", "compose")) or re.search(r"(?m)^\s*services\s*:", text)):
            return COMPOSE
    return None


# ---------------------------------------------------------------- scanning

def scan_text(text: str, path: str) -> list[Finding]:
    name = path.rsplit("/", 1)[-1]
    kind = classify(name, text)
    if kind is None:
        return []
    if kind == DOCKERFILE:
        return _scan_dockerfile(text, path)
    return _scan_yaml(text, path, kind)


def _scan_yaml(text: str, path: str, kind: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for rule in _RULES:
            if kind not in rule.kinds:
                continue
            m = rule.pattern.search(line)
            if not m:
                continue
            if rule.port_group is not None:
                try:
                    port = int(m.group(rule.port_group))
                except (ValueError, IndexError):
                    continue
                if port not in ADMIN_PORTS:
                    continue
            findings.append(_finding(rule, path, i, m.start() + 1, line.strip()))
    return findings


def _scan_dockerfile(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    users: list[tuple[int, str]] = []
    stages: set[str] = set()
    first_instr = None
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if first_instr is None:
            first_instr = i
        mu = _USER.match(raw)
        if mu:
            users.append((i, mu.group(1).strip().strip('"\'')))
        mf = _FROM.match(raw)
        if mf:
            ref, alias = mf.group(1), mf.group(2)
            if alias:
                stages.add(alias.lower())
            findings.extend(_from_findings(ref, path, i, raw.strip(), stages))
        me = _EXPOSE.match(raw)
        if me:
            findings.extend(_expose_findings(me.group(1), path, i, raw.strip()))

    rule_root = _dockerfile_rule("container-runs-as-root", "CWE-250", "high",
                                 "container runs as root: no non-root USER is set, so the process "
                                 "runs as uid 0 — a compromise owns the container")
    if users:
        last_line, last_user = users[-1]
        if last_user in ("root", "0"):
            findings.append(_finding(rule_root, path, last_line, 1, "USER " + last_user))
    elif first_instr is not None:
        findings.append(_finding(rule_root, path, first_instr, 1, "(no USER directive)"))
    return findings


def _from_findings(ref: str, path: str, line: int, text: str, stages: set) -> list[Finding]:
    low = ref.lower()
    if low in stages or low == "scratch":
        return []
    rule = _dockerfile_rule("latest-image-tag", "CWE-1188", "medium",
                            "`latest` (or untagged) base image: an unpinned, mutable image — the "
                            "running image is not what was reviewed and cannot be verified")
    if low.endswith(":latest"):
        return [_finding(rule, path, line, 1, text)]
    base = ref.split("@", 1)[0]                          # a @sha256 digest is a pin
    tagged = ":" in base.rsplit("/", 1)[-1]
    if "@" not in ref and not tagged:
        return [_finding(rule, path, line, 1, text)]
    return []


def _expose_findings(spec: str, path: str, line: int, text: str) -> list[Finding]:
    rule = _dockerfile_rule("world-exposed-admin-port", "CWE-16", "high",
                            "admin/database port EXPOSEd: a management service is published from the "
                            "container — do not expose management ports")
    out: list[Finding] = []
    seen: set[int] = set()
    for tok in re.split(r"[\s,]+", spec.strip()):
        m = re.match(r"(\d+)", tok)
        if not m:
            continue
        port = int(m.group(1))
        if port in ADMIN_PORTS and port not in seen:
            seen.add(port)
            out.append(_finding(rule, path, line, 1, text))
    return out


def _dockerfile_rule(rule_id: str, cwe: str, severity: str, rationale: str) -> Rule:
    return Rule(rule_id, cwe, severity, frozenset({DOCKERFILE}), re.compile(r"(?!x)x"), rationale)


# ---------------------------------------------------------------- finding + replay

def _finding(rule: Rule, path: str, line: int, col: int, excerpt: str) -> Finding:
    short = excerpt[:80]
    f = Finding(
        oracle=f"iac:{rule.id}",
        bug_class=rule.cwe,
        language="config",
        target=path,
        message=f"{rule.rationale.split(':')[0]} — `{short}` at {path}:{line}",
        severity=rule.severity,
        frames=[Frame(symbol=rule.id, uri=path, line=line, column=col)],
        raw_excerpt=short,
    )
    f.add_fix_site(FixSite(uri=path, rank=0, start_line=line, symbol=rule.id, rationale=rule.rationale))
    repro = Reproducer.from_bytes(
        f"{rule.id}@{path}:{line}".encode(),
        ["raksha", "iac-match", rule.id, path, str(line)],
        artifact_path=path, minimised=True, kind=DETERMINISTIC_MATCH,
        detail=f"{rule.id} ({rule.cwe}) matched `{short}` at {path}:{line}",
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=rule.id, exit_code=0))
    f.confirm(reason="IaC hardening rule deterministically re-matches at this location")
    return f


# ---------------------------------------------------------------- the lane

def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
            yield path


def scan_iac(root: str | Path) -> list[Finding]:
    """Scan every Dockerfile / compose / k8s manifest under ``root`` for hardening misses."""
    root = Path(root)
    findings: list[Finding] = []
    for path in _walk(root):
        rel = str(path.relative_to(root)) if path != root else path.name
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, rel))
    return findings


def replay(rule_id: str, path: str, line: int, root: str | Path = ".") -> bool:
    """Re-read ``root/path`` and re-run the IaC checks; True if ``rule_id`` still matches at ``line``.

    The ``python -m raksha iac-match RULE PATH LINE`` contract: True → exit 1 (reproduced), False →
    exit 0, FileNotFoundError → exit 2. The whole file is re-scanned because several rules are
    file-level (effective USER, multi-stage FROM aliases).
    """
    file = Path(root) / path
    if not file.exists():
        raise FileNotFoundError(str(file))
    text = file.read_text(errors="replace")
    want = f"iac:{rule_id}"
    return any(f.oracle == want and f.frames and f.frames[0].line == line
               for f in scan_text(text, path))
