"""Git-history secrets lane — credentials that were committed and later removed.

The secrets lane (``secrets.py``) reads the working tree: what is checked out *now*. A credential
that was committed, noticed, and deleted is gone from the working tree but still sits in the repo's
history, recoverable by anyone with a clone — so it is still a live exposure until it is rotated.
This lane walks prior commits with ``git log`` / ``git show`` and re-runs the **same** secret rule
shapes over the lines each commit *added*, so a secret introduced-then-removed is still found, with
the commit hash and path as its location.

Division of labour with the working-tree lane (no double reporting): a secret still present in the
working tree is left to ``secrets.scan_text``; this lane excludes any history hit whose
``(value, path)`` is also present in the current tree. Dedup across history is by ``(value, path)``,
keeping the most recent commit that carried it.

What is measured vs heuristic
-----------------------------
*Measured*: the secret value, its rule classification (reused verbatim from ``secrets.py`` so the
CWE and rule id match the working-tree lane), the commit hash and the file path. The reproducer
replays by re-reading that exact blob with ``git show <commit>:<path>`` and re-matching.

*Heuristic*: the line number within the historical file is read from the diff hunk header and is
best-effort (``--unified=0``); the finding's identity is the commit+path+value, not the line.

Only subprocess is the local ``git`` binary. A root that is not a git repository (or has no
commits, or no ``git``) yields ``[]`` with no error.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow
from . import secrets

_GIT_TIMEOUT = 60


# ---------------------------------------------------------------- git shims

def _git(root: Path, args: list[str]) -> str | None:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                              timeout=_GIT_TIMEOUT, check=False)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _is_repo(root: Path) -> bool:
    return _git(root, ["rev-parse", "--git-dir"]) is not None


def git_show_file(root: str | Path, commit: str, path: str) -> str | None:
    """The contents of ``path`` as it was at ``commit`` (``git show <commit>:<path>``), or None."""
    return _git(Path(root), ["show", f"{commit}:{path}"])


# ---------------------------------------------------------------- raw secret extraction

def _raw_secrets(text: str, path: str) -> list[tuple[str, str, int, int]]:
    """Every secret in ``text`` as ``(rule_id, raw_value, line, col)``, reusing the secrets rules.

    Mirrors ``secrets.scan_text`` exactly (same rules, same placeholder/entropy/config gating) but
    returns the *raw* value — which the working-tree lane redacts and this lane needs for dedup.
    """
    out: list[tuple[str, str, int, int]] = []
    config = secrets._is_config(path)
    for i, line in enumerate(text.splitlines(), 1):
        claimed = False
        for rule in secrets._FORMAT_RULES:
            m = rule.pattern.search(line)
            if not m:
                continue
            value = m.group(1) if m.groups() else m.group(0)
            if m.groups() and (secrets._PLACEHOLDER.match(value) or value.endswith("EXAMPLE")):
                continue
            if rule.min_entropy and secrets._entropy(value) < rule.min_entropy:
                continue
            out.append((rule.id, value, i, m.start() + 1))
            claimed = True
        if claimed:
            continue
        for rule, min_len in secrets._ASSIGN_RULES:
            m = rule.pattern.search(line)
            if not m:
                continue
            value = secrets._assignment_value(m.group(1), config)
            if value is None or len(value) < min_len or secrets._entropy(value) < rule.min_entropy:
                continue
            out.append((rule.id, value, i, m.start() + 1))
            break
    return out


def _rule_by_id(rule_id: str) -> secrets.Rule | None:
    for rule in secrets._FORMAT_RULES:
        if rule.id == rule_id:
            return rule
    for rule, _ in secrets._ASSIGN_RULES:
        if rule.id == rule_id:
            return rule
    return None


# ---------------------------------------------------------------- the lane

def _working_tree_values(root: Path) -> set[tuple[str, str]]:
    """``(value, path)`` of every secret currently in the tracked working tree — left to secrets.py."""
    listing = _git(root, ["ls-files"])
    present: set[tuple[str, str]] = set()
    if not listing:
        return present
    for rel in listing.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        file = root / rel
        try:
            text = file.read_text(errors="replace")
        except OSError:
            continue
        for _rule_id, value, _line, _col in _raw_secrets(text, rel):
            present.add((value, rel))
    return present


def _added_lines(diff: str) -> list[tuple[str, int, str]]:
    """``(path, new_line_no, text)`` for every added line in a ``git show --unified=0`` diff."""
    added: list[tuple[str, int, str]] = []
    path = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif raw.startswith("@@"):
            # @@ -a,b +c,d @@  → next added line is c
            try:
                plus = raw.split("+", 1)[1].split()[0]
                new_line = int(plus.split(",")[0])
            except (IndexError, ValueError):
                new_line = 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            if path is not None:
                added.append((path, new_line, raw[1:]))
            new_line += 1
        elif not raw.startswith("-") and not raw.startswith("\\"):
            new_line += 1
    return added


def scan_git_history(root: str | Path, max_commits: int = 200) -> list[Finding]:
    """Secrets introduced in the last ``max_commits`` commits and not present in the working tree.

    Returns ``[]`` (no error) when ``root`` is not a git repository, has no commits, or ``git`` is
    unavailable.
    """
    root = Path(root)
    if not _is_repo(root):
        return []
    log = _git(root, ["log", f"--max-count={max_commits}", "--format=%H"])
    if not log:
        return []
    present = _working_tree_values(root)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()                 # (value, path) — most recent commit wins
    for commit in (c.strip() for c in log.splitlines() if c.strip()):
        diff = _git(root, ["show", "--no-color", "--format=", "--unified=0", commit])
        if not diff:
            continue
        by_file: dict[str, list[tuple[int, str]]] = {}
        for path, line_no, line in _added_lines(diff):
            by_file.setdefault(path, []).append((line_no, line))
        for path, lines in by_file.items():
            blob = "\n".join(text for _ln, text in lines)
            base = 0
            for rule_id, value, rel_line, col in _raw_secrets(blob, path):
                if (value, path) in present or (value, path) in seen:
                    continue
                seen.add((value, path))
                abs_line = lines[rel_line - 1][0] if 0 < rel_line <= len(lines) else base
                findings.append(_finding(rule_id, path, commit, abs_line, col, value))
    return findings


def _finding(rule_id: str, path: str, commit: str, line: int, col: int, value: str) -> Finding:
    rule = _rule_by_id(rule_id)
    cwe = rule.cwe if rule else "CWE-798"
    severity = rule.severity if rule else "high"
    desc = rule.description if rule else rule_id
    redacted = secrets._redact(value)
    short = commit[:12]
    f = Finding(
        oracle=f"githistory:{rule_id}",
        bug_class=cwe,
        language="any",
        target=path,
        message=(f"{desc} committed to git history at {path} (commit {short}) — {redacted}; "
                 "removed from the working tree but still recoverable from history"),
        severity=severity,
        frames=[Frame(symbol=rule_id, uri=path, line=line or None, column=col)],
        abort_signature=f"{rule_id}@{short}",
    )
    f.add_fix_site(FixSite(uri=path, rank=0, start_line=line or None, symbol=rule_id,
                           rationale="rotate the credential and purge it from history "
                                     "(git filter-repo / BFG); removing it from HEAD is not enough"))
    repro = Reproducer.from_bytes(
        f"{rule_id}@{commit}:{path}:{line}".encode(),
        ["raksha", "git-secret-match", rule_id, commit, path, str(line)],
        artifact_path=path, minimised=True, kind=DETERMINISTIC_MATCH,
        detail=f"{desc} matched in {path} at commit {short} (secret redacted: {redacted})",
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=f"{rule_id}@{short}", exit_code=0))
    f.confirm(reason="secret rule re-matches the blob recovered from git history at this commit")
    return f


def replay(rule_id: str, commit: str, path: str, root: str | Path = ".") -> bool:
    """Re-read ``path`` at ``commit`` via ``git show`` and re-run ``rule_id``. True = still present.

    The ``python -m raksha git-secret-match RULE COMMIT PATH [LINE]`` contract. Raises
    ``FileNotFoundError`` when the blob cannot be recovered (not a repo / unknown commit), which the
    CLI maps to exit 2 (could not run).
    """
    if _rule_by_id(rule_id) is None:
        raise ValueError(f"unknown secret rule {rule_id!r}")
    blob = git_show_file(root, commit, path)
    if blob is None:
        raise FileNotFoundError(f"{commit}:{path}")
    return any(rid == rule_id for rid, _v, _l, _c in _raw_secrets(blob, path))
