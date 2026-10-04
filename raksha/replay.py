"""Replay scripts — safe to run, and actually runnable.

A replay script is the evidence a judge executes. Its contents come partly from the scanned target
(file paths, package names, API paths), and a scanned repository is attacker-controlled input. So:

  - every argument is `shlex.quote`d — a path like `x$(touch /tmp/p)` stays a literal string;
  - every comment line is flattened to one line of printable text — a newline in a path cannot break
    out of a `#` comment into a command;
  - commands that name the `raksha` CLI run it as `python3 -m raksha`, which exists;
  - an exploit reproducer's bytes ship beside the script as `repro`, and the script copies them into
    the working directory, so the replay command's `repro` argument refers to a real file.

Run from the target's root (the paths in a deterministic-match replay are relative to it).
"""

from __future__ import annotations

import shlex

from .finding import EXPLOIT_REPLAY, Finding

#: Name the reproducer bytes ship under, inside a bundle or export folder.
REPRO_FILE = "repro"


def one_line(text: str | None, limit: int = 300) -> str:
    """Flatten untrusted text to a single printable line (no newlines / control characters)."""
    if not text:
        return ""
    flat = "".join(c if c.isprintable() else " " for c in text)
    flat = " ".join(flat.split())
    return flat[:limit]


def command_argv(finding: Finding) -> list[str]:
    """The replay argv, with the `raksha` CLI resolved to the module that implements it."""
    repro = finding.reproducer
    if repro is None:
        return []
    argv = list(repro.replay_cmd)
    if argv and argv[0] == "raksha":
        argv = ["python3", "-m", "raksha", *argv[1:]]
    return argv


def ships_bytes(finding: Finding) -> bool:
    repro = finding.reproducer
    return bool(repro and repro.kind == EXPLOIT_REPLAY and repro.data is not None)


def replay_script(finding: Finding) -> str:
    repro = finding.reproducer
    lines = [
        "#!/usr/bin/env sh",
        f"# Replay for finding {one_line(finding.id)} ({one_line(finding.bug_class)})",
        f"# Evidence: {one_line(repro.kind) if repro else 'none'}",
    ]
    if repro is None:
        return "\n".join(lines + ["# no reproducer", ""])
    if repro.detail:
        lines.append(f"# {one_line(repro.detail)}")
    lines += [
        "# Run from the target's root. A non-zero exit means the finding reproduced.",
        "set -u",
    ]
    if ships_bytes(finding):
        lines += ['HERE="$(cd "$(dirname "$0")" && pwd)"',
                  f'cp "$HERE/{REPRO_FILE}" ./{REPRO_FILE}']
    lines += [" ".join(shlex.quote(a) for a in command_argv(finding)), ""]
    return "\n".join(lines)
