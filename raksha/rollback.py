"""Rollback scripts — nobody deploys a patch they cannot undo.

Every verified fix ships with a script that reverses it. A unified diff is reversible, so the
rollback is simply applying the patch in reverse (`git apply -R`, or `patch -R`). The script also
re-runs the target's own tests after reverting, so an operator sees the system is back to its prior
state. This is deliberately boring: a rollback that is clever is a rollback nobody trusts.
"""

from __future__ import annotations

from .finding import Finding


def rollback_script(finding: Finding, *, test_cmd: str | None = None) -> str:
    """A shell script that reverses this finding's patch and confirms the revert."""
    if not finding.patch_diff:
        return "#!/usr/bin/env sh\n# no patch was applied for this finding; nothing to roll back\n"
    lines = [
        "#!/usr/bin/env sh",
        f"# Rollback for finding {finding.id} ({finding.bug_class})",
        "# Reverses the RAKSHA patch and confirms the target is back to its prior state.",
        "set -eu",
        "",
        'PATCH="${1:-patch.diff}"',
        'echo "reverting $PATCH ..."',
        'if command -v git >/dev/null 2>&1; then',
        '    git apply -R --whitespace=nowarn "$PATCH"',
        "else",
        '    patch -R -p1 < "$PATCH"',
        "fi",
    ]
    if test_cmd:
        lines += ["", 'echo "re-running the target\'s own tests after revert ..."', test_cmd]
    lines += ["", 'echo "rollback complete; the fix has been removed."', ""]
    return "\n".join(lines)
