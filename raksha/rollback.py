"""Rollback scripts — nobody deploys a patch they cannot undo.

Every verified fix ships with a script that reverses it. A unified diff is reversible, so the
rollback is simply applying the patch in reverse (`git apply -R`, or `patch -R`). The script also
re-runs the target's own tests after reverting, so an operator sees the system is back to its prior
state. This is deliberately boring: a rollback that is clever is a rollback nobody trusts.
"""

from __future__ import annotations

import hashlib
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from .finding import Finding
from .replay import one_line

_SKIP = {".git", "__pycache__"}


def tree_hash(root: str | Path) -> str:
    """sha256 over every (relative path, content hash) pair under `root`, sorted — the identity of
    a tree. `.git` and RAKSHA's own `.raksha*` scratch files are excluded."""
    root = Path(root)
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or any(part in _SKIP or part.startswith(".raksha") for part in rel.parts):
            continue
        h.update(str(rel).encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def _touched(diff: str) -> list[str]:
    out = []
    for line in diff.splitlines():
        if line.startswith("--- a/"):
            out.append(line[6:].split("\t")[0].strip())
    return sorted(set(out))


def _apply(diff_path: Path, tree: Path, reverse: bool = False) -> bool:
    flag = ["-R"] if reverse else []
    for cmd in (["git", "apply", "-p1", *flag, str(diff_path)], ["patch", "-p1", *flag, "-i", str(diff_path)]):
        try:
            # raksha-own: applying a text diff to RAKSHA's scratch copy executes no target code
            if subprocess.run(cmd, cwd=str(tree), capture_output=True, timeout=60).returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def prove_rollback(source_root: str | Path, patch_diff: str) -> dict:
    """A5: apply the patch to a scratch copy, roll it back, and prove the tree is byte-identical to
    the original (tree hashes equal) while the patched tree differed. The per-file original hashes
    ride in the bundle so `rollback.sh` can check the operator's tree the same way."""
    src = Path(source_root)
    work = Path(tempfile.mkdtemp(prefix="raksha-rollback-")) / "t"
    try:
        shutil.copytree(src, work, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", ".raksha*"))
        files = {f: hashlib.sha256((work / f).read_bytes()).hexdigest()
                 for f in _touched(patch_diff) if (work / f).is_file()}
        original = tree_hash(work)
        diff_path = work.parent / "p.diff"
        diff_path.write_text(patch_diff)
        if not _apply(diff_path, work):
            return {"status": "not-applied", "original": original, "files": files}
        patched = tree_hash(work)
        if not _apply(diff_path, work, reverse=True):
            return {"status": "reverse-failed", "original": original, "patched": patched, "files": files}
        rolled = tree_hash(work)
        ok = rolled == original and patched != original
        return {"status": "proved" if ok else "refuted", "original": original, "patched": patched,
                "rolled_back": rolled, "files": files}
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)


def verify_rollback(tree: str | Path, proof: dict) -> bool:
    """True when `tree` is exactly the original the proof recorded — a tampered rollback is not."""
    return bool(proof) and tree_hash(tree) == proof.get("original")


def rollback_script(finding: Finding, *, test_cmd: str | None = None) -> str:
    """A shell script that reverses this finding's patch and confirms the revert."""
    if not finding.patch_diff:
        return "#!/usr/bin/env sh\n# no patch was applied for this finding; nothing to roll back\n"
    lines = [
        "#!/usr/bin/env sh",
        f"# Rollback for finding {one_line(finding.id)} ({one_line(finding.bug_class)})",
        "# Reverses the RAKSHA patch. Run from the target's root; the patch defaults to the",
        "# patch.diff shipped beside this script.",
        "set -eu",
        "",
        'HERE="$(cd "$(dirname "$0")" && pwd)"',
        'PATCH="${1:-$HERE/patch.diff}"',
        'echo "reverting $PATCH ..."',
        'if command -v git >/dev/null 2>&1; then',
        '    git apply -R --whitespace=nowarn "$PATCH"',
        "else",
        '    patch -R -p1 < "$PATCH"',
        "fi",
    ]
    files = (finding.rollback_proof or {}).get("files") or {}
    if files:
        # A5: the reverted files must hash to exactly what they were before the patch
        lines += ["", 'echo "checking the reverted files are byte-identical to the original ..."']
        lines += [f"echo {shlex.quote(h + '  ' + one_line(f))} | sha256sum -c -"
                  for f, h in sorted(files.items())]
    if test_cmd:
        lines += ["", 'echo "re-running the target\'s own tests after revert ..."', test_cmd]
    lines += ["", 'echo "rollback complete; the fix has been removed."', ""]
    return "\n".join(lines)
