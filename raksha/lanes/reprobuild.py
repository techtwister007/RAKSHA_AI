"""Reproducible-build lane — build a target twice and compare the artifact hashes.

A build that is not reproducible — the same source and inputs yielding bit-different artifacts — is
a supply-chain signal: it means something uncontrolled (a timestamp, a path, a random seed, an
embedded build host) rode into the output, which is exactly the gap a build-time tampering attack
hides in. SLSA and the Reproducible Builds project treat bit-for-bit reproducibility as the baseline
that lets a third party verify an artifact came from the claimed source. This lane runs the given
build command twice over the same inputs and compares the SHA-256 of each produced artifact; a
mismatch is one CONFIRMED finding (CWE-1104), with the two differing hashes as its evidence.

Build-flavour-agnostic by design: it runs whatever ``build_cmd`` the caller gives (a list, or a
string run through the shell) and hashes whatever matches ``artifact_glob``. It assumes no specific
language or build system.

What is measured vs heuristic
-----------------------------
*Measured*: both artifact hashes, from two real builds this function ran; the mismatch is observed,
not predicted. The finding records both hashes and the first differing artifact.

*Honest degradation*: if the build command is absent (``build_cmd`` empty, tool not found), exits
non-zero on either run, or produces no artifact matching the glob, the function returns ``None`` — it
does not guess. Reproducibility is only *asserted* when two successful builds produce the identical
artifact set; a single failed build is "could not determine", never "reproducible".

The only subprocess is the caller's own build command, run in ``root``. Offline unless the build
itself reaches out (that is the caller's command, not this lane).
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow

_BUILD_TIMEOUT = 600


def _run_build(build_cmd, root: Path) -> bool:
    """Run the build once in ``root``. True if it exited 0; False on any failure (incl. missing tool)."""
    shell = isinstance(build_cmd, str)
    try:
        from ..sandbox import run_target   # a target's build runs its code (build scripts)
        raw = run_target(build_cmd, str(root), shell=shell, timeout=_BUILD_TIMEOUT)
        proc = subprocess.CompletedProcess(raw.args, raw.returncode,
                                           (raw.stdout or b"").decode("utf-8", "replace"),
                                           (raw.stderr or b"").decode("utf-8", "replace"))
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ValueError):
        return False
    return proc.returncode == 0


def _hash_artifacts(root: Path, artifact_glob: str) -> dict[str, str]:
    """``{relative path: sha256}`` for every file matching the glob under ``root`` (sorted, stable)."""
    out: dict[str, str] = {}
    for path in sorted(root.glob(artifact_glob)):
        if path.is_file():
            try:
                out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
    return out


def _remove(root: Path, rels) -> None:
    for rel in rels:
        try:
            (root / rel).unlink()
        except OSError:
            continue


def check_reproducible(root: str | Path, build_cmd, artifact_glob: str) -> Finding | None:
    """Build ``root`` twice and compare artifact hashes. A mismatch → one Finding; else ``None``.

    ``build_cmd`` is a command list or a shell string; ``artifact_glob`` is a ``Path.glob`` pattern
    (e.g. ``"dist/*.whl"``, ``"**/*.jar"``, ``"out.bin"``) resolved relative to ``root``. Returns
    ``None`` when reproducibility cannot be established (missing tool, failed build, no artifact) or
    when the two builds matched bit-for-bit.
    """
    root = Path(root)
    if not build_cmd or not root.exists():
        return None

    if not _run_build(build_cmd, root):
        return None
    first = _hash_artifacts(root, artifact_glob)
    if not first:
        return None                                    # nothing to compare: cannot determine
    _remove(root, first.keys())                        # force the second build to regenerate

    if not _run_build(build_cmd, root):
        return None
    second = _hash_artifacts(root, artifact_glob)
    if not second:
        return None

    mismatches = _diff(first, second)
    if not mismatches:
        return None                                    # reproducible on this run
    return _finding(str(root), artifact_glob, build_cmd, mismatches, first, second)


def _diff(first: dict[str, str], second: dict[str, str]) -> list[tuple[str, str, str]]:
    """Artifacts that differ between the two builds, as ``(path, sha_a, sha_b)``."""
    out: list[tuple[str, str, str]] = []
    for rel in sorted(set(first) | set(second)):
        a, b = first.get(rel), second.get(rel)
        if a != b:
            out.append((rel, a or "(absent)", b or "(absent)"))
    return out


def _finding(root: str, artifact_glob: str, build_cmd, mismatches, first, second) -> Finding:
    rel, sha_a, sha_b = mismatches[0]
    cmd_str = build_cmd if isinstance(build_cmd, str) else " ".join(build_cmd)
    detail = (f"non-reproducible build: {rel} differed across two builds from identical inputs "
              f"({sha_a[:12]}… vs {sha_b[:12]}…)")
    f = Finding(
        oracle="reprobuild:artifact-mismatch",
        bug_class="CWE-1104",
        language="any",
        target=rel,
        message=(f"Non-reproducible build: {len(mismatches)} artifact(s) differ across two builds "
                 f"from the same inputs — `{rel}` {sha_a[:12]}… vs {sha_b[:12]}…. An uncontrolled "
                 "input (timestamp, path, seed, build host) is embedded in the output, which "
                 "defeats third-party verification of provenance."),
        severity="medium",
        frames=[Frame(symbol="build-artifact", uri=rel, line=None)],
        abort_signature=f"{sha_a[:12]}!={sha_b[:12]}",
        raw_excerpt=f"build1={sha_a}\nbuild2={sha_b}",
    )
    f.add_fix_site(FixSite(uri=rel, rank=0, symbol="build-artifact",
                           rationale="make the build deterministic: honour SOURCE_DATE_EPOCH, strip "
                                     "timestamps/paths/build-host, pin and order inputs"))
    repro = Reproducer.from_bytes(
        f"{rel}::{sha_a}::{sha_b}".encode(),
        ["raksha", "reprobuild-check", root, "--build", cmd_str, "--artifacts", artifact_glob],
        artifact_path=rel, minimised=True, kind=DETERMINISTIC_MATCH, detail=detail,
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=f"{sha_a[:12]}!={sha_b[:12]}", exit_code=0))
    f.confirm(reason="two builds from identical inputs produced different artifact hashes (measured)")
    return f
