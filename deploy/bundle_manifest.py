"""Offline bundle manifest — build, verify, and list the sealed-deployment bundle.

The bundle is what goes on the removable media: the orchestrator image, the model weights, the
dependency mirrors, the vuln DB, the compose files, this script. An air-gapped node cannot re-fetch
anything, so integrity is checked against a manifest of sha256 checksums on import. The manifest is
checksummed, not signed: it proves nothing was corrupted or swapped on the media *provided the
manifest's own hash is checked against a copy carried separately* (printed on the transfer record,
read aloud at handover). `verify` prints that hash for exactly this comparison. Production signs the
manifest with an offline cosign key; the check is otherwise identical. This is also the sneakernet
refresh format: a new manifest + changed files on media, verified here before they are trusted.

Usage:
  python3 bundle_manifest.py build  <bundle-dir>     write manifest.json (sha256 of every file)
  python3 bundle_manifest.py verify <bundle-dir>     fail if anything changed or is missing
  python3 bundle_manifest.py list   <bundle-dir>     show the manifest

No third-party dependencies — stdlib only, so it runs on a minimal sealed node.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

MANIFEST = "manifest.json"
_SKIP = {MANIFEST, ".DS_Store"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*")
                  if p.is_file() and p.name not in _SKIP and MANIFEST not in p.parts)


def build(root: Path) -> dict:
    entries = {str(p.relative_to(root)): {"sha256": _sha256(p), "bytes": p.stat().st_size}
               for p in _files(root)}
    manifest = {"version": 1, "files": entries, "count": len(entries),
                "total_bytes": sum(e["bytes"] for e in entries.values())}
    (root / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def verify(root: Path) -> list[str]:
    """Return a list of problems; empty means the bundle is intact."""
    mpath = root / MANIFEST
    if not mpath.exists():
        return [f"missing {MANIFEST}"]
    manifest = json.loads(mpath.read_text())
    recorded = manifest.get("files", {})
    problems: list[str] = []
    on_disk = {str(p.relative_to(root)) for p in _files(root)}
    for rel, meta in recorded.items():
        p = root / rel
        if not p.exists():
            problems.append(f"MISSING {rel}")
        elif _sha256(p) != meta["sha256"]:
            problems.append(f"CHANGED {rel}")
    for rel in on_disk - set(recorded):
        problems.append(f"UNEXPECTED {rel}")
    return problems


def _main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in {"build", "verify", "list"}:
        print(__doc__)
        return 2
    cmd, root = argv[1], Path(argv[2])
    if cmd == "build":
        m = build(root)
        print(f"manifest written: {m['count']} files, {m['total_bytes']} bytes")
        return 0
    if cmd == "list":
        print((root / MANIFEST).read_text())
        return 0
    problems = verify(root)
    if problems:
        print("BUNDLE VERIFICATION FAILED:")
        print("\n".join("  " + p for p in problems))
        return 1
    digest = hashlib.sha256((root / MANIFEST).read_bytes()).hexdigest()
    print("bundle verified: all files present and unchanged")
    print(f"manifest sha256: {digest}  <- compare with the copy on the transfer record")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
