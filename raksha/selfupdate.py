"""E6 — the signed self-update path for a sealed node.

New rule sets, a refreshed offline vuln DB, or a new RAKSHA version must be able to reach an
air-gapped node *without* opening a door an attacker can push through. The discipline here mirrors
the evidence bundle in reverse: an update is a directory of files plus a signed manifest of their
sha256 hashes. Nothing is applied until every hash recomputes and the signature verifies, so an
unsigned drop or a single flipped byte is refused before anything touches the destination.

  * ``sign_update(update_dir, key)``  — hash every file, write ``update.json`` + ``update.sig.json``.
  * ``verify_update(update_dir, key)`` — recompute + re-check; returns (ok, problems).
  * ``apply_update(update_dir, dest, key)`` — verify, then (and only then) copy files into ``dest``,
    backing up every file it overwrites and writing a rollback record. Refuses an unverified update.
  * ``rollback(dest, record)`` — restore ``dest`` to the exact prior bytes (hash-checked), deleting
    files the update newly created.

Signing reuses ``pqsign`` (post-quantum when the library is bundled, HMAC otherwise) over the
canonical manifest bytes — the same hashing/signing style as ``bundle.py``. Stdlib only; no network.
The backups live under ``dest/.raksha_backup/<id>/`` so a rollback is exact (hash-equal), not clever.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path

from . import pqsign

UPDATE_MANIFEST = "update.json"
UPDATE_SIG = "update.sig.json"
_BACKUP_DIR = ".raksha_backup"
_ROLLBACK_PREFIX = ".raksha_rollback"
#: Files that describe the update itself, never part of its payload.
_META = {UPDATE_MANIFEST, UPDATE_SIG}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _payload_files(update_dir: Path) -> list[str]:
    """Relative paths of every payload file in the update (metadata and backups excluded), sorted."""
    out: list[str] = []
    for p in sorted(update_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(update_dir).as_posix()
        if rel in _META or rel.split("/", 1)[0] in (_BACKUP_DIR,) \
                or rel.startswith(_ROLLBACK_PREFIX):
            continue
        out.append(rel)
    return out


def _manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, indent=2, sort_keys=True).encode()


def sign_update(update_dir: str | Path, key: bytes, *, version: str | None = None) -> Path:
    """Hash every payload file in ``update_dir`` and write a signed manifest. Returns the manifest
    path. ``key`` is the deployment update key (symmetric for HMAC; scopes the key id for PQ)."""
    up = Path(update_dir)
    files = _payload_files(up)
    hashes = {rel: _sha256_file(up / rel) for rel in files}
    manifest = {
        "kind": "raksha-update",
        "version": version or "unversioned",
        "files": hashes,
    }
    mbytes = _manifest_bytes(manifest)
    (up / UPDATE_MANIFEST).write_bytes(mbytes)
    signature = pqsign.sign(mbytes, key)
    signature["manifest_sha256"] = hashlib.sha256(mbytes).hexdigest()
    (up / UPDATE_SIG).write_text(json.dumps(signature, indent=2, sort_keys=True))
    return up / UPDATE_MANIFEST


def verify_update(update_dir: str | Path, key: bytes) -> tuple[bool, list[str]]:
    """Recompute every hash and re-check the signature. Returns (ok, problems).

    Refuses an update with no manifest or no signature (unsigned), a manifest whose bytes changed, a
    payload file that is missing or whose hash differs, a payload file not listed in the manifest,
    and a signature that does not verify under ``key``.
    """
    up = Path(update_dir)
    problems: list[str] = []
    if not (up / UPDATE_MANIFEST).is_file() or not (up / UPDATE_SIG).is_file():
        return False, ["UNSIGNED: missing update.json or update.sig.json"]
    try:
        mbytes = (up / UPDATE_MANIFEST).read_bytes()
        manifest = json.loads(mbytes)
        signature = json.loads((up / UPDATE_SIG).read_text())
        listed = manifest["files"]
        if not isinstance(manifest, dict) or not isinstance(signature, dict) \
                or not isinstance(listed, dict):
            raise ValueError("not the expected object shape")
    except (OSError, ValueError, KeyError) as e:
        return False, [f"MALFORMED manifest or signature ({e})"]

    recorded_msum = signature.get("manifest_sha256")
    if recorded_msum is not None and recorded_msum != hashlib.sha256(mbytes).hexdigest():
        problems.append("CHANGED update.json (manifest hash mismatch)")

    present = set(_payload_files(up))
    for rel, recorded_hash in listed.items():
        p = up / rel
        # reject path escapes and absolute paths outright
        if ".." in Path(rel).parts or Path(rel).is_absolute() or not p.is_file():
            problems.append(f"MISSING {rel}")
            continue
        if _sha256_file(p) != recorded_hash:
            problems.append(f"CHANGED {rel}")
    for extra in sorted(present - set(listed)):
        problems.append(f"UNEXPECTED {extra} (not in the signed manifest)")

    if not pqsign.verify(mbytes, signature, key):
        problems.append("SIGNATURE INVALID")

    return (not problems), problems


def apply_update(update_dir: str | Path, dest: str | Path, key: bytes) -> dict:
    """Verify then apply the update into ``dest``, returning a rollback record.

    Raises ``ValueError`` (refuses) if verification fails — nothing is touched. On success every file
    is copied into ``dest``; any file it overwrites is first backed up under
    ``dest/.raksha_backup/<id>/`` so the rollback is byte-exact. The record is both returned and
    written to ``dest/.raksha_rollback-<id>.json``.
    """
    up = Path(update_dir)
    dst = Path(dest)
    ok, problems = verify_update(up, key)
    if not ok:
        raise ValueError("refusing to apply an unverified update:\n  " + "\n  ".join(problems))

    manifest = json.loads((up / UPDATE_MANIFEST).read_bytes())
    files = sorted(manifest["files"])
    record_id = uuid.uuid4().hex[:12]
    backup_root = dst / _BACKUP_DIR / record_id
    entries: list[dict] = []

    for rel in files:
        target = dst / rel
        entry: dict = {"path": rel, "existed": target.is_file()}
        if target.is_file():
            entry["prior_sha256"] = _sha256_file(target)
            backup = backup_root / rel
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup)
            entry["backup"] = (Path(_BACKUP_DIR) / record_id / rel).as_posix()
        else:
            entry["prior_sha256"] = None
            entry["backup"] = None
        entries.append(entry)

    # Apply only after the full backup pass, so a rollback can always reach the prior state.
    for rel in files:
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(up / rel, target)

    record = {
        "id": record_id,
        "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dest": str(dst),
        "update_manifest_sha256": hashlib.sha256((up / UPDATE_MANIFEST).read_bytes()).hexdigest(),
        "backup_dir": (Path(_BACKUP_DIR) / record_id).as_posix(),
        "files": entries,
    }
    (dst / f"{_ROLLBACK_PREFIX}-{record_id}.json").write_text(
        json.dumps(record, indent=2, sort_keys=True))
    return record


def rollback(dest: str | Path, record: dict) -> tuple[bool, list[str]]:
    """Restore ``dest`` to the exact state captured in ``record``. Returns (ok, problems).

    Files that existed before are restored from their backup and re-hashed against the recorded prior
    hash (so a corrupted backup is caught); files the update newly created are removed. After a clean
    rollback every restored file is byte-identical to its pre-update content.
    """
    dst = Path(dest)
    problems: list[str] = []
    for entry in record.get("files", []):
        rel = entry["path"]
        target = dst / rel
        if entry.get("existed"):
            backup = dst / entry["backup"]
            if not backup.is_file():
                problems.append(f"MISSING BACKUP {rel}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, target)
            if _sha256_file(target) != entry.get("prior_sha256"):
                problems.append(f"RESTORE MISMATCH {rel}")
        else:
            if target.is_file():
                try:
                    target.unlink()
                except OSError as e:
                    problems.append(f"COULD NOT REMOVE {rel} ({e})")
    return (not problems), problems
