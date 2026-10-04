"""The signed evidence bundle — the heart of the trust story.

Every VERIFIED finding produces one sealed, signed bundle: the reproducer reference and how to
replay it, before/after oracle output, the five gate results, the diff and its plain-English
explanation, the regression test, the rollback script, the ROE level and approver signatures, and
the model/prompt version. We are not asking anyone to trust the AI — we are handing them the
receipts.

Signing: each artifact is content-addressed (sha256), and the manifest of those hashes is signed so
the whole bundle is tamper-evident. Here the signature is an HMAC-SHA256 over the sorted hashes with
a deployment verification key (stdlib only, so it runs on a minimal sealed node and a judge can
verify it live with the carried key). The production deployment signs with cosign / in-toto
(asymmetric, offline); the structure and the verify step are identical, only the primitive changes.

`verify_bundle()` recomputes every hash and re-checks the signature, so a single changed byte is
detected. That is the live check a judge performs at the Evidence Vault.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .brief import jssd_brief, plain_summary
from .finding import Finding, Status
from .rollback import rollback_script

MANIFEST = "bundle.json"
SIGNATURE = "signature.json"
_DEMO_KEY = b"raksha-demo-verification-key-v1"   # production replaces this with a cosign keypair


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(hashes: dict[str, str], key: bytes) -> str:
    material = "\n".join(f"{k}={hashes[k]}" for k in sorted(hashes)).encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def build_bundle(finding: Finding, out_dir: str | Path, *, key: bytes = _DEMO_KEY,
                 tool_version: str = "0.1.0") -> Path:
    """Write a signed evidence bundle for a VERIFIED (or REPORT_ONLY) finding."""
    if not finding.is_reportable:
        raise ValueError("refusing to bundle an unreportable (SUSPECTED) finding")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, bytes] = {
        "proof.json": json.dumps(finding.proof_block(), indent=2, sort_keys=True).encode(),
        "replay.sh": _replay_script(finding).encode(),
        "report.md": (plain_summary(finding) + "\n").encode(),
        "commanders_brief.txt": jssd_brief(finding).encode(),
    }
    if finding.status is Status.VERIFIED and finding.patch_diff:
        artifacts["patch.diff"] = finding.patch_diff.encode()
        artifacts["rollback.sh"] = rollback_script(finding).encode()
    if finding.regression_test:
        artifacts["regression_test"] = finding.regression_test.encode()

    for name, data in artifacts.items():
        (out / name).write_bytes(data)

    hashes = {name: _sha256_bytes(data) for name, data in artifacts.items()}
    manifest = {
        "tool": "RAKSHA AI", "version": tool_version,
        "finding_id": finding.id, "bug_class": finding.bug_class, "status": finding.status.value,
        "target": finding.target, "roe_level": finding.roe_level.value,
        "approver_signatures": [{"signer": s.signer, "key_id": s.key_id} for s in finding.signatures],
        "artifacts": hashes,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    (out / MANIFEST).write_bytes(manifest_bytes)

    signature = {
        "alg": "HMAC-SHA256",
        "note": "demo verification key; production signs with cosign/in-toto (asymmetric, offline)",
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "signature": _sign({**hashes, MANIFEST: _sha256_bytes(manifest_bytes)}, key),
    }
    (out / SIGNATURE).write_text(json.dumps(signature, indent=2, sort_keys=True))
    return out


@dataclass
class VerifyResult:
    ok: bool
    problems: list[str]

    def summary(self) -> str:
        return "signature valid; every artifact present and unchanged" if self.ok \
            else "VERIFICATION FAILED:\n" + "\n".join("  " + p for p in self.problems)


def verify_bundle(bundle_dir: str | Path, *, key: bytes = _DEMO_KEY) -> VerifyResult:
    """Recompute every hash and re-check the signature. A single changed byte fails this."""
    out = Path(bundle_dir)
    problems: list[str] = []
    if not (out / MANIFEST).exists() or not (out / SIGNATURE).exists():
        return VerifyResult(False, ["missing manifest or signature"])

    manifest_bytes = (out / MANIFEST).read_bytes()
    manifest = json.loads(manifest_bytes)
    signature = json.loads((out / SIGNATURE).read_text())

    recomputed: dict[str, str] = {}
    for name, recorded_hash in manifest.get("artifacts", {}).items():
        p = out / name
        if not p.exists():
            problems.append(f"MISSING {name}")
            continue
        actual = _sha256_bytes(p.read_bytes())
        recomputed[name] = actual
        if actual != recorded_hash:
            problems.append(f"CHANGED {name}")

    manifest_hash = _sha256_bytes(manifest_bytes)
    if manifest_hash != signature.get("manifest_sha256"):
        problems.append("CHANGED bundle.json (manifest hash mismatch)")

    expected_sig = _sign({**recomputed, MANIFEST: manifest_hash}, key)
    if not hmac.compare_digest(expected_sig, signature.get("signature", "")):
        problems.append("SIGNATURE INVALID")

    return VerifyResult(not problems, problems)


def _replay_script(finding: Finding) -> str:
    repro = finding.reproducer
    cmd = " ".join(repro.replay_cmd) if repro else "# no reproducer"
    detail = (repro.detail or "") if repro else ""
    return (f"#!/usr/bin/env sh\n# Replay for finding {finding.id} ({finding.bug_class})\n"
            f"# Evidence: {repro.kind if repro else 'none'}\n# {detail}\n{cmd}\n")
