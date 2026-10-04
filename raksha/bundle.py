"""The signed evidence bundle — the heart of the trust story.

Every VERIFIED finding produces one sealed, signed bundle: the reproducer reference and how to
replay it, before/after oracle output, the five gate results, the diff and its plain-English
explanation, the regression test, the rollback script, the ROE level and approver signatures, and
the model/prompt version, and the environment (interpreter, platform, toolchain versions) the
proof was produced in. We are not asking anyone to trust the AI — we are handing them the receipts.

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
from .replay import REPRO_FILE, replay_script, ships_bytes
from .rollback import rollback_script

MANIFEST = "bundle.json"
SIGNATURE = "signature.json"
_DEMO_KEY = b"raksha-demo-verification-key-v1"   # production replaces this with a cosign keypair


def signing_key() -> tuple[bytes, str]:
    """(key, key_id). A deployment provisions its own key (RAKSHA_BUNDLE_KEY_FILE); without one the
    published demo key is used and the bundle SAYS so — a demo-key signature only proves the bundle
    was not altered by someone who lacks this repository, and is labelled exactly that."""
    import os
    path = os.environ.get("RAKSHA_BUNDLE_KEY_FILE")
    if path and Path(path).is_file():
        key = Path(path).read_bytes().strip()
        return key, "deploy:" + hashlib.sha256(key).hexdigest()[:12]
    return _DEMO_KEY, "demo"


_ENV_CACHE: dict | None = None


def environment() -> dict:
    """The environment a replay must match: interpreter, platform and the toolchains the lanes
    drive. Probed once per process. A finding reproduced here and not there is a finding about
    the environment, and the record should let a reader tell the two apart."""
    global _ENV_CACHE
    if _ENV_CACHE is not None:
        return _ENV_CACHE
    import platform
    import shutil
    import subprocess
    tools = {}
    for name, argv in (("gcc", ["gcc", "--version"]), ("go", ["go", "version"]),
                       ("java", ["java", "-version"]), ("mvn", ["mvn", "-v"])):
        if shutil.which(argv[0]) is None:
            continue
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            first = (r.stdout or r.stderr).strip().splitlines()
            tools[name] = first[0][:120] if first else "present"
        except (OSError, subprocess.SubprocessError):
            tools[name] = "present (version probe failed)"
    _ENV_CACHE = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "toolchains": tools,
    }
    return _ENV_CACHE


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(hashes: dict[str, str], key: bytes) -> str:
    material = "\n".join(f"{k}={hashes[k]}" for k in sorted(hashes)).encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def build_bundle(finding: Finding, out_dir: str | Path, *, key: bytes | None = None,
                 tool_version: str = "0.1.0") -> Path:
    """Write a signed evidence bundle for a VERIFIED (or REPORT_ONLY) finding."""
    if not finding.is_reportable:
        raise ValueError("refusing to bundle an unreportable (SUSPECTED) finding")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key, key_id = (key, "caller") if key is not None else signing_key()

    artifacts: dict[str, bytes] = {
        "proof.json": json.dumps(finding.proof_block(), indent=2, sort_keys=True).encode(),
        "replay.sh": replay_script(finding).encode(),
        "report.md": (plain_summary(finding) + "\n").encode(),
        "commanders_brief.txt": jssd_brief(finding).encode(),
    }
    if ships_bytes(finding):
        artifacts[REPRO_FILE] = finding.reproducer.raw_bytes()  # the exploit itself (decompressed), so replay.sh runs
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
        "environment": environment(),
        "artifacts": hashes,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    (out / MANIFEST).write_bytes(manifest_bytes)

    signature = {
        "alg": "HMAC-SHA256",
        "key_id": key_id,
        "note": ("demo verification key: tamper-evident only against parties without the repository; "
                 "a deployment provisions RAKSHA_BUNDLE_KEY_FILE, production signs with cosign/in-toto")
                if key_id == "demo" else "deployment verification key",
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "signature": _sign({**hashes, MANIFEST: _sha256_bytes(manifest_bytes)}, key),
    }
    (out / SIGNATURE).write_text(json.dumps(signature, indent=2, sort_keys=True))
    return out


@dataclass
class VerifyResult:
    ok: bool
    problems: list[str]
    key_id: str = "demo"

    def summary(self) -> str:
        if not self.ok:
            return "VERIFICATION FAILED:\n" + "\n".join("  " + p for p in self.problems)
        note = " (demo key: proves no tampering by anyone without this repository)" \
            if self.key_id == "demo" else ""
        return "signature valid; every artifact present and unchanged" + note


def verify_bundle(bundle_dir: str | Path, *, key: bytes | None = None) -> VerifyResult:
    """Recompute every hash and re-check the signature. A single changed byte fails this, and so
    does any file in the bundle that the signed manifest does not list."""
    out = Path(bundle_dir)
    problems: list[str] = []
    if not (out / MANIFEST).exists() or not (out / SIGNATURE).exists():
        return VerifyResult(False, ["missing manifest or signature"])
    try:
        manifest_bytes = (out / MANIFEST).read_bytes()
        manifest = json.loads(manifest_bytes)
        signature = json.loads((out / SIGNATURE).read_text())
        if not isinstance(manifest, dict) or not isinstance(signature, dict) \
                or not isinstance(manifest.get("artifacts", {}), dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as e:
        return VerifyResult(False, [f"MALFORMED manifest or signature ({e})"])
    if key is None:
        key = _DEMO_KEY if signature.get("key_id", "demo") == "demo" else signing_key()[0]

    recomputed: dict[str, str] = {}
    listed = manifest.get("artifacts", {})
    for name, recorded_hash in listed.items():
        p = out / name
        if Path(name).name != name or not p.is_file():
            problems.append(f"MISSING {name}")
            continue
        actual = _sha256_bytes(p.read_bytes())
        recomputed[name] = actual
        if actual != recorded_hash:
            problems.append(f"CHANGED {name}")
    for extra in sorted(p.name for p in out.iterdir()
                        if p.name not in listed and p.name not in (MANIFEST, SIGNATURE)):
        problems.append(f"UNEXPECTED {extra} (not in the signed manifest)")

    manifest_hash = _sha256_bytes(manifest_bytes)
    if manifest_hash != signature.get("manifest_sha256"):
        problems.append("CHANGED bundle.json (manifest hash mismatch)")

    expected_sig = _sign({**recomputed, MANIFEST: manifest_hash}, key)
    if not hmac.compare_digest(expected_sig, str(signature.get("signature", ""))):
        problems.append("SIGNATURE INVALID")

    return VerifyResult(not problems, problems, key_id=str(signature.get("key_id", "demo")))
