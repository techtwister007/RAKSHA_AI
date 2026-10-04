"""Public-key signatures with Sigstore cosign — an additional seal on evidence bundles and reports.

The built-in HMAC signature is symmetric: whoever can verify can also sign. cosign adds a public-key
signature: the private key stays on the sealed box, and anyone holding only the public key can verify
but never forge. It is additive and optional, used only when

    * the `cosign` binary is on PATH, and
    * RAKSHA_COSIGN_KEY names a cosign private key (made by ``python -m raksha.cosign init DIR``,
      or ``cosign generate-key-pair``); COSIGN_PASSWORD supplies its password.

Fully offline: ``--tlog-upload=false`` and no transparency-log lookup on verify. Without cosign or
a key, nothing changes and nothing fails — the HMAC seal still stands.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

SIG_FILE = "signature.cosign"


def available() -> bool:
    return shutil.which("cosign") is not None and bool(os.environ.get("RAKSHA_COSIGN_KEY"))


def _env() -> dict:
    env = dict(os.environ)
    env.setdefault("COSIGN_PASSWORD", "")
    return env


def sign_file(path: str | Path, out_sig: str | Path) -> bool:
    """Sign `path` with RAKSHA_COSIGN_KEY into `out_sig` (base64). False when unavailable or failed."""
    if not available():
        return False
    # raksha-own: signing RAKSHA's own manifest with a local tool; no target code, no network
    r = subprocess.run(["cosign", "sign-blob", "--yes", "--tlog-upload=false",
                        "--key", os.environ["RAKSHA_COSIGN_KEY"], "--output-signature", str(out_sig),
                        str(path)], capture_output=True, text=True, timeout=60, env=_env())
    return r.returncode == 0 and Path(out_sig).is_file()


def verify_file(path: str | Path, sig: str | Path, pubkey: str | Path) -> bool:
    if shutil.which("cosign") is None:
        return False
    # raksha-own: verifying a signature locally; no network (no transparency-log lookup)
    r = subprocess.run(["cosign", "verify-blob", "--insecure-ignore-tlog=true", "--key", str(pubkey),
                        "--signature", str(sig), str(path)], capture_output=True, text=True,
                       timeout=60, env=_env())
    return r.returncode == 0


def init(directory: str | Path) -> dict:
    """Generate a cosign key pair in `directory` (cosign.key private, cosign.pub public)."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    if (d / "cosign.key").exists():
        raise FileExistsError(f"{d / 'cosign.key'} already exists")
    # raksha-own: key generation on this machine
    r = subprocess.run(["cosign", "generate-key-pair"], cwd=str(d), capture_output=True, text=True,
                       timeout=60, env=_env())
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[-300:])
    os.chmod(d / "cosign.key", 0o600)
    return {"private": str(d / "cosign.key"), "public": str(d / "cosign.pub")}


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m raksha.cosign")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("dir")
    v = sub.add_parser("verify"); v.add_argument("bundle"); v.add_argument("--pub", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "init":
        print(init(a.dir))
        return 0
    b = Path(a.bundle)
    ok = verify_file(b / "bundle.json", b / SIG_FILE, a.pub)
    print("cosign signature valid" if ok else "cosign signature INVALID or missing")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
