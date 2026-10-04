"""The deployment signing key: generated on the box at install, never shipped, never committed.

Evidence bundles, advisories, project reports and certificates are signed with an HMAC key. Without
a deployment key the published demo key is used, and every artifact says so. ``install.sh`` runs
``python -m raksha.keys init /var/lib/raksha-keys/bundle.key`` once, on the sealed node, so each
deployment has its own key that exists nowhere else; the compose file mounts it read-only and points
``RAKSHA_BUNDLE_KEY_FILE`` at it.

HMAC is symmetric: whoever can verify can also sign. A judge who verifies on their own laptop is
handed a copy of the key with the media (``verify.py --key-file``). The stronger, public-key path
(cosign / post-quantum) is the ideal state recorded in PLAN_V2.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
from pathlib import Path


def key_id(key: bytes) -> str:
    return "deploy:" + hashlib.sha256(key).hexdigest()[:12]


def init(path: str | Path, *, force: bool = False) -> str:
    """Create a fresh 256-bit key at `path` (mode 0600). Refuses to overwrite unless `force`."""
    p = Path(path)
    if p.exists() and not force:
        raise FileExistsError(f"{p} already exists; refusing to replace a deployment key")
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key + b"\n")
    os.chmod(p, 0o600)
    return key_id(key)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m raksha.keys")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("path"); i.add_argument("--force", action="store_true")
    s = sub.add_parser("id"); s.add_argument("path")
    a = ap.parse_args(argv)
    if a.cmd == "init":
        try:
            print(f"deployment key created: {a.path} ({init(a.path, force=a.force)})")
        except FileExistsError as e:
            print(e)
            return 1
        return 0
    print(key_id(Path(a.path).read_bytes().strip()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
