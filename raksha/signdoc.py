"""Signed documents — one format for every artifact Wave 5 hands to a person.

A signed document is a directory holding three files:

    <stem>.json       the body (canonical JSON, the machine-readable record)
    <stem>.md         the human rendering of the same body
    <stem>.sig.json   {alg, key_id, kind, id, prev, <stem>_json_sha256, <stem>_md_sha256, signature}

The signature is an HMAC-SHA256 over the two content hashes plus `prev` — the hash of the previous
document in the same chain (a project's report v(N-1), say), or 64 zeros for the first. So a chain
of documents is tamper-evident the way the session journal is: editing, dropping or reordering any
version breaks verification of every later one. The key is the evidence-bundle key (the published
demo key, labelled as such, unless a deployment provisions its own). The internal-CERT advisory
(J8) predates this module and keeps its own names; the standalone verifier checks both.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

ZERO = "0" * 64


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def material(stem: str, body: bytes, text: bytes, prev: str) -> bytes:
    return (f"{stem}.json={_sha(body)}\n{stem}.md={_sha(text)}\nprev={prev}").encode()


def write(out_dir: str | Path, stem: str, body: dict, text: str, *, kind: str, doc_id: str,
          prev: str = ZERO, key: bytes | None = None) -> Path:
    """Write and sign one document into `out_dir` (created). Returns the directory."""
    from .bundle import signing_key
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    bb = json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False).encode()
    tb = text.encode()
    (out / f"{stem}.json").write_bytes(bb)
    (out / f"{stem}.md").write_bytes(tb)
    k, key_id = (key, "caller") if key is not None else signing_key()
    sig = {"alg": "HMAC-SHA256", "key_id": key_id, "kind": kind, "id": doc_id, "prev": prev,
           f"{stem}_json_sha256": _sha(bb), f"{stem}_md_sha256": _sha(tb),
           "signature": hmac.new(k, material(stem, bb, tb, prev), hashlib.sha256).hexdigest()}
    (out / f"{stem}.sig.json").write_text(json.dumps(sig, indent=2, sort_keys=True))
    return out


def doc_hash(out_dir: str | Path, stem: str) -> str:
    """The chain hash of a written document: sha256 of its signature file (which binds everything)."""
    return _sha((Path(out_dir) / f"{stem}.sig.json").read_bytes())


def read(out_dir: str | Path, stem: str) -> dict:
    return json.loads((Path(out_dir) / f"{stem}.json").read_text())


def verify(out_dir: str | Path, stem: str, *, key: bytes | None = None,
           expect_prev: str | None = None) -> tuple[bool, list[str]]:
    from .bundle import _DEMO_KEY, signing_key
    d = Path(out_dir)
    try:
        bb = (d / f"{stem}.json").read_bytes()
        tb = (d / f"{stem}.md").read_bytes()
        sig = json.loads((d / f"{stem}.sig.json").read_text())
    except (OSError, ValueError) as e:
        return False, [f"missing or malformed document ({e})"]
    if key is None:
        key = _DEMO_KEY if sig.get("key_id", "demo") == "demo" else signing_key()[0]
    problems = []
    if _sha(bb) != sig.get(f"{stem}_json_sha256"):
        problems.append(f"CHANGED {stem}.json")
    if _sha(tb) != sig.get(f"{stem}_md_sha256"):
        problems.append(f"CHANGED {stem}.md")
    prev = str(sig.get("prev", ZERO))
    if expect_prev is not None and prev != expect_prev:
        problems.append("CHAIN BROKEN: prev does not match the previous document")
    want = hmac.new(key, material(stem, bb, tb, prev), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(sig.get("signature", ""))):
        problems.append("SIGNATURE INVALID")
    return not problems, problems
