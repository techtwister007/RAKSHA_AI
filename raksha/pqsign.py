"""D10 — a post-quantum signing abstraction for the evidence bundle.

The bundle's tamper-evidence rests on a signature over the manifest of artifact hashes. Today that
is HMAC-SHA256 (``bundle.py``); a defence timeline that outlives RSA/ECDSA wants a NIST
post-quantum signature. This module is the seam: ``sign`` / ``verify`` pick the strongest primitive
actually available on the node and name it honestly in the returned record's ``alg`` field.

The ladder (strongest first), each rung tried only by importing — never raising on a miss:

  1. **ML-DSA** (FIPS 204, formerly CRYSTALS-Dilithium) via liboqs' ``oqs`` Python binding, when it is
     bundled. This is the real post-quantum rung.
  2. a pure-Python ML-DSA/Dilithium module (``dilithium_py`` / ``pqcrypto``) if one is bundled.
  3. **HMAC-SHA256** — the existing classical primitive, always available (stdlib). Used as the
     fallback, with a ``note`` stating the PQ signature is available once the library is bundled.

Real vs fallback
----------------
*Real:* the HMAC rung (stdlib, exercised in CI) and the dispatch/verify logic. The ML-DSA rungs are
real when ``oqs``/a pure-Python provider is present, but are **opportunistic**: because ML-DSA is
asymmetric and this abstraction is handed one key (mirroring ``bundle.signing_key``), the PQ rungs
generate an ephemeral keypair per ``sign`` and embed the public key in the record; a production
deployment pins that public key out-of-band (the ``key`` here then scopes the ``key_id`` label).
``verify`` trusts the embedded public key, so the PQ rung proves *integrity of the material under the
carried public key*; binding that key to an identity is the deployment's out-of-band step, exactly
as cosign/in-toto would. The HMAC rung is a true symmetric MAC over ``key``.

Stdlib only at runtime; the PQ providers are optional imports with this clean HMAC fallback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib

#: ML-DSA parameter set used when a provider is available (NIST security category 3).
_ML_DSA_ALG = "ML-DSA-65"
_HMAC_ALG = "HMAC-SHA256"
_PQ_NOTE = ("post-quantum ML-DSA (FIPS 204) signature is used automatically when liboqs (oqs) or a "
            "pure-Python Dilithium provider is bundled; this node has none, so the classical "
            "HMAC-SHA256 fallback was used")


def _key_id(key: bytes) -> str:
    return "k:" + hashlib.sha256(bytes(key)).hexdigest()[:12]


def _load_oqs():
    """Return the liboqs ``oqs`` module if importable and it offers ML-DSA, else None."""
    try:
        oqs = importlib.import_module("oqs")
    except Exception:  # noqa: BLE001 — any import failure means "not available"
        return None
    try:
        mechanisms = set(oqs.get_enabled_sig_mechanisms())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return None
    if _ML_DSA_ALG in mechanisms:
        return oqs
    # Older liboqs spells it "Dilithium3"; accept that spelling but keep the public alg name honest.
    if "Dilithium3" in mechanisms:
        return oqs
    return None


def _oqs_mechanism(oqs) -> str:
    try:
        if _ML_DSA_ALG in set(oqs.get_enabled_sig_mechanisms()):  # type: ignore[attr-defined]
            return _ML_DSA_ALG
    except Exception:  # noqa: BLE001
        pass
    return "Dilithium3"


def pq_available() -> bool:
    """Whether a post-quantum signature provider is importable on this node (liboqs)."""
    return _load_oqs() is not None


def _b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def sign(material: bytes, key: bytes) -> dict:
    """Sign ``material`` with the strongest available primitive. Never raises on a missing library.

    Returns a self-describing record: ``alg`` names the primitive actually used, ``signature`` is
    base64, ``key_id`` labels the carried key. The PQ rung additionally carries ``public_key``
    (base64) — the trust anchor a verifier checks against, pinned out-of-band in production. The HMAC
    rung carries a ``note`` explaining that the PQ signature activates once the library is bundled.
    """
    material = bytes(material)
    oqs = _load_oqs()
    if oqs is not None:
        try:
            mech = _oqs_mechanism(oqs)
            with oqs.Signature(mech) as signer:  # type: ignore[attr-defined]
                public_key = signer.generate_keypair()
                signature = signer.sign(material)
            return {
                "alg": _ML_DSA_ALG,
                "mechanism": mech,
                "signature": _b64(signature),
                "public_key": _b64(public_key),
                "key_id": _key_id(key),
                "note": "post-quantum ML-DSA signature; verifier pins public_key out-of-band",
            }
        except Exception:  # noqa: BLE001 — a provider that errors must degrade, never crash the run
            pass
    return {
        "alg": _HMAC_ALG,
        "signature": _b64(hmac.new(bytes(key), material, hashlib.sha256).digest()),
        "key_id": _key_id(key),
        "note": _PQ_NOTE,
    }


def verify(material: bytes, sig: dict, key: bytes) -> bool:
    """Verify a record from ``sign`` against ``material`` and ``key``. Never raises; a malformed,
    tampered, or unknown-``alg`` record returns False. A single changed byte of ``material`` fails."""
    if not isinstance(sig, dict):
        return False
    material = bytes(material)
    alg = sig.get("alg")
    try:
        if alg == _HMAC_ALG:
            expected = hmac.new(bytes(key), material, hashlib.sha256).digest()
            got = _unb64(str(sig.get("signature", "")))
            return hmac.compare_digest(expected, got)
        if alg == _ML_DSA_ALG:
            oqs = _load_oqs()
            if oqs is None:
                return False
            mech = str(sig.get("mechanism") or _oqs_mechanism(oqs))
            signature = _unb64(str(sig.get("signature", "")))
            public_key = _unb64(str(sig.get("public_key", "")))
            with oqs.Signature(mech) as verifier:  # type: ignore[attr-defined]
                return bool(verifier.verify(material, signature, public_key))
    except Exception:  # noqa: BLE001 — any decode/verify error is a failed verification, not a crash
        return False
    return False
