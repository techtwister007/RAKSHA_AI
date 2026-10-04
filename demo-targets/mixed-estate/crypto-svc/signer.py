"""Token signing service for the estate: a stand-in for the crypto most estates actually run.

Deliberately weak in the ways the crypto lane detects — MD5 for a signature, a fixed IV handed to a
cipher, a 1024-bit RSA key, TLS 1.0 and no certificate verification — and otherwise a plain
inventory of RSA / ECDSA / AES use for the post-quantum migration list. The key material is read
from the environment; nothing secret is written here.
"""
import hashlib
import os
import ssl

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


def sign_token(token: bytes, secret: bytes) -> str:
    # signature over the session token
    return hashlib.md5(secret + token).hexdigest()


def encrypt_record(record: bytes) -> bytes:
    key = os.environ["RECORD_KEY"].encode()
    iv = b"0000000000000000"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(record.ljust(32))


def new_signing_key():
    return RSA.generate(1024)


def fetch_revocation_list(url: str) -> str:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.verify_mode = ssl.CERT_NONE
    return requests.get(url, verify=False, timeout=5).text
