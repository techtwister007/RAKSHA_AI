"""Crypto lane — weak-crypto findings and a post-quantum (PQC) readiness inventory, with no build.

Two outputs, deliberately kept apart:

1. **Findings** (`scan_text`): deterministic rules over source and config text for cryptography that
   is broken or misused *today* — MD5/SHA-1 in a signature, MAC or password-hashing context, DES /
   3DES / RC4 / Blowfish, AES in ECB mode, a hard-coded IV or nonce handed to a cipher, RSA/DSA keys
   under 2048 bits, EC curves below P-256, SSLv3 / TLS 1.0 / TLS 1.1 and disabled certificate
   verification. Each hit is CONFIRMED by deterministic match exactly like the secrets lane: the
   rule re-matches at that line of that file, and `python -m raksha crypto-match RULE PATH LINE`
   replays it. No exploit is claimed; the record says `deterministic-match`.

2. **Inventory** (`inventory`, `pqc_report`): NOT findings. A list of the cryptographic primitives in
   use (RSA, ECDSA, ECDH, DH, Ed25519/X25519, AES, ChaCha20, SHA-2/3, TLS versions, key and
   certificate files), each tagged with whether a cryptographically-relevant quantum computer breaks
   it and the NIST FIPS 203/204/205 replacement. `pqc_report` aggregates it into the migration list
   the Commander's Brief needs. Nothing here is a vulnerability claim, so nothing here is reportable.

What is measured and what is a heuristic
----------------------------------------
Measured: every number in `pqc_report` is a count over the inventory of the files actually scanned;
`blast_radius` is `None` (never 0) when no crypto was seen at all. Heuristic: the *context* test for
MD5/SHA-1 (a security word within two lines) and the *proximity* test for a static IV (a cipher
constructor within five lines) are textual; they were tuned so that a plain checksum / ETag use of
MD5 and a random nonce never fire, and the negative controls in the tests pin that. Key sizes are
read only from literals in the call; a size computed at runtime is unknown and is not reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..finding import DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow

# ---------------------------------------------------------------- rules


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    severity: str
    pattern: re.Pattern
    rationale: str
    #: If set, a line within `window` lines (inclusive, both sides) must match this too. This is what
    #: separates "MD5 of a password" from "MD5 of a download".
    context: re.Pattern | None = None
    window: int = 2
    #: If set and the matching line matches this, the hit is dropped (a checksum is not a signature).
    exclude: re.Pattern | None = None
    #: For size rules: the captured integer must be below this to fire.
    below: int | None = None


_SECURITY_CONTEXT = re.compile(
    r"(?i)\b(?:sign(?:ature|ed|ing)?|verif(?:y|ied|ies|ication)|hmac|mac\b|password|passwd|passphrase|"
    r"credential|secret|token|auth(?:enticat\w*)?|login|session|cookie|jwt|api[_-]?key)\b")
_CHECKSUM_ONLY = re.compile(r"(?i)\b(?:checksum|etag|crc|cache[_-]?key|dedup\w*|content[_-]?hash|fingerprint)\b")

#: MD5 / SHA-1 as an algorithm selection, in the shapes the common libraries use.
_WEAK_HASH = (r"(?:hashlib\.(?:md5|sha1)\b|MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-?1)[\"']|"
              r"createHash\(\s*[\"'](?:md5|sha1)[\"']|\b(?:md5|sha1)\.(?:New|Sum)\b|"
              r"\bcrypto/(?:md5|sha1)\b|Digest::(?:MD5|SHA1)\b|\b(?:MD5|SHA1)\s*\(|"
              r"\b(?:md5|sha1)_(?:hex|crypt|hmac|init|update)\b|\bEVP_(?:md5|sha1)\s*\()")

_RULES: list[Rule] = [
    Rule("weak-hash-signature", "CWE-328", "high",
         re.compile(r"(?:(?:MD5|SHA-?1)with(?:RSA|DSA|ECDSA)\b|\bHmac(?:MD5|SHA1)\b|"
                    r"\b(?:RS|HS|ES)1\b|md5WithRSAEncryption|sha1WithRSAEncryption|"
                    r"hmac\.new\([^)]*hashlib\.(?:md5|sha1)\b|hmac\.New\(\s*(?:md5|sha1)\.New\b|"
                    r"createHmac\(\s*[\"'](?:md5|sha1)[\"'])"),
         "MD5 / SHA-1 inside a signature or MAC algorithm: collisions are practical, so a signature "
         "or MAC over them can be forged"),
    Rule("weak-hash-security-context", "CWE-328", "medium",
         re.compile(_WEAK_HASH), context=_SECURITY_CONTEXT, exclude=_CHECKSUM_ONLY,
         rationale="MD5 / SHA-1 used where a security property (signature, MAC, password, token) is "
                   "expected; collision attacks are practical. Plain checksum / ETag use is not reported"),
    Rule("weak-cipher", "CWE-327", "high",
         re.compile(r"(?:Cipher\.getInstance\(\s*[\"'](?:DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish)\b|"
                    r"\b(?:DES|DES3|ARC4|Blowfish)\.new\(|algorithms\.(?:TripleDES|Blowfish|ARC4)\(|"
                    r"createCipheriv\(\s*[\"'](?:des|des3|des-ede3?|rc4|bf)\b|"
                    r"\b(?:des|rc4|blowfish)\.NewCipher\(|des\.NewTripleDESCipher\(|"
                    r"\bEVP_(?:des|des_ede3|rc4|bf)_\w*\(|"
                    r"\bcrypto/(?:des|rc4|blowfish)\b)"),
         "DES / 3DES / RC4 / Blowfish: 64-bit blocks (Sweet32) or a biased keystream; none is "
         "acceptable for new data"),
    Rule("ecb-mode", "CWE-327", "high",
         re.compile(r"(?:AES/ECB|MODE_ECB\b|modes\.ECB\(|aes-(?:128|192|256)-ecb|\bNewECB(?:Encrypter|Decrypter)?\(|"
                    r"\bEVP_aes_(?:128|192|256)_ecb\()"),
         "ECB mode: identical plaintext blocks give identical ciphertext blocks, so structure "
         "leaks and blocks can be cut and pasted"),
    Rule("static-iv", "CWE-329", "medium",
         re.compile(r"(?:\b(?:iv|nonce|IV|NONCE|initVector|init_vector)\s*(?::\s*\w+\s*)?=\s*"
                    r"(?:[rb]?[\"'][^\"']{4,}[\"']|bytes\(\s*\d+\s*\)|b?[\"']\\x00|new byte\[\s*\d+\s*\]|"
                    r"\[\s*0\s*(?:,\s*0\s*)+\]|\{\s*0x[0-9A-Fa-f]{2}(?:\s*,\s*0x[0-9A-Fa-f]{2}){3,}|"
                    r"\[\]byte\(\s*\"[^\"]{4,}\"\s*\)|make\(\s*\[\]byte\s*,\s*\d+\s*\)|Buffer\.(?:alloc|from)\()|"
                    r"IvParameterSpec\(\s*(?:new byte\[|\"[^\"]+\"\.getBytes)|"
                    r"GCMParameterSpec\(\s*\d+\s*,\s*(?:new byte\[|\"[^\"]+\"\.getBytes)|"
                    r"modes\.(?:CBC|CTR|GCM|CFB|OFB)\(\s*b?[\"']|"
                    r"\.new\([^)]*\b(?:iv|nonce)\s*=\s*b?[\"'])"),
         context=re.compile(r"(?:Cipher\b|AES\b|ChaCha|modes\.|createCipheriv|IvParameterSpec|GCMParameterSpec|"
                            r"NewGCM|NewCBC|NewCTR|NewCFB|NewOFB|\.new\(|EVP_(?:Encrypt|Decrypt|Cipher)Init)"),
         window=5,
         rationale="a fixed IV / nonce reused across messages breaks CBC semantic security and is "
                   "catastrophic for GCM / ChaCha20-Poly1305 (key recovery)"),
    Rule("weak-rsa-keysize", "CWE-326", "high",
         re.compile(r"(?:RSA\.generate\(\s*(\d+)|key_size\s*=\s*(\d+)|rsa\.GenerateKey\([^,]+,\s*(\d+)\s*\)|"
                    r"modulusLength\s*:\s*(\d+)|genrsa\b[^\n]*?\b(\d{3,4})\b|ssh-keygen\b[^\n]*-b\s*(\d+)|"
                    r"DSA\.generate\(\s*(\d+)|\.initialize\(\s*(\d+)\s*\)|RSAKeyGenParameterSpec\(\s*(\d+))"),
         below=2048,
         context=re.compile(r"(?i)\b(?:rsa|dsa)\b"), window=5,
         rationale="RSA / DSA modulus under 2048 bits is below the NIST SP 800-57 minimum (112-bit "
                   "security); 1024-bit keys are within reach of a well-funded classical attacker"),
    Rule("weak-ec-curve", "CWE-326", "medium",
         re.compile(r"(?:\bSECP(?:112|128|160|192|224)[RK][12]\b|\bsecp(?:112|128|160|192|224)[rk][12]\b|"
                    r"\bprime192v[123]\b|elliptic\.P224\(\)|[\"']P-(?:192|224)[\"']|\bbrainpoolP(?:160|192|224)[rt]1\b|"
                    r"\bNIST_P_(?:192|224)\b|\bcurve\s*=\s*[\"']?(?:P-?192|P-?224)\b)"),
         "an elliptic curve below P-256 gives under 112-bit security; P-256 / X25519 is the floor",
         ),
    Rule("legacy-tls-protocol", "CWE-757", "high",
         re.compile(r"(?:ssl\.PROTOCOL_(?:SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)\b|"
                    r"ssl\.TLSVersion\.(?:SSLv3|TLSv1|TLSv1_1)\b|"
                    r"SSLContext\.getInstance\(\s*[\"'](?:SSL|SSLv2|SSLv3|TLS|TLSv1|TLSv1\.1)[\"']|"
                    r"MinVersion\s*:\s*tls\.Version(?:SSL30|TLS10|TLS11)\b|"
                    r"tls\.Version(?:SSL30|TLS10|TLS11)\b[^\n]*MinVersion|"
                    r"secureProtocol\s*:\s*[\"'](?:SSLv2|SSLv3|TLSv1|TLSv1_1)_(?:client_|server_)?method|"
                    r"minVersion\s*:\s*[\"']TLSv1(?:\.1)?[\"']|"
                    r"ssl_protocols\b[^\n;]*\b(?:SSLv2|SSLv3|TLSv1(?:\.1)?)\b(?![.\d])|"
                    r"SSLProtocol\b[^\n]*\b(?:SSLv2|SSLv3|TLSv1(?:\.1)?)\b(?![.\d])|"
                    r"\bSSL_OP_NO_TLSv1_2\b|\b(?:SSLv3|TLSv1|TLSv1_1)_(?:client|server)?_?method\(\))"),
         "SSLv3 / TLS 1.0 / TLS 1.1 are deprecated (RFC 8996); POODLE and BEAST-class attacks apply"),
    Rule("no-cert-verification", "CWE-295", "high",
         re.compile(r"(?:\bverify\s*=\s*False\b|\bCERT_NONE\b|InsecureSkipVerify\s*:\s*true\b|"
                    r"rejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0\b|"
                    r"\bcheck_hostname\s*=\s*False\b|GIT_SSL_NO_VERIFY\s*=\s*(?:true|1)\b|"
                    r"\bssl_verify\s*[:=]\s*false\b|--no-check-certificate\b|\bcurl\b[^\n]*\s(?:-k|--insecure)\b|"
                    r"\bPYTHONHTTPSVERIFY\s*=\s*0\b|\bSSL_VERIFY_NONE\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b|"
                    r"\bTrustAllCerts\b|\bverify_mode\s*=\s*ssl\.CERT_NONE\b|\bsslmode\s*=\s*disable\b|"
                    r"\bssl_verify_peer\s*[:=]\s*(?:false|0)\b|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false|FALSE)\b)"),
         "certificate verification is disabled, so any on-path attacker can impersonate the peer; "
         "TLS then authenticates nothing"),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}

_LANG_BY_EXT = {
    ".py": "python", ".java": "java", ".kt": "kotlin", ".scala": "scala", ".go": "go",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".jsx": "javascript", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
    ".rs": "rust", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".swift": "swift",
    ".sh": "shell", ".bash": "shell", ".yaml": "config", ".yml": "config", ".json": "config",
    ".properties": "config", ".conf": "config", ".cfg": "config", ".ini": "config", ".toml": "config",
    ".xml": "config", ".tf": "config", ".env": "config",
}
_TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|examples?|mocks?)/")
_COMMENT_LINE = re.compile(r"^\s*(?://|#|\*|/\*|--|<!--)")


def language_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return _LANG_BY_EXT.get(suffix.lower(), "any")


def _captured_int(m: re.Match) -> int | None:
    for g in m.groups():
        if g is not None and g.isdigit():
            return int(g)
    return None


def _window(lines: list[str], i: int, n: int) -> str:
    """Lines i-n .. i+n (0-based i), joined — the context a rule may require."""
    return "\n".join(lines[max(0, i - n): i + n + 1])


def _matches(rule: Rule, lines: list[str], i: int) -> re.Match | None:
    """The rule's match on line i (0-based) once its context / exclude / size conditions hold."""
    line = lines[i]
    if _COMMENT_LINE.match(line):
        return None                                    # prose about MD5 is not a use of MD5
    m = rule.pattern.search(line)
    if not m:
        return None
    if rule.exclude is not None and rule.exclude.search(line):
        return None
    if rule.below is not None:
        size = _captured_int(m)
        if size is None or size >= rule.below:
            return None
    if rule.context is not None and not rule.context.search(_window(lines, i, rule.window)):
        return None
    return m


def scan_text(text: str, path: str) -> list[Finding]:
    """Every rule, every line; one finding per (rule, line), CONFIRMED by deterministic match."""
    lines = text.splitlines()
    in_test = bool(_TEST_PATH.search("/" + path))
    findings: list[Finding] = []
    for i in range(len(lines)):
        for rule in _RULES:
            m = _matches(rule, lines, i)
            if m is None:
                continue
            findings.append(_finding(rule, path, i + 1, m.start() + 1, m.group(0), in_test))
    return findings


def _finding(rule: Rule, path: str, line: int, col: int, matched: str, in_test: bool) -> Finding:
    """Mirror of `secrets._finding`: evidence is the re-match, replayed via `crypto-match`."""
    excerpt = matched.strip()[:60]
    severity = "low" if in_test else rule.severity   # test code: still real, never outranks production
    f = Finding(
        oracle=f"crypto:{rule.id}",
        bug_class=rule.cwe,
        language=language_of(path),
        target=path,
        message=f"{rule.rationale.split(':')[0].split(';')[0]} — `{excerpt}` at {path}:{line}",
        severity=severity,
        frames=[Frame(symbol=rule.id, uri=path, line=line, column=col)],
        raw_excerpt=excerpt,
    )
    f.add_fix_site(FixSite(uri=path, rank=0, start_line=line, symbol=rule.id, rationale=rule.rationale))
    repro = Reproducer.from_bytes(
        f"{rule.id}@{path}:{line}".encode(),
        ["raksha", "crypto-match", rule.id, path, str(line)],
        artifact_path=path, minimised=True, kind=DETERMINISTIC_MATCH,
        detail=f"{rule.id} ({rule.cwe}) matched `{excerpt}` at {path}:{line}",
    )
    f.attach_reproducer(repro)
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=rule.id, exit_code=0))
    f.confirm(reason="weak-crypto rule deterministically re-matches at this location")
    return f


def replay(rule_id: str, path: str, line: int, root: str | Path = ".") -> bool:
    """Re-read `root/path` and re-run `rule_id` at `line`. True = the finding still reproduces.

    This is the `python -m raksha crypto-match RULE PATH LINE` contract: the CLI maps True to exit 1
    (reproduced, like a crashing exploit), False to exit 0, and lets FileNotFoundError / ValueError
    surface as exit 2 (could not run). The whole file is re-read, not the one line, because the
    context rules look at neighbouring lines.
    """
    if rule_id not in RULES:
        raise ValueError(f"unknown crypto rule {rule_id!r}")
    file = Path(root) / path
    if not file.exists():
        raise FileNotFoundError(str(file))
    lines = file.read_text(errors="replace").splitlines()
    if not 1 <= line <= len(lines):
        return False
    return _matches(RULES[rule_id], lines, line - 1) is not None


# ---------------------------------------------------------------- PQC inventory

#: Migration targets, by family. These are the NIST FIPS 203/204/205 replacements; the transitional
#: note for key exchange is the hybrid every major TLS deployment is rolling out first.
_MIGRATION = {
    "key-exchange": "ML-KEM (FIPS 203); transitional: hybrid X25519+ML-KEM",
    "signature": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
    "rsa": "encryption / key transport: ML-KEM (FIPS 203); signatures: ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
    "aes-128": "AES-256 (Grover halves the effective key length: 128-bit keys give ~64-bit quantum security)",
    "aes-unknown": "confirm key size; use AES-256",
    "none": "no change needed (symmetric / hash: quantum impact is a constant factor, already covered at 256 bits)",
    "legacy-hash": "SHA-256 / SHA-3 (classically broken already; not a quantum question)",
    "tls": "TLS 1.3 with hybrid X25519+ML-KEM key exchange; ML-DSA certificates when the PKI issues them",
    "keyfile": "inspect: today's certificates and keys are RSA / ECDSA; plan ML-DSA or SLH-DSA certificates "
               "and ML-KEM for key transport",
}

#: (primitive, pattern, quantum_vulnerable, migration key, family). Order matters only for display.
_PRIMITIVES: list[tuple[str, re.Pattern, bool | str, str, str]] = [
    ("RSA", re.compile(r"\bRSA\b|\brsa\.(?:generate|GenerateKey|PublicKey|PrivateKey|Encrypt|Sign|new)|ssh-rsa\b|"
                       r"RSAKeyGenParameterSpec|RSAPublicKey|RSAPrivateKey|genrsa\b"), True, "rsa", "asymmetric"),
    ("DSA", re.compile(r"\bDSA\b(?!\w)|\bdsa\.(?:generate|GenerateKey|Sign|Verify)|ssh-dss\b"), True, "signature", "asymmetric"),
    ("ECDSA", re.compile(r"\bECDSA\b|\becdsa\.(?:Sign|Verify|GenerateKey|PublicKey|PrivateKey)|ecdsa-sha2|"
                         r"\bES(?:256|384|512)\b|ECGenParameterSpec|SECP\d+R1|secp\d+[rk]1|\bec\.(?:generate_private_key|ECDSA)"),
     True, "signature", "asymmetric"),
    ("ECDH", re.compile(r"\bECDHE?\b|\becdh\.|\bec\.ECDH\b|ECDHKeyAgreement"), True, "key-exchange", "asymmetric"),
    ("DH", re.compile(r"\bDHE?\b(?!-)|DiffieHellman|\bdh\.(?:generate|GenerateKey|DHParameter)|KeyAgreement\.getInstance\(\s*\"DH\""),
     True, "key-exchange", "asymmetric"),
    ("Ed25519", re.compile(r"\bEd25519\b|\bed25519\.|ssh-ed25519\b|\bEdDSA\b"), True, "signature", "asymmetric"),
    ("X25519", re.compile(r"\bX25519\b|\bx25519\.|\bcurve25519\b"), True, "key-exchange", "asymmetric"),
    ("AES-128", re.compile(r"\bAES[-_/]?128\b|aes-128-|AES_128|\bAES\b[^\n]*(?:key_size|keySize|size)\s*=\s*128\b"),
     "weakened", "aes-128", "symmetric"),
    ("AES-192", re.compile(r"\bAES[-_/]?192\b|aes-192-|AES_192"), "weakened", "aes-128", "symmetric"),
    ("AES-256", re.compile(r"\bAES[-_/]?256\b|aes-256-|AES_256"), False, "none", "symmetric"),
    ("AES", re.compile(r"\bAES\b(?![-_/]?(?:128|192|256))"), "unknown", "aes-unknown", "symmetric"),
    ("ChaCha20", re.compile(r"\bChaCha20(?:-Poly1305|Poly1305)?\b|\bchacha20"), False, "none", "symmetric"),
    ("SHA-2", re.compile(r"\bSHA[-_]?(?:224|256|384|512)\b|\bsha(?:224|256|384|512)\b|\bHS(?:256|384|512)\b|\bPS(?:256|384|512)\b"),
     False, "none", "hash"),
    ("SHA-3", re.compile(r"\bSHA[-_]?3(?:[-_]\d{3})?\b|\bsha3[-_]\d{3}\b|\bKeccak\b|\bSHAKE(?:128|256)\b"), False, "none", "hash"),
    ("SHA-1", re.compile(r"\bSHA[-_]?1\b|\bsha1\b"), False, "legacy-hash", "hash"),
    ("MD5", re.compile(r"\bMD5\b|\bmd5\b"), False, "legacy-hash", "hash"),
    ("TLS 1.3", re.compile(r"\bTLS[ v]?1\.3\b|TLSv1_3\b|VersionTLS13\b"), True, "tls", "protocol"),
    ("TLS 1.2", re.compile(r"\bTLS[ v]?1\.2\b|TLSv1_2\b|VersionTLS12\b"), True, "tls", "protocol"),
    ("TLS <1.2", re.compile(r"\bTLS[ v]?1\.[01]\b|TLSv1(?:_1)?\b(?![._]\d)|VersionTLS1[01]\b|\bSSLv[23]\b"), True, "tls", "protocol"),
]
_KEYFILE_EXT = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore", ".key", ".pub"}
_KEYFILE_REF = re.compile(r"[\w./\\-]+\.(?:pem|crt|cer|der|p12|pfx|jks|keystore)\b")


@dataclass(frozen=True)
class CryptoUse:
    """One sighting of a primitive. `quantum_vulnerable` is True / False / "weakened" / "unknown"."""

    path: str
    line: int
    primitive: str
    family: str
    quantum_vulnerable: bool | str
    migration: str
    evidence: str


def inventory(text: str, path: str) -> list[CryptoUse]:
    """Every primitive sighting in `text`, one per (line, primitive). Comments count: a comment naming
    RSA next to code is still part of the migration picture, and this is an inventory, not a claim."""
    uses: list[CryptoUse] = []
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if suffix in _KEYFILE_EXT:
        uses.append(CryptoUse(path, 1, "key/certificate file", "keyfile", "unknown", _MIGRATION["keyfile"], suffix))
    for i, line in enumerate(text.splitlines(), 1):
        seen: set[str] = set()
        for name, pat, qv, mig, family in _PRIMITIVES:
            m = pat.search(line)
            if m and name not in seen:
                seen.add(name)
                uses.append(CryptoUse(path, i, name, family, qv, _MIGRATION[mig], m.group(0)[:40]))
        m = _KEYFILE_REF.search(line)
        if m:
            uses.append(CryptoUse(path, i, "key/certificate file", "keyfile", "unknown", _MIGRATION["keyfile"],
                                  m.group(0)[-40:]))
    return uses


#: Which inventoried primitives each attacker class threatens. A deterministic table, not a forecast:
#: "classical" is what is broken with today's computers, "CRQC" is Shor (asymmetric) and Grover
#: (symmetric, constant-factor) on a cryptographically-relevant quantum computer, and "AI-assisted"
#: records honestly that no primitive here is broken by AI-assisted cryptanalysis — that attacker
#: threatens implementations and configurations, which is the findings half of this lane.
THREAT_MODELS: dict[str, dict] = {
    "classical": {
        "breaks": ["MD5", "SHA-1", "TLS <1.2"],
        "note": "collision / downgrade attacks are practical today; also any RSA/DSA key under 2048 bits "
                "and any EC curve under P-256 (reported by the findings rules, not the inventory)",
    },
    "cryptographically-relevant-quantum": {
        "breaks": ["RSA", "DSA", "ECDSA", "ECDH", "DH", "Ed25519", "X25519", "TLS <1.2", "TLS 1.2", "TLS 1.3"],
        "weakens": ["AES-128", "AES-192", "AES"],
        "note": "Shor breaks every factoring / discrete-log primitive (TLS is listed because its key "
                "exchange and certificates are those primitives); Grover halves symmetric key length. "
                "Harvest-now-decrypt-later means recorded traffic is already exposed",
    },
    "ai-assisted": {
        "breaks": [],
        "note": "no inventoried primitive is broken by AI-assisted cryptanalysis; the AI-assisted "
                "attacker finds misuse (static IVs, disabled verification, weak modes) faster — "
                "those are the findings rules",
    },
}


def pqc_report(uses: list[CryptoUse]) -> dict:
    """Aggregate an inventory into the migration view. Every number is a count over `uses`;
    `blast_radius` is None (never 0) when no crypto was seen, because 0/0 is not a measurement."""
    primitives: dict[str, int] = {}
    files_with_crypto: set[str] = set()
    files_affected: set[str] = set()
    migrations: dict[str, list[dict]] = {}
    vulnerable = weakened = unknown = 0
    for u in sorted(uses, key=lambda u: (u.path, u.line, u.primitive)):
        primitives[u.primitive] = primitives.get(u.primitive, 0) + 1
        files_with_crypto.add(u.path)
        if u.quantum_vulnerable is True:
            vulnerable += 1
            files_affected.add(u.path)
            migrations.setdefault(u.path, []).append(
                {"line": u.line, "primitive": u.primitive, "migration": u.migration})
        elif u.quantum_vulnerable == "weakened":
            weakened += 1
            files_affected.add(u.path)
            migrations.setdefault(u.path, []).append(
                {"line": u.line, "primitive": u.primitive, "migration": u.migration})
        elif u.quantum_vulnerable == "unknown":
            unknown += 1
    present = set(primitives)
    threat_models = {
        name: {
            "threatens": sorted(p for p in tm.get("breaks", []) if p in present),
            "weakens": sorted(p for p in tm.get("weakens", []) if p in present),
            "note": tm["note"],
        }
        for name, tm in THREAT_MODELS.items()
    }
    return {
        "sites": len(uses),
        "primitives": dict(sorted(primitives.items())),
        "quantum_vulnerable_sites": vulnerable,
        "weakened_sites": weakened,
        "unknown_sites": unknown,
        "files_with_crypto": len(files_with_crypto),
        "files_affected": len(files_affected),
        "blast_radius": (round(len(files_affected) / len(files_with_crypto), 3) if files_with_crypto else None),
        "migrations": migrations,
        "threat_models": threat_models,
    }


@dataclass
class CryptoResult:
    """One target's crypto lane output: findings (reportable) and the inventory (never reportable)."""

    findings: list[Finding] = field(default_factory=list)
    uses: list[CryptoUse] = field(default_factory=list)
    files_scanned: int = 0

    def report(self) -> dict:
        return pqc_report(self.uses)


_SOURCE_EXT = set(_LANG_BY_EXT) | {".txt", ".md", ".sh", ".gradle", ".groovy", ".cnf", ".nginx", ".htaccess"}
_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}


def scan_target(root: str | Path) -> CryptoResult:
    """Walk a target: findings and inventory from every text file. Mirrors `buildfree._walk`."""
    root = Path(root)
    result = CryptoResult()
    paths = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    for path in paths:
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in _SOURCE_EXT and suffix not in _KEYFILE_EXT:
            continue
        rel = str(path.relative_to(root)) if path != root else path.name
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, rel))
        result.uses.extend(inventory(text, rel))
    return result
