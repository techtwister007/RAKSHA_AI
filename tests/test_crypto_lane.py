"""Crypto lane: weak-crypto findings (deterministic match, replayable) and the PQC inventory.

Positives per rule, negatives that must stay silent (a checksum MD5, a random GCM nonce, RSA-4096),
replay that reproduces and then stops after the fix, and zero false positives on every demo file
that predates this lane and on the benchmark's clean negative controls.
"""

from __future__ import annotations

import pathlib

import pytest

from raksha.finding import DETERMINISTIC_MATCH, Status
from raksha.lanes import crypto

REPO = pathlib.Path(__file__).parents[1]
DEMO = REPO / "demo-targets"
#: Added with this lane; everything else under demo-targets predates it and must yield 0 findings.
ADDED_BY_THIS_LANE = {"mixed-estate/crypto-svc/signer.py", "mixed-estate/tool-py/ingest.py",
                      "mixed-estate/audit-java/pom.xml",
                      "mixed-estate/audit-java/src/main/java/com/example/audit/AuditLog.java"}


def oracles(text: str, path: str = "svc/app.py") -> list[str]:
    return [f.oracle for f in crypto.scan_text(text, path)]


# ---------------------------------------------------------------- positives, one per rule

@pytest.mark.parametrize("text,path,rule", [
    ('import hashlib\npw_hash = hashlib.md5(password.encode()).hexdigest()\n', "a.py", "weak-hash-security-context"),
    ('digest = MessageDigest.getInstance("SHA-1");\n// verify the signature\n', "A.java", "weak-hash-security-context"),
    ('Signature s = Signature.getInstance("SHA1withRSA");\n', "S.java", "weak-hash-signature"),
    ("mac = hmac.new(key, msg, hashlib.md5)\n", "m.py", "weak-hash-signature"),
    ('Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n', "C.java", "weak-cipher"),
    ("from Crypto.Cipher import ARC4\nc = ARC4.new(key)\n", "r.py", "weak-cipher"),
    ("block, _ := des.NewTripleDESCipher(key)\n", "d.go", "weak-cipher"),
    ('Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n', "E.java", "ecb-mode"),
    ("c = AES.new(key, AES.MODE_ECB)\n", "e.py", "ecb-mode"),
    ('iv = b"0123456789abcdef"\ncipher = AES.new(key, AES.MODE_CBC, iv)\n', "iv.py", "static-iv"),
    ('IvParameterSpec iv = new IvParameterSpec(new byte[16]);\nCipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n',
     "Iv.java", "static-iv"),
    ("key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n", "k.py", "weak-rsa-keysize"),
    ("key = RSA.generate(1024)\n", "k2.py", "weak-rsa-keysize"),
    ('KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\ng.initialize(1024);\n', "K.java", "weak-rsa-keysize"),
    ("priv, _ := rsa.GenerateKey(rand.Reader, 1024)\n", "k.go", "weak-rsa-keysize"),
    ("curve := elliptic.P224()\n", "ec.go", "weak-ec-curve"),
    ("key = ec.generate_private_key(ec.SECP192R1())\n", "ec.py", "weak-ec-curve"),
    ("ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n", "t.py", "legacy-tls-protocol"),
    ("ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n", "t2.py", "legacy-tls-protocol"),
    ("cfg := &tls.Config{MinVersion: tls.VersionTLS10}\n", "t.go", "legacy-tls-protocol"),
    ("ssl_protocols SSLv3 TLSv1 TLSv1.2;\n", "nginx.conf", "legacy-tls-protocol"),
    ("r = requests.get(url, verify=False)\n", "v.py", "no-cert-verification"),
    ("ctx.verify_mode = ssl.CERT_NONE\n", "v2.py", "no-cert-verification"),
    ("tls.Config{InsecureSkipVerify: true}\n", "v.go", "no-cert-verification"),
    ("const agent = new https.Agent({ rejectUnauthorized: false });\n", "v.js", "no-cert-verification"),
])
def test_rule_positive(text, path, rule):
    found = crypto.scan_text(text, path)
    assert f"crypto:{rule}" in [f.oracle for f in found], found
    f = next(x for x in found if x.oracle == f"crypto:{rule}")
    assert f.status is Status.CONFIRMED
    assert f.reproducer.kind == DETERMINISTIC_MATCH
    assert f.reproducer.replay_cmd[:3] == ["raksha", "crypto-match", rule]
    assert f.reproducer.replay_cmd[3:] == [path, str(f.frames[0].line)]
    assert f.bug_class == crypto.RULES[rule].cwe
    assert f.fix_site_set[0].start_line == f.frames[0].line


def test_every_rule_has_id_cwe_severity_and_rationale():
    for rule in crypto.RULES.values():
        assert rule.cwe in {"CWE-327", "CWE-328", "CWE-326", "CWE-329", "CWE-295", "CWE-757"}
        assert rule.severity in {"critical", "high", "medium", "low"}
        assert rule.rationale and rule.id


def test_language_from_extension():
    assert crypto.language_of("x/y.go") == "go"
    assert crypto.language_of("A.java") == "java"
    assert crypto.language_of("app.properties") == "config"
    assert crypto.language_of("Makefile") == "any"
    (f,) = crypto.scan_text("tls.Config{InsecureSkipVerify: true}\n", "pkg/client.go")
    assert f.language == "go"


# ---------------------------------------------------------------- negatives: must stay silent

@pytest.mark.parametrize("text,path", [
    ("import hashlib\netag = hashlib.md5(body).hexdigest()\n", "checksum.py"),          # plain checksum
    ("checksum = hashlib.sha1(blob).hexdigest()  # content checksum for dedup\n", "c.py"),
    ("# MD5 was the old signature scheme and is gone\n", "comment.py"),             # prose, not code
    ("nonce = os.urandom(12)\ncipher = AESGCM(key)\nct = cipher.encrypt(nonce, data, None)\n", "gcm.py"),
    ("key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n", "rsa4096.py"),
    ("key = RSA.generate(2048)\n", "rsa2048.py"),
    ("ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\nr = requests.get(url, verify=True)\n", "tls12.py"),
    ("cfg := &tls.Config{MinVersion: tls.VersionTLS12}\n", "tls12.go"),
    ("curve := elliptic.P256()\n", "p256.go"),
    ("digest = hashlib.sha256(password.encode()).hexdigest()\n", "sha256.py"),
    ('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n', "Gcm.java"),
    ("executor.initialize(1024);  // thread pool\n", "Pool.java"),                   # not a key size
])
def test_rule_negative(text, path):
    assert oracles(text, path) == []


def test_demo_files_that_predate_this_lane_draw_no_findings():
    """Every file under demo-targets that existed before this lane: zero findings. The files added
    with the lane are the only ones allowed to fire, and they are listed by name."""
    hits = {}
    for path in sorted(DEMO.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = str(path.relative_to(DEMO))
        if rel in ADDED_BY_THIS_LANE:
            continue
        found = crypto.scan_text(path.read_text(errors="replace"), rel)
        if found:
            hits[rel] = [f.oracle for f in found]
    assert hits == {}


def test_benchmark_negative_controls_draw_no_findings():
    from raksha.benchmark import NEGATIVE_CONTROLS
    for rel, text in NEGATIVE_CONTROLS.items():
        assert oracles(text, rel) == [], rel


def test_added_demo_service_fires_the_intended_rules():
    rel = "mixed-estate/crypto-svc/signer.py"
    found = crypto.scan_text((DEMO / rel).read_text(), rel)
    assert {f.oracle for f in found} >= {"crypto:weak-hash-security-context", "crypto:static-iv",
                                         "crypto:weak-rsa-keysize", "crypto:legacy-tls-protocol",
                                         "crypto:no-cert-verification"}


def test_test_paths_are_ranked_low():
    (f,) = crypto.scan_text("r = requests.get(url, verify=False)\n", "tests/test_client.py")
    assert f.severity == "low"


# ---------------------------------------------------------------- replay contract

def test_replay_reproduces_then_stops_after_fix(tmp_path):
    src = tmp_path / "svc" / "client.py"
    src.parent.mkdir()
    src.write_text("import requests\n\ndef get(url):\n    return requests.get(url, verify=False)\n")
    (f,) = crypto.scan_text(src.read_text(), "svc/client.py")
    _, cmd, rule, path, line = f.reproducer.replay_cmd
    assert cmd == "crypto-match" and path == "svc/client.py" and line == "4"
    assert crypto.replay(rule, path, int(line), root=tmp_path) is True
    src.write_text(src.read_text().replace("verify=False", "verify=True"))
    assert crypto.replay(rule, path, int(line), root=tmp_path) is False
    assert crypto.replay(rule, path, 99, root=tmp_path) is False       # no such line: not reproduced
    with pytest.raises(FileNotFoundError):
        crypto.replay(rule, "svc/missing.py", 1, root=tmp_path)
    with pytest.raises(ValueError):
        crypto.replay("no-such-rule", path, 1, root=tmp_path)


def test_replay_uses_context_lines(tmp_path):
    # the context rule needs the neighbouring line; replay must re-read the file, not one line
    src = tmp_path / "h.py"
    src.write_text("import hashlib\n# password digest\nh = hashlib.md5(pw).hexdigest()\n")
    (f,) = crypto.scan_text(src.read_text(), "h.py")
    assert crypto.replay("weak-hash-security-context", "h.py", 3, root=tmp_path) is True
    src.write_text("import hashlib\n# file checksum\nh = hashlib.md5(pw).hexdigest()\n")
    assert crypto.replay("weak-hash-security-context", "h.py", 3, root=tmp_path) is False


# ---------------------------------------------------------------- inventory and PQC report

MIXED = """\
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
sig = ec.ECDSA(hashes.SHA256())
kx = x25519.X25519PrivateKey.generate()
cipher = AES-256-GCM
legacy = AES-128
digest = hashlib.sha3_256(data)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
cert = open("certs/server.pem").read()
"""


def test_inventory_on_a_mixed_file():
    uses = crypto.inventory(MIXED, "svc/crypto.py")
    by = {u.primitive: u for u in uses}
    assert by["RSA"].quantum_vulnerable is True and "ML-KEM" in by["RSA"].migration
    assert by["ECDSA"].quantum_vulnerable is True and "ML-DSA" in by["ECDSA"].migration
    assert by["X25519"].quantum_vulnerable is True and "hybrid X25519+ML-KEM" in by["X25519"].migration
    assert by["AES-256"].quantum_vulnerable is False
    assert by["AES-128"].quantum_vulnerable == "weakened" and "AES-256" in by["AES-128"].migration
    assert by["SHA-2"].quantum_vulnerable is False
    assert by["SHA-3"].quantum_vulnerable is False
    assert by["TLS 1.3"].quantum_vulnerable is True
    assert by["key/certificate file"].family == "keyfile"
    assert all(u.path == "svc/crypto.py" and u.line >= 1 for u in uses)


def test_keyfile_by_extension_is_inventoried():
    (u,) = [u for u in crypto.inventory("", "certs/server.jks") if u.family == "keyfile"]
    assert u.quantum_vulnerable == "unknown"


def test_pqc_report_numbers():
    uses = crypto.inventory(MIXED, "svc/crypto.py") + crypto.inventory("h = hashlib.sha256(x)\n", "svc/safe.py")
    rep = crypto.pqc_report(uses)
    assert rep["sites"] == len(uses)
    assert rep["files_with_crypto"] == 2 and rep["files_affected"] == 1
    assert rep["blast_radius"] == 0.5
    assert rep["quantum_vulnerable_sites"] == sum(1 for u in uses if u.quantum_vulnerable is True)
    assert rep["weakened_sites"] == 1
    assert set(rep["migrations"]) == {"svc/crypto.py"}
    assert rep["primitives"]["RSA"] >= 1 and rep["primitives"]["SHA-2"] >= 1
    tm = rep["threat_models"]
    assert set(tm) == {"classical", "cryptographically-relevant-quantum", "ai-assisted"}
    assert "RSA" in tm["cryptographically-relevant-quantum"]["threatens"]
    assert "AES-128" in tm["cryptographically-relevant-quantum"]["weakens"]
    assert tm["ai-assisted"]["threatens"] == []
    assert "SHA-2" not in tm["cryptographically-relevant-quantum"]["threatens"]


def test_pqc_report_on_nothing_is_none_not_zero():
    rep = crypto.pqc_report([])
    assert rep["blast_radius"] is None and rep["sites"] == 0 and rep["migrations"] == {}


def test_scan_target_walks_the_estate():
    res = crypto.scan_target(DEMO / "mixed-estate")
    assert res.files_scanned > 0
    assert {f.target for f in res.findings} == {"crypto-svc/signer.py"}
    assert res.report()["files_affected"] >= 1
