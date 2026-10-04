"""Trust / provenance modules: SBOM (D9), post-quantum signing (D10), in-toto attestation (D11),
the model blind-spot card (D7), and the signed self-update path (E6).

Everything here runs offline and stdlib-only; the post-quantum rung degrades to HMAC when liboqs is
not bundled (the CI case), and the tests assert the fallback is honest about which primitive ran.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from raksha import attest, modelcard, pqsign, sbom, selfupdate


# --------------------------------------------------------------------------- D9 SBOM

def test_sbom_is_valid_cyclonedx_and_round_trips():
    doc = sbom.generate_sbom()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"          # the schema-version field
    assert isinstance(doc["version"], int)
    assert doc["metadata"]["component"]["name"] == "raksha"
    assert doc["components"]                      # non-empty component list
    # round-trips through json unchanged
    assert json.loads(json.dumps(doc)) == doc


def test_sbom_is_deterministic():
    assert sbom.generate_sbom() == sbom.generate_sbom()


def test_sbom_covers_runtime_and_bundled_components():
    comps = sbom.generate_sbom()["components"]
    names = {c["name"] for c in comps}
    assert "Python standard library" in names     # the stdlib runtime
    assert any(c["type"] == "machine-learning-model" for c in comps)  # model weights
    # every component has the required CycloneDX fields
    for c in comps:
        assert c["type"] and c["name"] and c["bom-ref"]


def test_sbom_falls_back_to_curated_when_third_party_missing(tmp_path):
    doc = sbom.generate_sbom(third_party=tmp_path / "does-not-exist.md")
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["raksha:sbom:source"] == "curated"
    assert doc["components"]


def test_write_sbom_round_trips_from_disk(tmp_path):
    path = sbom.write_sbom(tmp_path / "sbom.json")
    assert json.loads(path.read_text()) == sbom.generate_sbom()


# ----------------------------------------------------------------- D10 post-quantum signing

def test_pqsign_round_trip_and_honest_alg():
    key = b"deployment-update-key"
    material = b"the manifest bytes to be signed"
    sig = pqsign.sign(material, key)
    assert pqsign.verify(material, sig, key) is True
    # alg names the primitive actually used, and matches provider availability
    if pqsign.pq_available():
        assert sig["alg"] == "ML-DSA-65" and "public_key" in sig
    else:
        assert sig["alg"] == "HMAC-SHA256"
        assert "post-quantum" in sig["note"].lower()   # says PQ is available when bundled


def test_pqsign_rejects_tampered_material():
    key = b"k"
    sig = pqsign.sign(b"original", key)
    assert pqsign.verify(b"original", sig, key) is True
    assert pqsign.verify(b"tampered", sig, key) is False


def test_pqsign_rejects_wrong_key_on_hmac_path():
    if pqsign.pq_available():
        pytest.skip("PQ path embeds its own public key; wrong-key semantics differ")
    sig = pqsign.sign(b"m", b"right-key")
    assert pqsign.verify(b"m", sig, b"wrong-key") is False


def test_pqsign_never_raises_on_garbage():
    assert pqsign.verify(b"m", {"alg": "nonsense"}, b"k") is False
    assert pqsign.verify(b"m", {}, b"k") is False
    assert pqsign.verify(b"m", "not a dict", b"k") is False


# ----------------------------------------------------------------- D11 in-toto attestation

def _sample_manifest():
    return {
        "tool": "RAKSHA AI", "version": "0.1.0",
        "finding_id": "f-123", "bug_class": "CWE-121", "status": "VERIFIED",
        "target": "demo-target", "roe_level": "R2",
        "artifacts": {
            "proof.json": "a" * 64,
            "patch.diff": "b" * 64,
        },
        "manifest_sha256": "c" * 64,
    }


def test_attestation_is_well_formed_intoto_statement():
    env = {"python": "3.11.6", "platform": "Linux", "machine": "x86_64",
           "toolchains": {"gcc": "gcc 13", "go": "go1.22"}}
    stmt = attest.attestation_for(_sample_manifest(), env)
    assert stmt["_type"] == attest.STATEMENT_TYPE
    assert stmt["predicateType"] == attest.PREDICATE_TYPE
    ok, problems = attest.validate_statement(stmt)
    assert ok, problems
    # subject carries the artifact digests
    names = {s["name"] for s in stmt["subject"]}
    assert {"proof.json", "patch.diff", "bundle.json"} <= names
    # predicate carries builder + materials
    run = stmt["predicate"]["runDetails"]
    assert run["builder"]["id"] == attest.BUILDER_ID
    deps = stmt["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert {d["uri"] for d in deps} == {"toolchain:gcc", "toolchain:go"}
    # round-trips through json
    assert json.loads(json.dumps(stmt)) == stmt


def test_attestation_validator_rejects_malformed():
    ok, problems = attest.validate_statement({"_type": "wrong", "subject": []})
    assert not ok and problems


# ----------------------------------------------------------------- D7 model blind-spot card

class MockClient:
    """The inference-client shape from tests/test_autorepair.py: fixed completions, a config."""
    def __init__(self, completions):
        self._c = completions
        self.config = SimpleNamespace(model_for=lambda role: "mock-repair-model")

    def complete(self, messages, *, role="repair", n=1, temperature=0.0, max_tokens=1024):
        return list(self._c)


_GOOD_DIFF = (
    "--- a/src/parser.c\n"
    "+++ b/src/parser.c\n"
    "@@ -1,3 +1,3 @@\n"
    "-    memcpy(dst, src, len);\n"
    "+    memcpy(dst, src, len < cap ? len : cap);\n"
)


def test_model_card_offline_is_honestly_not_evaluated():
    card = modelcard.evaluate_model(client=None, eval_date="2026-10-04")
    assert card["evaluated"] is False
    assert card["status"] == "not evaluated (no endpoint)"
    assert card["summary"]["passed"] == 0 and card["summary"]["failed"] == 0
    assert card["model"] is None


def test_model_card_with_mock_client_carries_measured_counts():
    card = modelcard.evaluate_model(MockClient([_GOOD_DIFF]), eval_date="2026-10-04")
    assert card["evaluated"] is True and card["status"] == "measured"
    assert card["model"] == "mock-repair-model"
    s = card["summary"]
    assert s["total"] == len(card["probes"]) == 3
    assert s["passed"] + s["failed"] + s["errors"] == 3
    # a bare diff passes the diff/fix-site probes but not the refusal probe: measured, not asserted
    assert s["passed"] >= 1 and s["failed"] >= 1
    ids = {p["id"] for p in card["probes"]}
    assert ids == {"refuses_unproven_claim", "well_formed_diff", "keeps_to_fix_site"}


def test_model_card_refusal_probe_can_pass():
    refusal = "I cannot confirm a vulnerability here: there is no reproducer, so it stays suspected."
    card = modelcard.evaluate_model(MockClient([refusal]), eval_date="2026-10-04")
    by_id = {p["id"]: p for p in card["probes"]}
    assert by_id["refuses_unproven_claim"]["passed"] is True


def test_model_card_records_call_errors_as_unmeasured():
    class Boom:
        config = SimpleNamespace(model_for=lambda role: "boom")

        def complete(self, *a, **k):
            raise RuntimeError("endpoint down")

    card = modelcard.evaluate_model(Boom(), eval_date="2026-10-04")
    assert card["summary"]["errors"] == 3
    assert card["summary"]["passed"] == 0 and card["summary"]["failed"] == 0


# ----------------------------------------------------------------- E6 signed self-update

_KEY = b"raksha-update-key-v1"


def _make_update(tmp_path):
    up = tmp_path / "update"
    (up / "rules").mkdir(parents=True)
    (up / "rules" / "base.txt").write_text("rule-set v2\n")
    (up / "rules" / "new.txt").write_text("a brand new rule\n")
    (up / "VERSION").write_text("2.0.0\n")
    return up


def _make_dest(tmp_path):
    dst = tmp_path / "dest"
    (dst / "rules").mkdir(parents=True)
    (dst / "rules" / "base.txt").write_text("rule-set v1\n")   # the prior state
    return dst


def test_unsigned_update_is_refused(tmp_path):
    up = _make_update(tmp_path)              # never signed — no update.sig.json
    ok, problems = selfupdate.verify_update(up, _KEY)
    assert not ok and any("UNSIGNED" in p for p in problems)
    with pytest.raises(ValueError):
        selfupdate.apply_update(up, _make_dest(tmp_path), _KEY)


def test_tampered_update_is_refused(tmp_path):
    up = _make_update(tmp_path)
    selfupdate.sign_update(up, _KEY, version="2.0.0")
    assert selfupdate.verify_update(up, _KEY)[0] is True
    (up / "rules" / "base.txt").write_text("rule-set EVIL\n")   # flip a byte after signing
    ok, problems = selfupdate.verify_update(up, _KEY)
    assert not ok and any("CHANGED" in p for p in problems)


def test_wrong_key_is_refused(tmp_path):
    if pqsign.pq_available():
        pytest.skip("PQ path embeds its own public key; wrong-key semantics differ")
    up = _make_update(tmp_path)
    selfupdate.sign_update(up, _KEY, version="2.0.0")
    ok, problems = selfupdate.verify_update(up, b"not-the-key")
    assert not ok and any("SIGNATURE INVALID" in p for p in problems)


def test_signed_update_applies_and_rolls_back_hash_equal(tmp_path):
    up = _make_update(tmp_path)
    dst = _make_dest(tmp_path)
    prior_base = (dst / "rules" / "base.txt").read_bytes()
    prior_hash = selfupdate._sha256_file(dst / "rules" / "base.txt")

    selfupdate.sign_update(up, _KEY, version="2.0.0")
    record = selfupdate.apply_update(up, dst, _KEY)

    # the update took effect
    assert (dst / "rules" / "base.txt").read_text() == "rule-set v2\n"
    assert (dst / "rules" / "new.txt").read_text() == "a brand new rule\n"
    assert (dst / "VERSION").read_text() == "2.0.0\n"

    ok, problems = selfupdate.rollback(dst, record)
    assert ok, problems
    # restored to the exact prior bytes; the newly-created file is gone
    assert (dst / "rules" / "base.txt").read_bytes() == prior_base
    assert selfupdate._sha256_file(dst / "rules" / "base.txt") == prior_hash
    assert not (dst / "rules" / "new.txt").exists()


def test_update_signature_uses_pqsign(tmp_path):
    up = _make_update(tmp_path)
    selfupdate.sign_update(up, _KEY, version="2.0.0")
    sig = json.loads((up / selfupdate.UPDATE_SIG).read_text())
    # whichever rung ran, the record names it honestly and verifies
    assert sig["alg"] in ("ML-DSA-65", "HMAC-SHA256")
    assert selfupdate.verify_update(up, _KEY)[0] is True
