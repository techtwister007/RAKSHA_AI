"""Validate our output against the real OASIS SARIF 2.1.0 schema.

The dossier's instruction was "use SARIF + a proof block -- don't invent"
(`06_gaps_and_fixes.md` gap 3). That is only worth anything if the output is *actually*
valid SARIF, so this test checks it against the published schema rather than against
our own idea of the format. The schema is vendored under `schemas/` because the product
must work with no network.

If this test fails, our findings cannot be consumed by any standard SARIF tool and the
interoperability claim is false.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from raksha.finding import (
    GATE_ORDER,
    RepairLane,
    ReplayResult,
    Reproducer,
    Signature,
    to_sarif_log,
    utcnow,
)
from raksha.oracles import KEYSTONE_ORACLES

SCHEMA_PATH = pathlib.Path(__file__).parents[1] / "schemas" / "sarif-2.1.0.json"

jsonschema = pytest.importorskip("jsonschema")

pytestmark = pytest.mark.skipif(
    not SCHEMA_PATH.exists(),
    reason="vendored SARIF schema missing; run scripts/fetch_sarif_schema.sh",
)


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def _all_keystone_findings(fixture_text):
    findings = []
    for name in ("asan_heap_overflow.txt", "jazzer_jndi.txt", "pysecsan_cmd_injection.txt"):
        raw = fixture_text(name)
        for oracle in KEYSTONE_ORACLES:
            findings.extend(oracle.parse(raw, target="keystone"))
    assert len(findings) == 3
    return findings


def test_suspected_findings_emit_valid_sarif(schema, fixture_text):
    log = to_sarif_log(_all_keystone_findings(fixture_text))
    jsonschema.validate(log, schema)


def test_a_fully_verified_finding_emits_valid_sarif(schema, fixture_text):
    """The fullest proof block -- reproducer, both replays, five gate results,
    signatures and metrics -- must still validate."""
    findings = _all_keystone_findings(fixture_text)

    f = findings[1]
    f.attach_reproducer(
        Reproducer.from_bytes(b"${jndi:ldap://x/a}", ["./replay.sh"], minimised=True)
    )
    f.record_replay_before(
        ReplayResult(oracle_fired=True, at=utcnow(), abort_signature="sig", exit_code=77)
    )
    f.confirm()
    f.mark_patched("--- a\n+++ b\n", RepairLane.TEMPLATE)
    for check in GATE_ORDER:
        f.record_gate(check, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow(), exit_code=0))
    f.add_signature(Signature("key-1", "Maj A", "sig", utcnow()))
    f.add_signature(Signature("key-2", "Capt B", "sig", utcnow()))
    f.verify()

    log = to_sarif_log(findings)
    jsonschema.validate(log, schema)

    result = next(
        r for r in log["runs"][0]["results"]
        if r["properties"]["raksha/proof"]["id"] == f.id
    )
    assert result["properties"]["raksha/proof"]["status"] == "VERIFIED"


def test_an_empty_run_is_still_valid_sarif(schema):
    """A clean target produces a valid, empty report -- not a crash and not silence."""
    jsonschema.validate(to_sarif_log([]), schema)
