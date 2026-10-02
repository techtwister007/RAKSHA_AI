"""Tests for the oracle layer, and for the keystone claim itself.

`test_the_keystone_*` are the tests that decide whether the architecture holds. The
dossier states the claim plainly (`14_open_questions.md` item 1): if a Java reproducer,
a C trace and a Python abort cannot all become valid records that one gate consumes,
then "one pipeline, every language" is false and we need to know immediately.
"""

from __future__ import annotations

import json

import pytest

from raksha.finding import (
    GATE_ORDER,
    InvariantViolation,
    RepairLane,
    ReplayResult,
    Reproducer,
    Status,
    dedup,
    reportable,
    to_sarif_log,
    utcnow,
)
from raksha.oracles import AsanOracle, JazzerOracle, KEYSTONE_ORACLES, PySecSanOracle


# ------------------------------------------------------------------- ASan


def test_asan_parses_a_heap_overflow(fixture_text):
    (f,) = AsanOracle().parse(fixture_text("asan_heap_overflow.txt"), target="parser")

    assert f.language == "c/c++"
    assert f.bug_class == "CWE-122"
    assert f.severity == "high"
    assert "heap-buffer-overflow" in f.message
    assert f.status is Status.SUSPECTED        # oracles never confirm

    assert f.frames[0].symbol == "parse_header"
    assert f.frames[0].uri == "/src/target/src/parser.c"
    assert f.frames[0].line == 142
    assert f.frames[0].column == 9


def test_asan_localises_to_target_code_not_to_the_fuzzer(fixture_text):
    """The top frame is target code here, but the seeder must never pick a tool frame."""
    (f,) = AsanOracle().parse(fixture_text("asan_heap_overflow.txt"), target="parser")
    assert f.fix_site_set[0].uri == "/src/target/src/parser.c"
    assert "compiler-rt" not in (f.fix_site_set[0].uri or "")


def test_asan_parses_ubsan_integer_overflow(fixture_text):
    (f,) = AsanOracle().parse(fixture_text("ubsan_int_overflow.txt"), target="frame")
    assert f.bug_class == "CWE-190"
    assert "signed integer overflow" in f.message
    assert f.fix_site_set[0].start_line == 57


def test_asan_is_silent_on_a_clean_run(fixture_text):
    assert AsanOracle().parse(fixture_text("clean_run.txt"), target="parser") == []


# ----------------------------------------------------------------- Jazzer


def test_jazzer_parses_the_log4shell_bug_class(fixture_text):
    (f,) = JazzerOracle().parse(fixture_text("jazzer_jndi.txt"), target="demo-svc")

    assert f.language == "java"
    assert f.bug_class == "CWE-917"            # JNDI lookup / Log4Shell
    assert f.severity == "critical"
    assert f.status is Status.SUSPECTED
    assert f.artifact_hint == "./crash-7f3a9b2c1d4e5f60"


def test_jazzer_skips_its_own_sanitizer_frame_when_localising(fixture_text):
    """The top frame is Jazzer's own hook; the fix site must be application code."""
    (f,) = JazzerOracle().parse(fixture_text("jazzer_jndi.txt"), target="demo-svc")
    site = f.fix_site_set[0]
    assert site.symbol == "com.example.svc.AuditLogger.write"
    assert site.uri == "com/example/svc/AuditLogger.java"
    assert site.start_line == 48


def test_jazzer_reconstructs_a_source_path_from_the_package(fixture_text):
    """A JVM frame reports only `AuditLogger.java`; SARIF needs a path."""
    (f,) = JazzerOracle().parse(fixture_text("jazzer_jndi.txt"), target="demo-svc")
    uris = [fr.uri for fr in f.frames]
    assert "com/example/svc/RequestHandler.java" in uris


def test_jazzer_parses_sql_injection(fixture_text):
    (f,) = JazzerOracle().parse(fixture_text("jazzer_sqli.txt"), target="demo-svc")
    assert f.bug_class == "CWE-89"
    assert f.severity == "high"
    assert f.fix_site_set[0].symbol == "com.example.dao.UserDao.findById"


def test_jazzer_does_not_inflate_an_ordinary_uncaught_exception():
    """An IndexOutOfBounds is a real bug but it is not a critical security issue."""
    raw = (
        "== Java Exception: java.lang.ArrayIndexOutOfBoundsException: Index 5 out of bounds\n"
        "\tat com.example.app.Parser.read(Parser.java:30)\n"
    )
    (f,) = JazzerOracle().parse(raw, target="demo-svc")
    assert f.severity == "low"
    assert f.bug_class == "CWE-125"


def test_jazzer_is_silent_on_a_clean_run(fixture_text):
    assert JazzerOracle().parse(fixture_text("clean_run.txt"), target="demo-svc") == []


# --------------------------------------------------------------- PySecSan


def test_pysecsan_parses_a_command_injection_sink_abort(fixture_text):
    (f,) = PySecSanOracle().parse(fixture_text("pysecsan_cmd_injection.txt"), target="runner")

    assert f.language == "python"
    assert f.bug_class == "CWE-78"
    assert f.severity == "high"
    assert f.oracle.endswith("detector")
    assert f.status is Status.SUSPECTED


def test_pysecsan_reverses_the_traceback_so_frame_zero_is_the_abort_site(fixture_text):
    """CPython prints outermost-first; a sanitizer trace is innermost-first.

    The dedup key and the fix-site seeder both assume frame 0 is the abort site, so the
    Python adapter has to normalise the order rather than leave it to callers.
    """
    (f,) = PySecSanOracle().parse(fixture_text("pysecsan_cmd_injection.txt"), target="runner")
    # The pysecsan hook frame is innermost, so it sorts first -- and is then skipped by
    # the localiser as a tool frame.
    assert "pysecsan" in (f.frames[0].uri or "")
    assert f.fix_site_set[0].uri == "/src/target/app/runner.py"
    assert f.fix_site_set[0].start_line == 57


def test_pysecsan_falls_back_to_the_verified_atheris_path(fixture_text):
    """When no detector message matches, the Atheris banner still yields a finding.

    This is the degrade-don't-die rung inside the parser: we lose CWE precision, never
    the finding.
    """
    (f,) = PySecSanOracle().parse(fixture_text("atheris_uncaught.txt"), target="records")
    assert f.oracle.endswith("atheris")
    assert f.bug_class == "CWE-125"            # IndexError
    assert f.severity == "low"
    assert f.fix_site_set[0].uri == "/src/target/app/records.py"


def test_pysecsan_is_silent_on_a_clean_run(fixture_text):
    assert PySecSanOracle().parse(fixture_text("clean_run.txt"), target="runner") == []


# =============================================================== THE KEYSTONE


KEYSTONE_FIXTURES = [
    ("asan_heap_overflow.txt", "c/c++", "CWE-122"),
    ("jazzer_jndi.txt", "java", "CWE-917"),
    ("pysecsan_cmd_injection.txt", "python", "CWE-78"),
]


def _route(raw: str, *, target: str):
    """Hand raw output to every oracle; the one that recognises it produces the record.

    This is the real ingest behaviour: no caller has to know which language produced the
    output. Exactly one oracle should claim it.
    """
    claimed = [f for oracle in KEYSTONE_ORACLES for f in oracle.parse(raw, target=target)]
    assert len(claimed) == 1, f"expected exactly one oracle to claim this output, got {len(claimed)}"
    return claimed[0]


@pytest.mark.parametrize("name,language,cwe", KEYSTONE_FIXTURES)
def test_the_keystone_every_oracle_emits_one_valid_record(fixture_text, name, language, cwe):
    """Three languages, one record shape, auto-routed."""
    f = _route(fixture_text(name), target="keystone")

    assert f.language == language
    assert f.bug_class == cwe
    assert f.status is Status.SUSPECTED
    assert f.frames, "a record with no frames cannot be localised or deduped"
    assert f.fix_site_set, "every record must carry at least one candidate fix site"
    assert f.abort_signature
    assert f.dedup_key()


@pytest.mark.parametrize("name,language,cwe", KEYSTONE_FIXTURES)
def test_the_keystone_one_gate_consumes_all_three(fixture_text, name, language, cwe):
    """The claim under test: the SAME gate code drives a C, a Java and a Python finding
    from SUSPECTED to VERIFIED, with no language-specific branching anywhere below the
    oracle layer."""
    f = _route(fixture_text(name), target="keystone")

    # --- the pipeline, identical for all three languages ---
    f.attach_reproducer(
        Reproducer.from_bytes(b"\xde\xad\xbe\xef", ["./replay.sh", "crash-1"], minimised=True)
    )
    f.record_replay_before(
        ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=f.abort_signature)
    )
    f.confirm()
    assert f.status is Status.CONFIRMED

    f.mark_patched("--- a/f\n+++ b/f\n@@\n-bad\n+good\n", RepairLane.TEMPLATE)
    for check in GATE_ORDER:
        f.record_gate(check, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow(), exit_code=0))
    f.verify()

    assert f.status is Status.VERIFIED
    assert f.gate_passed
    assert f.time_to_pov_seconds is not None
    assert f.time_to_patch_seconds is not None


def test_the_keystone_all_three_serialise_into_one_sarif_log(fixture_text):
    """One SARIF log holding a C, a Java and a Python finding, valid and portable."""
    findings = [_route(fixture_text(name), target="keystone")
                for name, _, _ in KEYSTONE_FIXTURES]

    log = to_sarif_log(findings)
    payload = json.loads(json.dumps(log))         # must survive a round trip

    results = payload["runs"][0]["results"]
    assert len(results) == 3
    assert {r["ruleId"] for r in results} == {"CWE-122", "CWE-917", "CWE-78"}

    languages = {r["properties"]["raksha/proof"]["language"] for r in results}
    assert languages == {"c/c++", "java", "python"}

    # Every record carries the proof block, and none of them is reportable yet.
    for r in results:
        proof = r["properties"]["raksha/proof"]
        assert proof["status"] == "SUSPECTED"
        assert proof["reproducer"] is None


def test_the_keystone_precision_holds_across_all_three_languages(fixture_text):
    """The scored claim: nothing without a replaying reproducer is ever reportable."""
    findings = [_route(fixture_text(name), target="keystone")
                for name, _, _ in KEYSTONE_FIXTURES]

    assert reportable(findings) == []

    for f in findings:
        with pytest.raises(InvariantViolation):
            f.confirm()

    # Prove exactly one of them, and only that one becomes reportable.
    chosen = findings[1]
    chosen.attach_reproducer(Reproducer.from_bytes(b"x", ["./replay.sh"]))
    chosen.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    chosen.confirm()

    assert reportable(findings) == [chosen]
    assert all(f.is_reportable for f in reportable(findings))


def test_the_keystone_dedup_works_across_languages(fixture_text):
    """Normalise must not collapse two different languages' bugs into one."""
    findings = [_route(fixture_text(name), target="keystone")
                for name, _, _ in KEYSTONE_FIXTURES]
    assert len({f.dedup_key() for f in findings}) == 3
    assert len(dedup(findings + findings)) == 3
