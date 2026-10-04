"""ARVO benchmark loader seam.

The loader must be honest offline (no manifest → [] + a clear note), must parse a well-formed
manifest into cases, must reject a malformed one, and — the point of a seam — must produce a case
that runs end-to-end through the normal autofuzz → gate path when pointed at an in-repo target.
"""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest

from raksha.benchmark import run_cases
from raksha.benchmark_arvo import ArvoCase, arvo_cases, load_manifest, manifest_status
from raksha.finding import Status

REPO = pathlib.Path(__file__).parents[1]
FIXTURE = REPO / "tests" / "arvo_fixtures" / "arvo_manifest.json"
HAVE_GCC = shutil.which("gcc") is not None


# ---------------------------------------------------------------- the honest offline state

def test_missing_manifest_yields_no_cases_and_a_clear_note(tmp_path):
    missing = tmp_path / "nope.json"
    assert arvo_cases(missing) == []
    assert load_manifest(missing) == []
    note = manifest_status(missing)
    assert "offline" in note and "0 ARVO cases" in note


def test_empty_manifest_yields_no_cases(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("[]")
    assert arvo_cases(empty) == []
    assert "empty" in manifest_status(empty)


def test_malformed_manifest_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "an array"}')
    with pytest.raises(ValueError):
        load_manifest(bad)
    # an entry missing a required field is also rejected
    bad.write_text('[{"name": "x", "language": "c/c++"}]')   # no source_path
    with pytest.raises(ValueError):
        load_manifest(bad)


# ---------------------------------------------------------------- parsing a real manifest

def test_load_manifest_parses_and_resolves_paths(tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps([
        {"name": "arvo-1", "language": "c/c++", "source_path": "src", "bug_class": "CWE-787",
         "reproducer_path": "crash.bin", "max_execs": 1234}]))
    (tmp_path / "src").mkdir()
    (tmp_path / "crash.bin").write_bytes(b"\x00")
    (case,) = load_manifest(manifest)
    assert isinstance(case, ArvoCase)
    assert case.name == "arvo-1" and case.language == "c/c++" and case.bug_class == "CWE-787"
    assert case.source_path == tmp_path / "src"                 # resolved relative to the manifest
    assert case.reproducer_path == tmp_path / "crash.bin"
    assert case.max_execs == 1234


def test_bundled_fixture_loads_one_case():
    cases = arvo_cases(FIXTURE)
    assert [name for name, _ in cases] == ["arvo-demo-c-nolibfuzzer"]
    assert "1 case" in manifest_status(FIXTURE)


# ---------------------------------------------------------------- end-to-end through the gate

@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to build and fuzz the demo target")
def test_synthetic_arvo_case_reaches_verified_through_the_normal_path():
    # the synthetic manifest points at demo-targets/c-nolibfuzzer; the loader drives it through the
    # same autofuzz -> confirm -> repair -> five-check gate path as every other target
    report = run_cases(arvo_cases(FIXTURE))
    (result,) = report.results
    assert result.name == "arvo-demo-c-nolibfuzzer"
    assert result.status in (Status.CONFIRMED.value, Status.VERIFIED.value)
    assert result.evidence == "exploit-replay"                 # a real crash, replayed
