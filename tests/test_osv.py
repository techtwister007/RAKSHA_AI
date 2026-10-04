"""OSV-format loader + the expanded curated DB.

`parse_osv` must convert a real osv.dev record into RAKSHA's internal advisory shape; `load_osv_dir`
must read the bundled samples; `merge_into_db` must be idempotent; and the DB expansion must not
move any existing result or add a single false positive on the negative controls — the latter is the
precision promise the benchmark publishes.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from raksha.lanes import osv, supply, vulndb

REPO = pathlib.Path(__file__).parents[1]
SAMPLES = REPO / "raksha" / "data" / "osv"


# ---------------------------------------------------------------- parse_osv

def _spring4shell_record() -> dict:
    return {
        "id": "GHSA-36p3-wjmg-h94x",
        "aliases": ["CVE-2022-22965"],
        "summary": "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {"package": {"ecosystem": "Maven", "name": "org.springframework:spring-beans"},
             "ranges": [{"type": "ECOSYSTEM", "events": [
                 {"introduced": "0"}, {"fixed": "5.2.20.RELEASE"},
                 {"introduced": "5.3.0"}, {"fixed": "5.3.18"}]}]},
            {"package": {"ecosystem": "Maven", "name": "org.springframework:spring-webmvc"},
             "ranges": [{"type": "ECOSYSTEM", "events": [
                 {"introduced": "0"}, {"fixed": "5.2.20.RELEASE"},
                 {"introduced": "5.3.0"}, {"fixed": "5.3.18"}]}]},
        ],
        "database_specific": {"cwe_ids": ["CWE-94"], "severity": "CRITICAL"},
    }


def test_parse_osv_yields_the_internal_shape():
    adv = osv.parse_osv(_spring4shell_record())
    assert adv == {
        "ecosystem": "Maven",
        "package": "org.springframework:spring-beans",
        "id": "GHSA-36p3-wjmg-h94x",
        "aka": "CVE-2022-22965",
        "cwe": "CWE-94",
        "severity": "critical",
        "summary": "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)",
        "ranges": [{"introduced": "0", "fixed": "5.2.20.RELEASE"},
                   {"introduced": "5.3.0", "fixed": "5.3.18"}],
    }
    # the converted advisory must drop straight into the version-range machinery
    assert vulndb.affected_range(adv, "5.3.17") is not None
    assert vulndb.affected_range(adv, "5.3.18") is None          # fixed is exclusive
    assert vulndb.affected_range(adv, "5.2.20.RELEASE") is None  # backport line fixed


def test_parse_osv_all_fans_out_across_packages():
    advs = osv.parse_osv_all(_spring4shell_record())
    assert {a["package"] for a in advs} == {
        "org.springframework:spring-beans", "org.springframework:spring-webmvc"}
    assert all(a["id"] == "GHSA-36p3-wjmg-h94x" and a["aka"] == "CVE-2022-22965" for a in advs)


def test_parse_osv_maps_ecosystems_and_picks_cve_alias():
    rec = {"id": "GHSA-x", "aliases": ["GHSA-x", "CVE-2021-0001"],
           "database_specific": {"cwe_ids": ["CWE-400"], "severity": "HIGH"},
           "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}]}]}
    adv = osv.parse_osv(rec)
    assert adv["ecosystem"] == "Go" and adv["aka"] == "CVE-2021-0001" and adv["severity"] == "high"


def test_parse_osv_skips_unsupported_ecosystems():
    rec = {"id": "GHSA-y", "aliases": [],
           "affected": [{"package": {"ecosystem": "crates.io", "name": "foo"},
                         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]}]}
    assert osv.parse_osv(rec) is None
    assert osv.parse_osv_all(rec) == []


# ---------------------------------------------------------------- load_osv_dir

def test_load_osv_dir_reads_the_bundled_samples():
    advs = osv.load_osv_dir(SAMPLES)
    by = {(a["id"], a["package"]) for a in advs}
    # the two individual files + the two records inside all.json
    assert ("GHSA-36p3-wjmg-h94x", "org.springframework:spring-beans") in by
    assert ("GHSA-36p3-wjmg-h94x", "org.springframework:spring-webmvc") in by
    assert ("GHSA-jf85-cpcp-j695", "lodash") in by
    assert ("GHSA-6757-jp84-gxfx", "PyYAML") in by
    assert ("GHSA-69ch-w2m2-3vjp", "golang.org/x/text") in by
    assert len(advs) == 5


def test_load_osv_dir_accepts_a_single_file():
    advs = osv.load_osv_dir(SAMPLES / "GHSA-jf85-cpcp-j695.json")
    assert len(advs) == 1 and advs[0]["package"] == "lodash" and advs[0]["cwe"] == "CWE-1321"


def test_load_osv_dir_missing_path_is_empty():
    assert osv.load_osv_dir(SAMPLES / "does-not-exist") == []


# ---------------------------------------------------------------- merge_into_db

def test_merge_into_db_is_idempotent(tmp_path):
    db_path = tmp_path / "vulndb.json"
    db_path.write_text(json.dumps({"_comment": "seed", "advisories": []}))
    advs = osv.load_osv_dir(SAMPLES)

    first = osv.merge_into_db(advs, db_path)
    assert first["added"] == len(advs) and first["updated"] == 0 and first["total"] == len(advs)

    second = osv.merge_into_db(advs, db_path)
    assert second["added"] == 0 and second["updated"] == len(advs) and second["total"] == len(advs)

    data = json.loads(db_path.read_text())
    assert data["_comment"] == "seed"                      # top-level keys preserved
    assert len(data["advisories"]) == len(advs)            # no duplicates
    # the merged DB loads and matches
    db = vulndb.load(db_path)
    assert db.by_id("GHSA-jf85-cpcp-j695") is not None


def test_merge_updates_an_existing_advisory_in_place(tmp_path):
    db_path = tmp_path / "vulndb.json"
    db_path.write_text(json.dumps({"advisories": [
        {"ecosystem": "npm", "package": "lodash", "id": "GHSA-jf85-cpcp-j695", "aka": "CVE-2019-10744",
         "cwe": "CWE-1321", "severity": "low", "summary": "stale", "ranges": [{"introduced": "0", "fixed": "1.0.0"}]}]}))
    advs = [a for a in osv.load_osv_dir(SAMPLES) if a["id"] == "GHSA-jf85-cpcp-j695"]
    res = osv.merge_into_db(advs, db_path)
    assert res["added"] == 0 and res["updated"] == 1
    data = json.loads(db_path.read_text())
    assert len(data["advisories"]) == 1
    assert data["advisories"][0]["severity"] == "critical"            # replaced in place
    assert data["advisories"][0]["ranges"] == [{"introduced": "0", "fixed": "4.17.12"}]


# ---------------------------------------------------------------- the expanded DB

def test_expanded_db_has_grown_and_keeps_every_ecosystem():
    db = vulndb.load()
    assert len(db.advisories) >= 24
    assert {a["ecosystem"] for a in db.advisories} == {"Maven", "npm", "PyPI", "Go"}


@pytest.mark.parametrize("eco,pkg,version,expected_vulnerable", [
    # the pinned results the existing suite relies on must not move
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", True),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.17.1", False),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.12.4", False),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.12.6.1", False),
    ("npm", "lodash", "4.17.21", False), ("npm", "lodash", "4.17.20", True),
    ("npm", "minimist", "1.2.6", False), ("npm", "minimist", "1.2.5", True),
    ("PyPI", "pyyaml", "5.4", False), ("PyPI", "pyyaml", "5.3.1", True),
    ("PyPI", "requests", "2.31.0", False),
    ("Go", "github.com/gin-gonic/gin", "1.7.7", False),
    # a few of the newly added advisories resolve correctly
    ("Maven", "org.springframework:spring-beans", "5.3.17", True),
    ("Maven", "org.springframework:spring-beans", "5.3.18", False),
    ("Maven", "org.apache.commons:commons-text", "1.9", True),
    ("PyPI", "django", "3.2.12", True), ("PyPI", "django", "3.2.13", False),
    ("Go", "golang.org/x/text", "0.3.7", True), ("Go", "golang.org/x/text", "0.3.8", False),
])
def test_expanded_db_results_are_correct(eco, pkg, version, expected_vulnerable):
    deps = [supply.Dependency(eco, pkg, version, "m")]
    assert bool(supply.scan_dependencies(deps)) is expected_vulnerable


def test_expanded_db_adds_no_false_positive_on_negative_controls():
    # the DB grew; prove the growth did not start flagging any clean, patched control version
    from raksha.benchmark import NEGATIVE_CONTROLS, BenchReport, negative_controls
    rep = BenchReport()
    negative_controls(rep)
    assert rep.negative_controls == len(NEGATIVE_CONTROLS)
    assert rep.false_positives == 0, rep.false_positive_notes
