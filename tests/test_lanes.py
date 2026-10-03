"""Build-free lanes: supply chain (every ecosystem), secrets, version logic, and bump patches.

These prove the lane that makes "all languages" and "findings fast" true: proven findings on any
target with no build, no network, no language runtime.
"""

from __future__ import annotations

import pathlib

import pytest

from raksha.finding import DETERMINISTIC_MATCH, Status
from raksha.lanes import bump, scan_target, secrets, supply, vulndb
from raksha.lanes.version import compare, in_range

FIXTURES = pathlib.Path(__file__).parents[1] / "demo-targets" / "mixed-estate"


# ---------------------------------------------------------------- version logic

@pytest.mark.parametrize("a,b,expected", [
    ("2.14.1", "2.17.1", -1), ("2.17.1", "2.14.1", 1), ("1.2.3", "1.2.3", 0),
    ("4.17.20", "4.17.21", -1), ("1.6.3", "1.7.0", -1), ("v1.2.6", "1.2.6", 0),
    ("2.17.1-rc1", "2.17.1", -1),          # pre-release sorts before the release
    ("2.13.2.1", "2.13.2", 1),
])
def test_version_compare(a, b, expected):
    assert compare(a, b) == expected


def test_in_range():
    assert in_range("2.14.1", "2.0.0", "2.17.1")
    assert not in_range("2.17.1", "2.0.0", "2.17.1")   # fixed version is excluded
    assert not in_range("1.0.0", "2.0.0", "2.17.1")
    assert in_range("5.0", "0.0.0", None)              # unbounded above


# ---------------------------------------------------------------- manifest parsers

def test_parse_maven_follows_property_indirection():
    text = """<properties><log4j.version>2.14.1</log4j.version></properties>
    <dependency><groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>"""
    (dep,) = supply.parse_maven(text, "pom.xml")
    assert dep.package == "org.apache.logging.log4j:log4j-core" and dep.version == "2.14.1"


def test_parse_requirements_and_go_and_npm():
    (py,) = supply.parse_requirements("pyyaml==5.3.1  # yaml\n", "requirements.txt")
    assert py.package == "pyyaml" and py.version == "5.3.1" and py.ecosystem == "PyPI"
    deps = supply.parse_go_mod("require (\n\tgithub.com/gin-gonic/gin v1.6.3\n)\n", "go.mod")
    assert deps[0].package == "github.com/gin-gonic/gin" and deps[0].version == "1.6.3"
    npm = supply.parse_package_lock('{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}', "package-lock.json")
    assert npm[0].package == "lodash" and npm[0].version == "4.17.20"


# ---------------------------------------------------------------- the supply lane

def test_scan_finds_vulnerable_deps_across_ecosystems():
    res = scan_target(FIXTURES)
    langs = {f.language for f in res.findings if f.oracle.startswith("osv")}
    assert {"java", "javascript", "python", "go"} & langs == {"javascript", "python", "go"} or "java" in langs
    assert langs.issuperset({"javascript", "python", "go"})


def test_every_supply_finding_is_confirmed_by_deterministic_match():
    res = scan_target(FIXTURES)
    supply_findings = [f for f in res.findings if f.oracle.startswith("osv")]
    assert supply_findings
    for f in supply_findings:
        assert f.status is Status.CONFIRMED
        assert f.is_reportable
        assert f.reproducer is not None
        assert f.reproducer.kind == DETERMINISTIC_MATCH       # honest: a match, not an exploit
        assert f.reproducer.detail and f.fix_site_set


def test_a_patched_version_is_not_flagged():
    db = vulndb.load()
    # lodash 4.17.21 is the fixed version -> no finding
    deps = [supply.Dependency("npm", "lodash", "4.17.21", "package-lock.json")]
    assert scan_dependencies_count(deps, db) == 0
    deps = [supply.Dependency("npm", "lodash", "4.17.20", "package-lock.json")]
    assert scan_dependencies_count(deps, db) == 1


def scan_dependencies_count(deps, db):
    return len(supply.scan_dependencies(deps, db))


def test_unknown_package_yields_nothing():
    db = vulndb.load()
    deps = [supply.Dependency("npm", "left-pad", "1.0.0", "package-lock.json")]
    assert scan_dependencies_count(deps, db) == 0


# ---------------------------------------------------------------- secrets

def test_secrets_lane_finds_real_secrets_and_skips_placeholders():
    text = (FIXTURES / "config" / "app.properties").read_text()
    findings = secrets.scan_text(text, "config/app.properties")
    ids = {f.oracle for f in findings}
    assert "secrets:aws-secret-access-key" in ids
    assert "secrets:generic-password-assign" in ids
    # changeme and <your-token-here> are placeholders and must not be flagged
    assert not any("changeme" in f.message or "your-token" in f.message for f in findings)


def test_secrets_are_redacted_in_the_record():
    text = 'password = "S3cr3tP@ssw0rd123"\n'
    (f,) = secrets.scan_text(text, "x.properties")
    assert "S3cr3tP@ssw0rd123" not in f.message          # never store the secret in the clear
    assert "S3cr" in f.message and "…" in f.message


def test_low_entropy_values_are_not_flagged_as_secrets():
    # a repetitive value is almost certainly not a real secret
    assert secrets.scan_text('api_key = "aaaaaaaaaaaaaaaa"\n', "x.env") == []


# ---------------------------------------------------------------- bump patches

def test_bump_maven_through_property():
    pom = ("<properties><log4j.version>2.14.1</log4j.version></properties>\n"
           "<dependency><groupId>org.apache.logging.log4j</groupId>"
           "<artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>\n")
    diff = bump.bump("Maven", pom, "org.apache.logging.log4j:log4j-core", "2.17.1")
    assert "-" in diff and "2.17.1" in diff and "2.14.1" in diff


def test_bump_each_ecosystem_changes_the_version():
    assert "pyyaml==5.4" in bump.bump("PyPI", "pyyaml==5.3.1\n", "pyyaml", "5.4")
    assert "4.17.21" in bump.bump("npm", '{"dependencies":{"lodash":"^4.17.20"}}', "lodash", "4.17.21")
    assert "v1.7.0" in bump.bump("Go", "\tgithub.com/gin-gonic/gin v1.6.3\n", "github.com/gin-gonic/gin", "1.7.0")


def test_bump_is_a_noop_when_nothing_matches():
    assert bump.bump("PyPI", "flask==3.0.0\n", "django", "4.0") == ""


# ---------------------------------------------------------------- end to end

def test_build_free_scan_is_fast_and_language_agnostic():
    res = scan_target(FIXTURES)
    assert res.seconds < 5.0                              # no build, no network: effectively instant
    assert res.manifests_found >= 3
    langs = {f.language for f in res.findings}
    assert len(langs) >= 4                                # js, python, go, 'any' (secrets)
    assert all(f.is_reportable for f in res.findings)     # nothing unproven in the output
