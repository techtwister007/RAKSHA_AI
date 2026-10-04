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


def test_package_json_reports_exact_pins_only():
    # a range says what is allowed, not what is installed — matching its floor would be a false positive
    deps = {d.package: d.version for d in
            supply.parse_package_json('{"dependencies":{"lodash":"^4.17.20","minimist":"1.2.5",'
                                      '"a":"link:../foo2","b":"https://x/pkg-2.0.0.tgz","c":"<1.0.0",'
                                      '"d":"github:u/r#v1.2.3","e":"workspace:*"}}', "package.json")}
    assert deps == {"minimist": "1.2.5"}


def test_lockfile_overrides_its_manifest(tmp_path):
    # package.json pins a vulnerable lodash but the lockfile resolved the fixed one: no finding
    (tmp_path / "package.json").write_text('{"dependencies":{"lodash":"4.17.20"}}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/lodash":{"version":"4.17.21"}},"dependencies":{"lodash":{"version":"4.17.21"}}}')
    assert scan_target(tmp_path).findings == []


def test_one_dependency_one_finding_across_manifest_and_lockfile(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"minimist":"1.2.5"}}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/minimist":{"version":"1.2.5"}},"dependencies":{"minimist":{"version":"1.2.5"}}}')
    found = [f for f in scan_target(tmp_path).findings if "minimist" in f.message]
    assert len(found) == 1 and found[0].target == "package-lock.json"


def test_parse_pyproject_runtime_pins_only():
    text = ('[build-system]\nrequires = ["setuptools>=61", "pyyaml==5.3.1"]\n'
            '[project]\nname = "x"\ndependencies = [\n  "requests>=2.25.1",\n'
            '  "pyyaml[extra]==5.3.1 ; python_version>\'3\'",\n]\n'
            '[project.optional-dependencies]\ndev = ["flask==1.0"]\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\nclick = "8.0.1"\nrich = "^13.0"\n')
    deps = {d.package: d.version for d in supply.parse_pyproject(text, "pyproject.toml")}
    assert deps == {"pyyaml": "5.3.1", "click": "8.0.1"}


def test_parse_go_mod_single_line_exclude_and_replace():
    text = ("module x\nrequire github.com/gin-gonic/gin v1.6.3\nrequire github.com/a/b v1.0.0\n"
            "exclude (\n\tgithub.com/c/d v0.1.0\n)\n"
            "replace github.com/a/b => github.com/a/b v1.9.1\n")
    deps = {d.package: d.version for d in supply.parse_go_mod(text, "go.mod")}
    assert deps == {"github.com/gin-gonic/gin": "1.6.3", "github.com/a/b": "1.9.1"}


def test_maven_tag_order_does_not_matter():
    pom = ("<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind"
           "</artifactId><scope>compile</scope><version>2.9.8</version></dependency>")
    (dep,) = supply.parse_maven(pom, "pom.xml")
    assert dep.version == "2.9.8"


@pytest.mark.parametrize("version,expected", [
    ("2.0", 3), ("2.0-beta9", 3), ("2.14.1", 3),   # all three Log4j CVEs
    ("2.15.0", 2), ("2.16.0", 1),                   # Log4Shell fixed; the later CVEs are not
    ("2.17.1", 0), ("2.12.4", 0), ("2.3.2", 0),     # fixed, including the backport lines
])
def test_log4j_ranges_match_osv(version, expected):
    deps = [supply.Dependency("Maven", "org.apache.logging.log4j:log4j-core", version, "pom.xml")]
    assert len(supply.scan_dependencies(deps)) == expected


@pytest.mark.parametrize("pkg,eco,version,vulnerable", [
    ("com.fasterxml.jackson.core:jackson-databind", "Maven", "2.12.6.1", False),
    ("com.fasterxml.jackson.core:jackson-databind", "Maven", "2.13.1", True),
    ("minimist", "npm", "0.2.4", False), ("minimist", "npm", "1.2.5", True),
    ("github.com/gin-gonic/gin", "Go", "1.7.6", True), ("github.com/gin-gonic/gin", "Go", "1.7.7", False),
    ("requests", "PyPI", "2.31", False), ("PyYAML", "PyPI", "5.3.1", True),
])
def test_backport_lines_and_boundaries(pkg, eco, version, vulnerable):
    assert bool(supply.scan_dependencies([supply.Dependency(eco, pkg, version, "m")])) is vulnerable


def test_dedup_keeps_distinct_build_free_findings(tmp_path):
    # two passwords in one file and the same CVE in two services are four findings, not two
    for svc in ("svc_a", "svc_b"):
        (tmp_path / svc).mkdir()
        (tmp_path / svc / "package-lock.json").write_text(
            '{"packages":{"node_modules/minimist":{"version":"1.2.5"}}}')
    (tmp_path / "svc_a" / "settings.py").write_text(
        'DB_PASSWORD = "Xk9mQ2vL7pZw"\nADMIN_PASSWORD = "Qw8eRt5yUi2o"\n')
    found = scan_target(tmp_path).findings
    assert len([f for f in found if "minimist" in f.message]) == 2
    assert len([f for f in found if f.oracle == "secrets:generic-password-assign"]) == 2


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


def test_dotted_api_key_names_are_detected():
    # api.key (Spring/.properties form) and an unquoted assignment were both missed before
    (f,) = secrets.scan_text("api.key=A1b2C3d4E5f6G7h8X9\n", "application.properties")
    assert f.oracle == "secrets:generic-api-key"


def test_secrets_scanned_in_c_rust_and_key_files(tmp_path):
    # the scan must reach C/Rust source and bare key files, not only scripting languages
    from raksha.lanes.buildfree import _SECRET_EXT, _SECRET_NAMES
    assert ".c" in _SECRET_EXT and ".rs" in _SECRET_EXT and ".pem" in _SECRET_EXT
    assert "id_rsa" in _SECRET_NAMES
    (tmp_path / "creds.c").write_text('const char* k = "AKIA2QX7RB5NLM3PZK4W";\n')
    res = scan_target(tmp_path)
    assert any(f.oracle == "secrets:aws-access-key-id" for f in res.findings)


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


# ---------------------------------------------------------------- secrets precision

@pytest.mark.parametrize("line", [
    'password = os.environ["DB_PASS"]', 'password = config.get("database", "password")',
    'password = request.form["password"]', 'password = hashlib.sha256(raw).hexdigest()',
    'pwd = os.getcwd()', 'token = generate_csrf_token_for_user(user)', 'password=getpass()',
    'self.token = refresh_access_token_from_cache()', 'const authToken: AuthTokenProviderType',
    'SECRET = loadSecretFromKeystore();', 'secret_key = settings.SECRET_KEY', 'token: str',
    'bypass = "aB3dE5fG7hJ9kL"', 'password = "changeme"',
])
def test_expressions_in_code_are_not_secrets(line):
    assert secrets.scan_text(line, "app/service.py") == []


@pytest.mark.parametrize("line", [
    "DB_PASSWORD=${DB_PASSWORD}", "spring.datasource.password=${SPRING_DATASOURCE_PASSWORD}",
    "secret: SECRET_KEY_FROM_VAULT_REF", "password: !vault |",
])
def test_config_references_are_not_secrets(line):
    assert secrets.scan_text(line, "config/application.yml") == []


@pytest.mark.parametrize("line", [
    '"password": "Xk9mQ2vL7pZ",', 'DB_PASS = "Xk9#mQ2vL7"', 'client_secret = "8Q~4nX.yZ2-wq9Lp3Rr8tT"',
    'GH = "ghp_' + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2" + '"',
    'x = "xoxb-123456789012-abcdefABCDEF"', 'url = "mongodb://admin:S3cr3tP4ss@db.internal:27017"',
    'STRIPE = "sk_live_' + "4eC39HqLyjWDarjtT1zdp7dc" + '"', "-----BEGIN ENCRYPTED PRIVATE KEY-----",
])
def test_real_secrets_are_found(line):
    assert secrets.scan_text(line, "app/settings.py")


def test_aws_documentation_example_key_is_not_reported():
    assert secrets.scan_text('k = "AKIAIOSFODNN7EXAMPLE"', "app/x.py") == []


def test_secrets_in_test_fixtures_rank_low():
    (f,) = secrets.scan_text('password = "Xk9mQ2vL7pZ"', "tests/fixtures/x.py")
    assert f.severity == "low" and f.is_reportable


# ---- reachability: proven present is not proven reached -----------------------------------------

def test_dependency_findings_say_whether_the_code_imports_the_package():
    from raksha.lanes.buildfree import scan_target
    r = scan_target(pathlib.Path(__file__).parents[1] / "demo-targets" / "mixed-estate")
    reach = {f.frames[0].symbol: f.reachability for f in r.findings if f.oracle == "osv:version-match"}
    assert reach["minimist"] == "imported" and reach["requests"] == "imported"
    assert reach["lodash"] == "not-imported" and reach["pyyaml"] == "not-imported"
    assert reach["github.com/gin-gonic/gin"] == "unknown"        # no Go source in the tree at all
    # a secret or an API exposure carries no reachability field — it is not a dependency match
    assert all(f.reachability is None for f in r.findings if f.oracle != "osv:version-match")


def test_reachability_ranks_an_unreached_critical_below_a_reached_medium():
    from raksha.lanes.buildfree import scan_target
    from raksha.risk import register
    rows = register(scan_target(pathlib.Path(__file__).parents[1] / "demo-targets" / "mixed-estate").findings)
    score = {r.finding.frames[0].symbol: r.score for r in rows if r.finding.frames}
    assert score["requests"] > score["pyyaml"]       # medium+imported outranks critical+not-imported
    assert score["minimist"] > score["lodash"]
    assert all(r.as_dict()["reachability"] in ("imported", "not-imported", "unknown", None) for r in rows)


def test_import_index_handles_each_ecosystem_shape():
    from raksha.lanes.supply import ImportIndex
    ix = ImportIndex()
    ix.add("a.py", "from yaml import safe_load\nimport requests.adapters\n")
    ix.add("b.ts", "import express from 'express';\nconst m = require(\"minimist\");\n")
    ix.add("c.go", 'package x\nimport (\n\t"fmt"\n\t"github.com/gin-gonic/gin"\n)\n')
    ix.add("D.java", "import org.apache.logging.log4j.LogManager;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n")
    assert ix.reaches("PyPI", "PyYAML") == "imported" and ix.reaches("PyPI", "requests") == "imported"
    assert ix.reaches("PyPI", "flask") == "not-imported"
    assert ix.reaches("npm", "express") == "imported" and ix.reaches("npm", "lodash") == "not-imported"
    assert ix.reaches("Go", "github.com/gin-gonic/gin") == "imported"
    assert ix.reaches("Maven", "org.apache.logging.log4j:log4j-core") == "imported"
    assert ix.reaches("Maven", "com.fasterxml.jackson.core:jackson-databind") == "imported"
    assert ix.reaches("Maven", "org.springframework:spring-core") == "not-imported"
    assert ImportIndex().reaches("PyPI", "requests") == "unknown"
