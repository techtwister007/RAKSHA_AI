"""Supply-chain v2 lanes: transitive deps, git-history secrets, VEX, KEV/EPSS, reproducible
builds, and the IaC hardening floor.

Each lane is build-free and deterministic, and each degrades to ``[]`` (or ``None``) when its
prerequisite — a lockfile, a git repo, a build tool — is absent. The negative controls that the
benchmark pins at zero false positives must stay at zero for these lanes too.
"""

from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

from raksha.finding import DETERMINISTIC_MATCH, Status
from raksha.lanes import githistory, iac, kev, reprobuild, supply, transitive, vex, vulndb
from raksha.lanes.buildfree import scan_target

REPO = pathlib.Path(__file__).parents[1]
MIXED = REPO / "demo-targets" / "mixed-estate"


# ================================================================ C1 transitive dependencies

def _write(root: pathlib.Path, rel: str, text: str) -> None:
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text)


def test_transitive_vuln_pulled_in_via_lockfile_is_found_and_flagged(tmp_path):
    # Only 'express' is a direct dependency (clean); the vulnerable 'minimist' is hoisted into the
    # lockfile as a transitive dependency express pulls in.
    _write(tmp_path, "package.json", json.dumps({
        "name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.2"}}))
    _write(tmp_path, "package-lock.json", json.dumps({
        "name": "app", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.18.2"}},
            "node_modules/express": {"version": "4.18.2", "dependencies": {"minimist": "1.2.5"}},
            "node_modules/minimist": {"version": "1.2.5"},
        }}))
    findings = transitive.scan_transitive(tmp_path)
    minimist = [f for f in findings if f.frames and f.frames[0].symbol == "minimist"]
    assert len(minimist) == 1
    f = minimist[0]
    assert f.status is Status.CONFIRMED and f.is_reportable
    assert f.reproducer.kind == DETERMINISTIC_MATCH
    assert f.transitive is True and "transitive dependency" in f.message
    assert "express" in f.dep_via                       # best-effort via chain names the parent


def test_direct_dependency_still_works_and_is_flagged_direct(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"minimist": "1.2.5"}}))
    _write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"minimist": "1.2.5"}},
                     "node_modules/minimist": {"version": "1.2.5"}}}))
    findings = transitive.scan_transitive(tmp_path)
    (f,) = [f for f in findings if f.frames and f.frames[0].symbol == "minimist"]
    assert f.transitive is False and "direct dependency" in f.message


def test_resolve_tree_degrades_to_direct_when_tool_absent(tmp_path, monkeypatch):
    # No mvn / go tree available: fall back to direct dependencies only, and say so in the notes.
    monkeypatch.setattr(transitive, "_run", lambda *a, **k: None)
    _write(tmp_path, "svc/pom.xml",
           "<project><dependencies><dependency>"
           "<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
           "<version>2.14.1</version></dependency></dependencies></project>")
    _write(tmp_path, "gw/go.mod", "module x\nrequire github.com/gin-gonic/gin v1.6.3\n")
    notes: list[str] = []
    deps = transitive.resolve_tree(tmp_path, notes)
    assert all(not getattr(d, "transitive", False) for d in deps)   # direct-only
    assert {d.package for d in deps} == {"org.apache.logging.log4j:log4j-core", "github.com/gin-gonic/gin"}
    assert len(notes) == 2 and all("direct dependencies only" in n for n in notes)
    # and the matches still land, flagged direct
    findings = transitive.scan_transitive(tmp_path)
    assert findings and all(f.transitive is False for f in findings)


def test_no_manifest_yields_no_transitive_findings(tmp_path):
    _write(tmp_path, "readme.txt", "nothing here")
    assert transitive.scan_transitive(tmp_path) == []


# ================================================================ C3 git-history secrets

def _git(root: pathlib.Path, *args: str) -> None:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@e"}
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   text=True, env={**_os_environ(), **env})


def _os_environ() -> dict:
    import os
    return dict(os.environ)


_AWS_KEY = "AKIAZ3XB7KQW9MNPZL2R"


def _init_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    return root


def test_secret_removed_in_last_commit_is_found_in_history(tmp_path):
    root = _init_repo(tmp_path)
    _write(root, "app/conf.py", f'AWS_KEY = "{_AWS_KEY}"\n')
    _git(root, "add", "-A"); _git(root, "commit", "-qm", "add config")
    (root / "app" / "conf.py").write_text("AWS_KEY = cfg.lookup('aws')\n")   # secret removed
    _git(root, "add", "-A"); _git(root, "commit", "-qm", "remove secret")

    findings = githistory.scan_git_history(root)
    assert len(findings) == 1
    f = findings[0]
    assert f.oracle == "githistory:aws-access-key-id"
    assert f.frames[0].uri == "app/conf.py"
    assert f.status is Status.CONFIRMED and f.reproducer.kind == DETERMINISTIC_MATCH
    assert _AWS_KEY not in f.message                      # redacted
    # the reproducer replays by re-reading that blob via git show
    commit = f.reproducer.replay_cmd[3]
    assert githistory.replay("aws-access-key-id", commit, "app/conf.py", root) is True


def test_never_committed_secret_is_not_found(tmp_path):
    root = _init_repo(tmp_path)
    _write(root, "readme.md", "# hi\n")
    _git(root, "add", "-A"); _git(root, "commit", "-qm", "init")
    _write(root, "scratch.py", f'AWS_KEY = "{_AWS_KEY}"\n')   # written, never committed
    assert githistory.scan_git_history(root) == []


def test_working_tree_secret_is_not_double_reported(tmp_path):
    root = _init_repo(tmp_path)
    _write(root, "live.py", f'AWS_KEY = "{_AWS_KEY}"\n')
    _git(root, "add", "-A"); _git(root, "commit", "-qm", "commit live secret")
    # still present at HEAD / working tree -> left to the secrets lane, not reported here
    assert githistory.scan_git_history(root) == []


def test_non_repo_yields_nothing(tmp_path):
    assert githistory.scan_git_history(tmp_path) == []


# ================================================================ C4 VEX statements

def _estate_findings():
    return [f for f in scan_target(MIXED).findings if f.oracle == "osv:version-match"]


def test_not_imported_dependency_yields_code_not_reachable(tmp_path):
    findings = _estate_findings()
    statements = {s["affects"][0]["ref"].split("@")[0]: s for s in vex.vex_for(findings)}
    lodash = statements["lodash"]                          # present but not imported in the estate
    assert lodash["analysis"]["state"] == "not_affected"
    assert lodash["analysis"]["justification"] == "code_not_reachable"
    assert lodash["reachability"] == "not-imported"


def test_imported_dependency_is_affected_or_under_investigation():
    statements = {s["affects"][0]["ref"].split("@")[0]: s for s in vex.vex_for(_estate_findings())}
    assert statements["requests"]["analysis"]["state"] in ("affected", "under_investigation")
    # a dependency in a language with no source seen reads under_investigation, honestly
    gin = statements["github.com/gin-gonic/gin"]
    assert gin["analysis"]["state"] == "under_investigation"


def test_vex_document_is_cyclonedx_shaped():
    doc = vex.vex_document(_estate_findings())
    assert doc["bomFormat"] == "CycloneDX" and doc["vulnerabilities"]
    assert all("analysis" in v and v["id"] for v in doc["vulnerabilities"])


# ================================================================ C6 KEV + EPSS

def _match(eco, pkg, ver, manifest="pom.xml"):
    return supply.scan_dependencies([supply.Dependency(eco, pkg, ver, manifest)], vulndb.load())


def test_kev_cve_is_marked_exploited_with_the_snapshot_date():
    intel = kev.load()
    findings = _match("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    kev.annotate_exploit_intel(findings, intel)
    # Log4Shell CVE-2021-44228 is in the KEV snapshot
    log4shell = [f for f in findings if f.exploit_intel["cve"] == "CVE-2021-44228"]
    assert log4shell and log4shell[0].kev is True
    assert log4shell[0].exploit_intel["kev_snapshot"] == intel.kev_snapshot == "2025-09-01"
    assert log4shell[0].epss is not None and 0.0 <= log4shell[0].epss <= 1.0


def test_non_kev_finding_reads_false_and_epss_is_honest():
    findings = _match("Go", "github.com/gin-gonic/gin", "1.6.3", "go.mod")
    kev.annotate_exploit_intel(findings)
    (f,) = findings
    assert f.kev is False                                  # CVE-2020-28483 not in KEV
    assert f.epss is None                                  # and absent from the EPSS snapshot -> None, not 0
    assert f.exploit_intel["cve"] == "CVE-2020-28483"


def test_epss_present_when_the_cve_is_scored():
    findings = _match("PyPI", "requests", "2.30.0", "requirements.txt")
    kev.annotate_exploit_intel(findings)
    (f,) = findings
    assert f.kev is False and f.epss == pytest.approx(0.0256)


def test_exploit_intel_does_not_touch_non_dependency_findings():
    from raksha.lanes import secrets
    sec = secrets.scan_text('password = "Xk9mQ2vL7pZw"\n', "app.properties")
    kev.annotate_exploit_intel(sec)
    assert all(not hasattr(f, "kev") for f in sec)


# ================================================================ C7 reproducible build

def test_nondeterministic_build_is_flagged(tmp_path):
    cmd = ["python3", "-c", "import os; open('out.bin','wb').write(os.urandom(16))"]
    f = reprobuild.check_reproducible(tmp_path, cmd, "out.bin")
    assert f is not None
    assert f.bug_class == "CWE-1104" and f.status is Status.CONFIRMED
    assert f.reproducer.kind == DETERMINISTIC_MATCH
    assert "build1=" in f.raw_excerpt and "build2=" in f.raw_excerpt


def test_deterministic_build_is_not_flagged(tmp_path):
    cmd = ["python3", "-c", "open('out.bin','wb').write(b'same-bytes-every-time')"]
    assert reprobuild.check_reproducible(tmp_path, cmd, "out.bin") is None


def test_missing_build_tool_degrades_cleanly(tmp_path):
    assert reprobuild.check_reproducible(tmp_path, ["raksha-no-such-build-binary"], "out.bin") is None
    assert reprobuild.check_reproducible(tmp_path, "", "out.bin") is None


# ================================================================ C8 IaC hardening floor

def test_dockerfile_root_and_admin_port_yield_replaying_findings(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM ubuntu:22.04\nUSER root\nEXPOSE 22\n")
    findings = iac.scan_iac(tmp_path)
    oracles = {f.oracle for f in findings}
    assert "iac:container-runs-as-root" in oracles
    assert "iac:world-exposed-admin-port" in oracles
    for f in findings:
        assert f.status is Status.CONFIRMED and f.reproducer.replay_cmd[1] == "iac-match"
        rule, path, line = f.frames[0].symbol, f.target, f.frames[0].line
        assert iac.replay(rule, path, line, tmp_path) is True
    assert iac.replay("container-runs-as-root", "Dockerfile", 999, tmp_path) is False


def test_hardened_dockerfile_yields_nothing(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM ubuntu:22.04\nRUN useradd app\nUSER app\nEXPOSE 8443\n")
    assert iac.scan_iac(tmp_path) == []


def test_compose_misconfigurations_are_found(tmp_path):
    _write(tmp_path, "docker-compose.yml",
           "services:\n  db:\n    image: redis:latest\n    privileged: true\n"
           "    network_mode: host\n    ports:\n      - \"0.0.0.0:6379:6379\"\n")
    oracles = {f.oracle for f in iac.scan_iac(tmp_path)}
    assert {"iac:privileged-container", "iac:host-network", "iac:latest-image-tag",
            "iac:world-exposed-admin-port"} <= oracles


def test_k8s_misconfigurations_are_found(tmp_path):
    _write(tmp_path, "pod.yaml",
           "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  hostPID: true\n"
           "  containers:\n    - image: nginx:latest\n      securityContext:\n"
           "        privileged: true\n        runAsUser: 0\n      ports:\n        - hostPort: 2379\n")
    oracles = {f.oracle for f in iac.scan_iac(tmp_path)}
    assert {"iac:host-network", "iac:host-pid", "iac:privileged-container",
            "iac:run-as-root-k8s", "iac:latest-image-tag", "iac:world-exposed-admin-port"} <= oracles


def test_plain_config_yaml_is_not_treated_as_iac(tmp_path):
    _write(tmp_path, "application.yml", "db:\n  password: ${DB_PASSWORD}\n  secret: VAULT_REF\n")
    assert iac.scan_iac(tmp_path) == []


# ================================================================ negative controls stay at zero

def test_new_lanes_add_no_false_positives_on_negative_controls(tmp_path, monkeypatch):
    from raksha.benchmark import NEGATIVE_CONTROLS
    for rel, text in NEGATIVE_CONTROLS.items():
        _write(tmp_path, rel, text)
    # IaC lane: none of the clean controls is a Dockerfile / compose / k8s manifest
    assert iac.scan_iac(tmp_path) == []
    # Transitive lane (offline, deterministic fallback): every control version is patched
    monkeypatch.setattr(transitive, "_run", lambda *a, **k: None)
    assert transitive.scan_transitive(tmp_path) == []


def test_git_history_of_a_subdirectory_stays_inside_it(tmp_path):
    """A target that is a subdirectory of a larger repo: only its own history, paths relative to it."""
    import shutil
    import subprocess
    if shutil.which("git") is None:
        import pytest
        pytest.skip("git absent")
    from raksha.lanes.githistory import scan_git_history
    repo = tmp_path / "repo"; (repo / "svc").mkdir(parents=True); (repo / "other").mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    g("init", "-q"); g("config", "user.email", "t@t"); g("config", "user.name", "t")
    (repo / "svc" / "app.cfg").write_text('password = "S3cretValue99"\n')
    (repo / "other" / "x.cfg").write_text('password = "0therSecret77"\n')
    g("add", "-A"); g("commit", "-q", "-m", "a")
    (repo / "svc" / "app.cfg").write_text("password = env\n")
    (repo / "other" / "x.cfg").write_text("password = env\n")
    g("add", "-A"); g("commit", "-q", "-m", "b")
    found = scan_git_history(repo / "svc")
    assert [f.target for f in found] == ["app.cfg"]
