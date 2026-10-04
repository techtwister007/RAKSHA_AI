"""External "take" lanes — additive evidence that cross-confirms our own lanes.

The invariants under test: with nothing installed/enabled the lanes are a clean no-op (the default,
and this box); with a fake tool on PATH and its flag set, the adapter parses the tool's JSON into
findings tagged by tool, with the right CWE and status; and a static (semgrep) finding cross-confirms
one of our reproducer-backed findings on the same site + CWE.
"""

from __future__ import annotations

import os
import stat

from raksha.finding import (
    DETERMINISTIC_MATCH, Finding, FixSite, Frame, Reproducer, ReplayResult, Status, utcnow,
)
from raksha.gate.crossconfirm import cross_confirm
from raksha.lanes import take


def _install_fake(tmp_path, monkeypatch, name: str, script: str) -> None:
    """Write an executable `name` emitting `script` to a bin dir and prepend it to PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    tool = bindir / name
    tool.write_text("#!/bin/sh\n" + script)
    tool.chmod(tool.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))


# ---------------------------------------------------------------- the offline default

def test_no_tools_available_is_a_clean_noop(monkeypatch):
    # an empty PATH means nothing is found; no flags either
    monkeypatch.setenv("PATH", "")
    for flag in ("RAKSHA_TAKE_SEMGREP", "RAKSHA_TAKE_GITLEAKS", "RAKSHA_TAKE_OSV_SCANNER",
                 "RAKSHA_TAKE_ALL"):
        monkeypatch.delenv(flag, raising=False)
    assert take.run_take_lanes("/any/root") == []
    assert take.available_lanes() == []


def test_present_but_not_enabled_stays_off(tmp_path, monkeypatch):
    # the binary exists but no flag enables it: must not run
    _install_fake(tmp_path, monkeypatch, "semgrep", 'echo "{}"\n')
    monkeypatch.delenv("RAKSHA_TAKE_SEMGREP", raising=False)
    monkeypatch.delenv("RAKSHA_TAKE_ALL", raising=False)
    assert take.run_take_lanes("/root") == []
    # explicit opt-in via the `enabled` set turns it on
    assert take.run_take_lanes("/root", enabled={"semgrep"}) == []  # emits no results, but ran


# ---------------------------------------------------------------- semgrep (static → SUSPECTED)

_SEMGREP_JSON = (
    '{"results":[{"check_id":"python.lang.security.dangerous-subprocess-use",'
    '"path":"app/runner.py","start":{"line":12,"col":5},'
    '"extra":{"message":"subprocess called with shell=True","severity":"ERROR",'
    '"metadata":{"cwe":["CWE-78: OS Command Injection"]}}}]}'
)


def test_semgrep_parses_to_suspected_findings(tmp_path, monkeypatch):
    _install_fake(tmp_path, monkeypatch, "semgrep", f"cat <<'JSON'\n{_SEMGREP_JSON}\nJSON\n")
    monkeypatch.setenv("RAKSHA_TAKE_SEMGREP", "1")
    (f,) = take.run_take_lanes("/root")
    assert f.oracle == "take:semgrep"
    assert f.bug_class == "CWE-78"
    assert f.status is Status.SUSPECTED        # static, no reproducer: not reportable on its own
    assert f.reproducer is None
    assert f.frames[0].uri == "app/runner.py" and f.frames[0].line == 12


def test_semgrep_finding_cross_confirms_one_of_our_reproducer_findings(tmp_path, monkeypatch):
    _install_fake(tmp_path, monkeypatch, "semgrep", f"cat <<'JSON'\n{_SEMGREP_JSON}\nJSON\n")
    monkeypatch.setenv("RAKSHA_TAKE_SEMGREP", "1")
    (static,) = take.run_take_lanes("/root")

    # our own lane landed a reproducer on the same site + CWE
    ours = Finding(oracle="pysecsan:cmd-injection", bug_class="CWE-78", language="python",
                   target="app/runner.py", message="command injection",
                   frames=[Frame(symbol="run_cmd", uri="app/runner.py", line=12)])
    ours.add_fix_site(FixSite(uri="app/runner.py", rank=0, start_line=12, symbol="run_cmd"))
    ours.attach_reproducer(Reproducer.from_bytes(b"status; rm -rf /", ["./replay"]))
    ours.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    ours.confirm()

    survivors = cross_confirm([static, ours])
    assert static.status is Status.CONFIRMED              # promoted by our reproducer
    assert static.reproducer is ours.reproducer
    assert static.id in ours.merged_from
    assert survivors == [ours]                            # the static finding folded into ours


# ---------------------------------------------------------------- gitleaks (deterministic match)

def test_gitleaks_parses_to_confirmed_deterministic_matches(tmp_path, monkeypatch):
    report = ('[{"RuleID":"aws-access-token","File":"config/app.env","StartLine":4,'
              '"Secret":"AKIAIOSFODNN7EXAMPLEKEY","Match":"key=AKIA..."}]')
    _install_fake(tmp_path, monkeypatch, "gitleaks", f"cat <<'JSON'\n{report}\nJSON\n")
    monkeypatch.setenv("RAKSHA_TAKE_GITLEAKS", "1")
    (f,) = take.run_take_lanes("/root")
    assert f.oracle == "take:gitleaks"
    assert f.bug_class == "CWE-798"
    assert f.status is Status.CONFIRMED and f.is_reportable
    assert f.reproducer is not None and f.reproducer.kind == DETERMINISTIC_MATCH
    assert "AKIAIOSFODNN7EXAMPLEKEY" not in f.message       # redacted
    assert f.frames[0].uri == "config/app.env" and f.frames[0].line == 4


# ---------------------------------------------------------------- osv-scanner (deterministic match)

def test_osv_scanner_parses_to_confirmed_deterministic_matches(tmp_path, monkeypatch):
    report = ('{"results":[{"source":{"path":"go.mod"},"packages":[{'
              '"package":{"name":"github.com/gin-gonic/gin","version":"1.6.3"},'
              '"vulnerabilities":[{"id":"GHSA-h395-qcrw-5vmq","summary":"header smuggling",'
              '"database_specific":{"cwe_ids":["CWE-444"]}}]}]}]}')
    _install_fake(tmp_path, monkeypatch, "osv-scanner", f"cat <<'JSON'\n{report}\nJSON\n")
    monkeypatch.setenv("RAKSHA_TAKE_OSV_SCANNER", "1")
    (f,) = take.run_take_lanes("/root")
    assert f.oracle == "take:osv-scanner"
    assert f.bug_class == "CWE-444"
    assert f.status is Status.CONFIRMED and f.reproducer.kind == DETERMINISTIC_MATCH
    assert "gin" in f.message and "GHSA-h395-qcrw-5vmq" in f.message


# ---------------------------------------------------------------- robustness

def test_enable_all_flag_turns_every_present_lane_on(tmp_path, monkeypatch):
    _install_fake(tmp_path, monkeypatch, "gitleaks", 'echo "[]"\n')
    monkeypatch.setenv("RAKSHA_TAKE_ALL", "1")
    monkeypatch.delenv("RAKSHA_TAKE_GITLEAKS", raising=False)
    # present + enabled-via-all, emits no hits here, but the lane is considered available and ran
    assert any(l.tool == "gitleaks" for l in take.available_lanes())
    assert take.run_take_lanes("/root") == []


def test_unparseable_output_is_dropped_not_fatal(tmp_path, monkeypatch):
    _install_fake(tmp_path, monkeypatch, "semgrep", 'echo "not json {{{"\n')
    monkeypatch.setenv("RAKSHA_TAKE_SEMGREP", "1")
    assert take.run_take_lanes("/root") == []     # garbage output degrades cleanly
