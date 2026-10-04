"""B12: behavioural baseline — files, sockets and processes touched on benign input; flag the new."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from raksha import behaviour as b
from raksha.finding import Status

HAVE_GCC = shutil.which("gcc") is not None
REPO = Path(__file__).parents[1]
CORPUS = [b"doc:manual.txt", b"doc:roster.txt", b"doc:index.txt", b"doc:missing.txt"]


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    if not HAVE_GCC:
        pytest.skip("gcc absent")
    so = b.build_shim(out_dir=tmp_path_factory.mktemp("shim"))
    assert so is not None
    return so


def _docserver(tmp_path: Path, fixed: bool = False) -> Path:
    root = tmp_path / ("fixed" if fixed else "docserver")
    shutil.copytree(REPO / "demo-targets" / "c-docserver", root)
    src = (root / "src" / "docserver.c").read_text()
    if fixed:
        src = src.replace("    char path[600];",
                          '    if (strstr(req + 4, "..") || req[4] == \'/\') { puts("denied"); return 0; }\n'
                          "    char path[600];")
        (root / "src" / "docserver.c").write_text(src)
    subprocess.run(["gcc", "-O2", "-o", str(root / "docserver"), str(root / "src" / "docserver.c")], check=True)
    return root


def test_traversal_is_flagged_and_replays(shim, tmp_path):
    root = _docserver(tmp_path)
    r = b.scan(b.Observer(["./docserver"], root, shim), CORPUS, target="c-docserver")
    assert r.baseline.sufficient
    assert all(e.what.startswith("<root>/data/") for e in r.baseline.events)
    hits = [f for f in r.findings if f.bug_class == "CWE-22"]
    assert hits and hits[0].status is Status.CONFIRMED and hits[0].reproducer is not None


def test_fixed_build_is_silent(shim, tmp_path):
    root = _docserver(tmp_path, fixed=True)
    assert b.scan(b.Observer(["./docserver"], root, shim), CORPUS, target="fixed").findings == []


def test_python_interpreter_noise_is_not_an_anomaly(shim, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "manual.txt").write_text("m\n")
    (tmp_path / "app.py").write_text(
        "import sys, os\nn = sys.stdin.read().strip()\n"
        "p = os.path.join('data', os.path.basename(n[4:]))\n"
        "print(open(p).read() if os.path.exists(p) else 'nf')\n")
    r = b.scan(b.Observer(["python3", "app.py"], tmp_path, shim), CORPUS, target="py", language="python")
    assert r.findings == []


def test_exec_is_recorded_and_never_performed(shim, tmp_path):
    binsink = tmp_path / "binsink"
    subprocess.run(["gcc", "-O2", "-o", str(binsink), str(REPO / "demo-targets/c-binsink/src/binsink.c")], check=True)
    r = b.scan(b.Observer([str(binsink)], tmp_path, shim), [b"hello", b"abc", b"xyz"],
               candidates=[b"Bx"], target="binsink")
    assert [f.bug_class for f in r.findings] == ["CWE-78"]
    assert not (tmp_path / "raksha_binsink_sentinel").exists()


def test_thin_baseline_yields_nothing(shim, tmp_path):
    root = _docserver(tmp_path)
    r = b.scan(b.Observer(["./docserver"], root, shim), CORPUS[:2], target="c-docserver")
    assert r.findings == [] and "baseline needs" in r.note


def test_session_ingest_behaviour(shim, tmp_path):
    from raksha.orchestrator import Session
    root = _docserver(tmp_path)
    s = Session()
    t = s.ingest_behaviour(root, ["./docserver"], CORPUS)
    assert any(s.findings[i].bug_class == "CWE-22" for i in t.finding_ids)
