"""B4: measured line coverage for the Python and Node harnesses (no echo heuristic)."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from raksha.harness import raksha_cov

HELPER = Path(raksha_cov.__file__)


def _lines(out: str) -> set[tuple[str, int]]:
    res = set()
    for ln in out.splitlines():
        f, _, n = ln.rpartition(":")
        res.add((f, int(n)))
    return res


def test_python_tracer_reports_only_executed_target_lines(tmp_path):
    (tmp_path / "lib.py").write_text("def f(x):\n    if x == b'a':\n        return 1\n    return 2\n")
    (tmp_path / "raksha_harness.py").write_text(
        "import sys\nfrom lib import f\nf(open(sys.argv[1], 'rb').read())\n")
    shutil.copy2(HELPER, tmp_path / "raksha_cov.py")
    (tmp_path / "in").write_bytes(b"b")
    out = subprocess.run([sys.executable, "raksha_cov.py", "py", "raksha_harness.py", "in"],
                         cwd=tmp_path, capture_output=True, text=True).stdout
    got = _lines(out)
    assert ("lib.py", 4) in got and ("lib.py", 3) not in got     # the untaken branch is absent
    assert not any(f == "raksha_harness.py" or f.startswith("<") for f, _ in got)


def test_python_tracer_flushes_on_os_exit(tmp_path):
    (tmp_path / "lib.py").write_text("import os\ndef f():\n    os._exit(99)\n")
    (tmp_path / "raksha_harness.py").write_text("from lib import f\nf()\n")
    shutil.copy2(HELPER, tmp_path / "raksha_cov.py")
    p = subprocess.run([sys.executable, "raksha_cov.py", "py", "raksha_harness.py"],
                       cwd=tmp_path, capture_output=True, text=True)
    assert ("lib.py", 3) in _lines(p.stdout)


def test_v8_ranges_paint_inner_blocks(tmp_path):
    src = "function f(x) {\n  if (x) {\n    return 1;\n  }\n  return 2;\n}\nf(false);\n"
    (tmp_path / "a.js").write_text(src)
    inner_start = src.index("{\n    return 1")
    inner_end = src.index("  return 2")
    cov = {"result": [{"url": (tmp_path / "a.js").as_uri(), "functions": [
        {"ranges": [{"startOffset": 0, "endOffset": len(src), "count": 1}]},
        {"ranges": [{"startOffset": 0, "endOffset": src.index("f(false)") - 1, "count": 1},
                    {"startOffset": inner_start, "endOffset": inner_end, "count": 0}]}]}]}
    d = tmp_path / "cov"; d.mkdir()
    (d / "c.json").write_text(json.dumps(cov))
    got = raksha_cov.v8_lines(str(d), str(tmp_path.resolve()))
    assert ("a.js", 5) in got and ("a.js", 3) not in got


@pytest.mark.skipif(shutil.which("node") is None, reason="node absent")
def test_js_target_coverage_is_measured():
    from raksha.adapters.js_sink import js_autofuzz
    r = js_autofuzz(Path(__file__).parents[1] / "demo-targets" / "js-noharness")
    b = r.target.build(None)
    cov = r.target.covered_lines(b, [b"10m"])
    site = r.finding.fix_site_set[0]
    assert (Path(site.uri).name, site.start_line) in {(Path(f).name, n) for f, n in cov}
