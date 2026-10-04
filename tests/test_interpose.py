"""B11: LD_PRELOAD sink interposition for compiled targets with no source."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from raksha.harness.interpose import InterposeOracle, build_shim, run_with_shim
from raksha.oracles import ALL_ORACLES

HAVE_GCC = shutil.which("gcc") is not None
DEMO = Path(__file__).parents[1] / "demo-targets" / "c-binsink" / "src" / "binsink.c"


def test_oracle_silent_on_clean_output():
    assert InterposeOracle().parse("benign\n", target="bin") == []
    # a log line that merely mentions the shim is not a banner
    assert InterposeOracle().parse("loaded RAKSHA INTERPOSE shim\n", target="bin") == []


def test_oracle_maps_sinks_to_cwe():
    o = InterposeOracle()
    sys_f = o.parse("=== RAKSHA INTERPOSE: system ===\n", target="bin")
    assert len(sys_f) == 1 and sys_f[0].bug_class == "CWE-78"
    assert sys_f[0].fix_site_set  # localised to the sink, never empty
    assert o.parse("=== RAKSHA INTERPOSE: connect ===\n", target="bin")[0].bug_class == "CWE-918"


def test_registered_in_all_oracles():
    assert any(isinstance(o, InterposeOracle) for o in ALL_ORACLES)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    if not HAVE_GCC:
        pytest.skip("gcc absent")
    d = tmp_path_factory.mktemp("interpose")
    shim = build_shim(out_dir=d)
    assert shim is not None
    binary = d / "binsink"
    subprocess.run(["gcc", "-O2", "-o", str(binary), str(DEMO)], check=True, capture_output=True)
    return d, shim, binary


def test_shim_blocks_sink_before_it_runs(built, tmp_path):
    d, shim, binary = built
    inp = tmp_path / "in"; inp.write_bytes(b"Battacker")
    sentinel = tmp_path / "sentinel"
    import os
    env = dict(os.environ, RAKSHA_BINSINK_SENTINEL=str(sentinel))
    out = run_with_shim([binary], inp, shim, timeout=10, env=env)
    findings = InterposeOracle().parse(out, target=str(binary))
    assert len(findings) == 1 and findings[0].bug_class == "CWE-78"
    assert not sentinel.exists()  # blocked, not merely detected


def test_shim_silent_on_benign_input(built, tmp_path):
    d, shim, binary = built
    inp = tmp_path / "in"; inp.write_bytes(b"hello")
    out = run_with_shim([binary], inp, shim, timeout=10)
    assert "benign" in out
    assert InterposeOracle().parse(out, target=str(binary)) == []


def test_build_shim_degrades_without_compiler(tmp_path):
    assert build_shim(cc="no-such-cc-raksha", out_dir=tmp_path) is None
