"""B8: nothing RAKSHA places in a target's tree carries a fixed product marker; names change per run."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from raksha.harness.autofuzz import autofuzz

REPO = Path(__file__).parents[1]
MARKERS = (b"raksha", b"sinkguard")


def _added(work: Path, original: Path) -> list[Path]:
    """Files present in the scratch tree that the target did not ship."""
    theirs = {p.relative_to(original) for p in original.rglob("*") if p.is_file()}
    return [p for p in work.rglob("*") if p.is_file() and p.relative_to(work) not in theirs]


@pytest.mark.parametrize("demo", ["c-nolibfuzzer", "py-noharness"])
def test_scratch_tree_has_no_fixed_marker(demo, tmp_path):
    if demo.startswith("c-") and shutil.which("gcc") is None:
        pytest.skip("gcc absent")
    # The demo sources mention the product in their comments; scrub a copy first so any marker
    # found afterwards can only have come from what RAKSHA put there.
    original = tmp_path / demo
    shutil.copytree(REPO / "demo-targets" / demo, original,
                    ignore=shutil.ignore_patterns("__pycache__"))
    for f in original.rglob("*"):
        if f.is_file():
            f.write_bytes(f.read_bytes().replace(b"RAKSHA", b"XXXXXX").replace(b"raksha", b"xxxxxx")
                          .replace(b"Raksha", b"Xxxxxx"))
    r = autofuzz(original, use_model=False, max_execs=4000)
    assert r.target is not None, r.note
    work = Path(r.target.source_root)
    # materialise everything the gate would add too (coverage twin, regression helper)
    b = r.target.build(None)
    r.target.covered_lines(b, [b"ok"])
    try:
        for tree in (work, Path(b.root)):
            import tempfile
            ours = str(tree.resolve().relative_to(Path(tempfile.gettempdir()).resolve()))
            assert not any(m in ours.lower().encode() for m in MARKERS), ours   # the part RAKSHA named
            for f in _added(tree, original):
                rel = str(f.relative_to(tree)).lower().encode()
                assert not any(m in rel for m in MARKERS), rel
                if f.stat().st_size < 2_000_000:
                    body = f.read_bytes().lower()
                    assert not any(m in body for m in MARKERS), (f, [m for m in MARKERS if m in body])
    finally:
        r.target.discard(b)
        r.cleanup()


def test_names_differ_per_run():
    code = "from raksha import names; print(names.HARNESS, names.dot('in'))"
    a = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO).stdout
    b = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO).stdout
    assert a and b and a != b


def test_run_token_is_reproducible_on_request():
    import os
    code = "from raksha import names; print(names.HARNESS)"
    env = {**os.environ, "RAKSHA_RUN_TOKEN": "abc123"}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO, env=env).stdout
    assert out.strip() == "h_abc123"
