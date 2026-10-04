"""A5: a shipped patch provably rolls back to a byte-identical tree; a tampered rollback fails."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from raksha.finding import Finding
from raksha.rollback import prove_rollback, rollback_script, tree_hash, verify_rollback

DIFF = "--- a/s.c\n+++ b/s.c\n@@ -1,2 +1,2 @@\n int f(void) {\n-  return 1; }\n+  return 2; }\n"


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "t"; root.mkdir()
    (root / "s.c").write_text("int f(void) {\n  return 1; }\n")
    (root / "other.c").write_text("int g;\n")
    return root


def test_prove_rollback(tmp_path):
    root = _tree(tmp_path)
    proof = prove_rollback(root, DIFF)
    assert proof["status"] == "proved"
    assert proof["original"] == proof["rolled_back"] != proof["patched"]
    assert proof["original"] == tree_hash(root)          # the source tree itself was never touched
    assert set(proof["files"]) == {"s.c"}


def test_tampered_rollback_fails(tmp_path):
    root = _tree(tmp_path)
    proof = prove_rollback(root, DIFF)
    assert verify_rollback(root, proof)
    (root / "other.c").write_text("int g = 1;\n")       # someone changed an unrelated file
    assert not verify_rollback(root, proof)


@pytest.mark.skipif(shutil.which("sha256sum") is None or shutil.which("patch") is None, reason="tools")
def test_rollback_script_checks_hashes(tmp_path):
    root = _tree(tmp_path)
    f = Finding(oracle="o", bug_class="CWE-121", language="c", target="t", message="m")
    f.patch_diff = DIFF
    f.rollback_proof = prove_rollback(root, DIFF)
    script = tmp_path / "rollback.sh"; script.write_text(rollback_script(f))
    (tmp_path / "patch.diff").write_text(DIFF)
    subprocess.run(["patch", "-p1", "-i", str(tmp_path / "patch.diff")], cwd=root, check=True,
                   capture_output=True)                  # the deployed (patched) state
    ok = subprocess.run(["sh", str(script)], cwd=root, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "s.c: OK" in ok.stdout
    # deploy again, then tamper with the patched file so the reverse leaves the wrong bytes
    subprocess.run(["patch", "-p1", "-i", str(tmp_path / "patch.diff")], cwd=root, check=True,
                   capture_output=True)
    (root / "s.c").write_text((root / "s.c").read_text() + "/* local edit */\n")
    bad = subprocess.run(["sh", str(script)], cwd=root, capture_output=True, text=True)
    assert bad.returncode != 0
