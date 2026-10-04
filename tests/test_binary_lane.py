"""B10: binary lane — embedded versions, weak-crypto constants and an SBOM from bytes alone."""
from __future__ import annotations

import glob
import io
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from raksha.finding import Status
from raksha.lanes import binary, buildfree

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57


def _go_binary(version: str) -> bytes:
    info = (b"path\tsvc\nmod\tsvc\t(devel)\t\n"
            b"dep\tgithub.com/gin-gonic/gin\tv" + version.encode() + b"\th1:abc=\n"
            b"dep\tgolang.org/x/sys\tv0.20.0\th1:def=\n")
    return ELF + b"\x00" * 128 + info + b"\x00" * 64


def _jar(group: str, artifact: str, version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr(f"META-INF/maven/{group}/{artifact}/pom.properties",
                   f"#generated\nversion={version}\ngroupId={group}\nartifactId={artifact}\n")
    return buf.getvalue()


def test_go_buildinfo_dep_matches_advisory(tmp_path):
    (tmp_path / "svc").write_bytes(_go_binary("1.6.3"))
    r = binary.scan_artifacts(tmp_path)
    names = {(c.name, c.version) for c in r.components}
    assert ("github.com/gin-gonic/gin", "v1.6.3") in names
    vuln = [f for f in r.findings if f.oracle == "binary:version-match"]
    assert vuln and all(f.status is Status.CONFIRMED for f in vuln)
    rule = vuln[0].reproducer.replay_cmd[2]
    assert binary.replay(rule, "svc", root=tmp_path)
    (tmp_path / "svc").write_bytes(_go_binary("1.9.1"))    # rebuilt with the fix
    assert not binary.replay(rule, "svc", root=tmp_path)


def test_jar_pom_properties_matches_log4shell(tmp_path):
    (tmp_path / "app.jar").write_bytes(_jar("org.apache.logging.log4j", "log4j-core", "2.14.1"))
    r = binary.scan_artifacts(tmp_path)
    hits = [f for f in r.findings if f.bug_class == "CWE-917"]
    assert hits and hits[0].severity == "critical"
    bom = binary.sbom(r)
    assert any(c["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" for c in bom["components"])


def test_fixed_jar_is_silent(tmp_path):
    (tmp_path / "app.jar").write_bytes(_jar("org.apache.logging.log4j", "log4j-core", "2.17.1"))
    assert not binary.scan_artifacts(tmp_path).findings


def test_crypto_word_census():
    md5_t = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a]
    blob = ELF + b"\x90".join(w.to_bytes(4, "little") for w in md5_t)
    assert [h[0] for h in binary.crypto_hits(blob)] == ["bin-md5-impl"]
    shared_init = bytes.fromhex("0123456789abcdeffedcba9876543210")   # MD5 and SHA-1 share these
    assert binary.crypto_hits(ELF + shared_init) == []
    f = binary.scan_bytes(blob, "x.bin").findings[0]
    assert f.severity == "info" and f.bug_class == "CWE-327" and "presence only" in f.message


def test_text_file_is_not_a_binary(tmp_path):
    (tmp_path / "notes.txt").write_bytes(b"dep\tgithub.com/gin-gonic/gin\tv1.6.3\n")
    assert binary.scan_artifacts(tmp_path).findings == []


def test_cli_replay_exit_codes(tmp_path):
    (tmp_path / "svc").write_bytes(_go_binary("1.6.3"))
    f = next(f for f in binary.scan_artifacts(tmp_path).findings if f.oracle == "binary:version-match")
    argv = [sys.executable, "-m", "raksha", *f.reproducer.replay_cmd[1:]]
    root = Path(__file__).parents[1]
    env_pp = {"PYTHONPATH": str(root)}
    import os
    p = subprocess.run(argv, cwd=tmp_path, capture_output=True, text=True, env={**os.environ, **env_pp})
    assert p.returncode == 1 and "REPRODUCED" in p.stdout


def test_buildfree_includes_binary_lane(tmp_path):
    (tmp_path / "svc").write_bytes(_go_binary("1.6.3"))
    res = buildfree.scan_target(tmp_path)
    assert res.by_lane().get("binary")
    assert res.binary_components


M2_LOG4J = Path.home() / ".m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"


@pytest.mark.skipif(not M2_LOG4J.exists(), reason="real log4j-core 2.14.1 jar not cached")
def test_real_log4j_jar():
    r = binary.scan_bytes(M2_LOG4J.read_bytes(), "log4j-core-2.14.1.jar")
    assert any(f.bug_class == "CWE-917" for f in r.findings)


LIBCRYPTO = sorted(glob.glob("/usr/lib/x86_64-linux-gnu/libcrypto.so*"))


@pytest.mark.skipif(not LIBCRYPTO, reason="no system libcrypto")
def test_real_libcrypto_has_md5_and_openssl_banner():
    data = Path(LIBCRYPTO[0]).read_bytes()
    assert "bin-md5-impl" in {h[0] for h in binary.crypto_hits(data)}
    assert any(c.name == "openssl" for c in binary.components_in(data))
