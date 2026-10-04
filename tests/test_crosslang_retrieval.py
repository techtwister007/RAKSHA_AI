"""G3: a fix proven in one language retrieved, by its idea, for an analogous finding in another."""
from __future__ import annotations

from pathlib import Path

from raksha.embed import Embedder, concepts, cosine, structural_vector
from raksha.finding import (Finding, FixSite, Frame, GateCheck, RepairLane, Reproducer, ReplayResult,
                            utcnow)
from raksha.retrieval import FixMemory, cross_language, fix_concept

C_DIFF = ("--- a/tlv.c\n+++ b/tlv.c\n@@ -1,3 +1,3 @@\n void f(const uint8_t *data, size_t n) {\n"
          "-    memcpy(rec->value, data + 2, n);\n+    memcpy(rec->value, data + 2, (n) < sizeof(rec->value) ? (n) : sizeof(rec->value));\n }\n")
PY_DIFF = ("--- a/r.py\n+++ b/r.py\n@@ -1,2 +1,2 @@\n def run(cmd):\n"
           "-    return subprocess.run(cmd, shell=True)\n+    return subprocess.run(shlex.split(cmd), shell=False)\n")
GO_SRC = ("package d\n\nfunc Decode(data []byte) int {\n\tif len(data) == 0 {\n\t\treturn 0\n\t}\n"
          "\tn := int(data[0])\n\tbody := data[1 : 1+n]\n\treturn len(body)\n}\n")


def _verified(lang, cwe, diff, uri):
    f = Finding(oracle="o", bug_class=cwe, language=lang, target="t", message="m",
                frames=[Frame(symbol="f", uri=uri, line=2)])
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.add_fix_site(FixSite(uri=uri, rank=0, start_line=2)); f.confirm()
    f.mark_patched(diff, RepairLane.TEMPLATE)
    for c in list(GateCheck): f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow())); f.verify()
    return f


def _go_finding(tmp_path: Path) -> Finding:
    (tmp_path / "decoder.go").write_text(GO_SRC)
    f = Finding(oracle="go", bug_class="CWE-125", language="go", target="t", message="slice bounds",
                frames=[Frame(symbol="Decode", uri="decoder.go", line=8)])
    f.add_fix_site(FixSite(uri="decoder.go", rank=0, start_line=8))
    return f


def test_concepts_bridge_copy_and_slice():
    assert "RANGE" in concepts("memcpy(dst, src, n);") and "RANGE" in concepts("body := data[1 : 1+n]")
    assert "SIZE" in concepts("x < sizeof(buf)") and "SIZE" in concepts("min(hi, len(a))")


def test_fix_concepts():
    assert fix_concept(C_DIFF) == "bound-clamp"
    assert fix_concept(PY_DIFF) == "no-shell-argv"


def test_c_bound_fix_is_retrieved_for_a_go_finding(tmp_path):
    mem = FixMemory()
    mem.remember(_verified("c/c++", "CWE-121", C_DIFF, "tlv.c"))
    out = cross_language(mem, _go_finding(tmp_path), tmp_path)
    assert out, "no cross-language candidate"
    diff, prov = out[0]
    assert prov["from_language"] == "c/c++" and prov["idea"] == "bound-clamp" and prov["realised"]
    assert prov["vector_backend"] == "structural" and prov["similarity"] >= 0.5
    assert "min(1+n, len(data))" in diff and diff.startswith("--- a/decoder.go")


def test_a_fix_of_another_family_is_not_offered(tmp_path):
    mem = FixMemory()
    mem.remember(_verified("python", "CWE-78", PY_DIFF, "r.py"))
    assert cross_language(mem, _go_finding(tmp_path), tmp_path) == []


def test_same_language_records_are_left_to_the_syntactic_lane(tmp_path):
    mem = FixMemory()
    go_diff = ("--- a/x.go\n+++ b/x.go\n@@ -1,1 +1,1 @@\n-\tb := d[1 : 1+n]\n+\tb := d[1:min(1+n, len(d))]\n")
    mem.remember(_verified("go", "CWE-125", go_diff, "x.go"))
    assert cross_language(mem, _go_finding(tmp_path), tmp_path) == []


def test_endpoint_backend_and_fallback():
    class Fake:
        def embed(self, texts, *, model):
            return [[1.0, 0.0]] * len(texts)

    class Broken:
        def embed(self, texts, *, model):
            raise RuntimeError("down")

    assert Embedder(Fake(), "code-embed").vector("x") == [1.0, 0.0]
    e = Embedder(Broken(), "code-embed")
    v = e.vector("memcpy(a, b, n)")
    assert e.backend == "structural" and len(v) == len(structural_vector("x"))   # degraded, visibly


def test_vectors_rank_analogues_above_strangers():
    c = structural_vector("memcpy(rec->value, data + 2, n);", family="memory")
    go = structural_vector("body := data[1 : 1+n]", family="memory")
    shell = structural_vector("subprocess.run(cmd, shell=True)", family="injection")
    assert cosine(c, go) > cosine(c, shell)
