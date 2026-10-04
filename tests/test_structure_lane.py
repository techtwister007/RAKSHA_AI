"""Structure lane: source→sink paths over a code-property-graph-lite, emitted SUSPECTED only.

Python taint positive / negatives, C `(data, len)` → memcpy, Go `exec.Command`, the demo targets'
known paths, SUSPECTED findings carrying `structure`, the graph JSON hook, and cross-confirmation by
a dynamic finding on the same file + CWE.
"""

from __future__ import annotations

import pathlib

from raksha.finding import EXPLOIT_REPLAY, Finding, FixSite, Frame, InvariantViolation, Reproducer, ReplayResult, Status, utcnow
from raksha.gate.crossconfirm import cross_confirm
from raksha.lanes import structure

REPO = pathlib.Path(__file__).parents[1]
DEMO = REPO / "demo-targets"


def paths(text: str, name: str) -> list[structure.StructuralPath]:
    return structure.scan_file(text, name)


# ---------------------------------------------------------------- Python (ast taint)

def test_python_param_to_fstring_to_shell_positive():
    (p,) = paths('import subprocess\ndef run(data):\n    cmd = f"echo {data}"\n'
                 '    subprocess.run(cmd, shell=True)\n', "run.py")
    assert p.function == "run" and p.source == "data" and p.cwe == "CWE-78"
    assert p.lines == [2, 3, 4] and p.confidence == 0.8


def test_python_negatives_list_form_shlex_and_constant():
    assert paths('import subprocess, shlex\ndef run(data):\n'
                 '    subprocess.run(shlex.split("echo " + data))\n', "a.py") == []
    assert paths('import subprocess\ndef run(data):\n    subprocess.run(["echo", data])\n', "b.py") == []
    assert paths('import subprocess\ndef run(data):\n    argv = ["echo", data]\n'
                 '    subprocess.run(argv)\n', "c.py") == []
    assert paths('import subprocess\ndef run(data):\n    subprocess.run("echo hi", shell=True)\n', "d.py") == []
    assert paths('import subprocess, shlex\ndef run(data):\n    safe = shlex.quote(data)\n'
                 '    subprocess.run("echo " + safe, shell=True)\n', "e.py") == []


def test_python_attributes_the_right_parameter():
    (p,) = paths('import subprocess\ndef run(mode, data):\n    cmd = "echo " + data\n'
                 '    subprocess.run(cmd, shell=True)\n', "two.py")
    assert p.source == "data"


def test_python_follows_one_local_helper():
    (p,) = paths('import subprocess\ndef wrap(x):\n    return "echo " + x\n'
                 'def run(payload):\n    c = wrap(payload)\n    subprocess.run(c, shell=True)\n', "h.py")
    assert p.source == "payload" and p.lines == [4, 5, 6]


def test_python_other_sinks():
    (y,) = paths("import yaml\ndef load(payload):\n    return yaml.load(payload)\n", "y.py")
    assert y.cwe == "CWE-502"
    assert paths("import yaml\ndef load(payload):\n    return yaml.load(payload, Loader=yaml.SafeLoader)\n", "ys.py") == []
    (s,) = paths('@app.route("/u")\ndef h(name):\n    q = "select * from t where n=%s" % name\n'
                 '    cur.execute(q)\n', "sql.py")
    assert s.cwe == "CWE-89" and s.confidence == 0.9           # a route handler: strongest source
    (e,) = paths("def calc(expr):\n    return eval(expr)\n", "ev.py")
    assert e.cwe == "CWE-94" and e.confidence == 0.5            # public function, untyped param
    (o,) = paths("def read(req):\n    return open(req).read()\n", "op.py")
    assert o.cwe == "CWE-22"
    assert paths("def _helper(x):\n    return eval(x)\n", "priv.py") == []   # private: no source claim


# ---------------------------------------------------------------- C and Go (regex)

def test_c_data_len_to_memcpy_positive_and_sizeof_negative():
    found = paths("int parse(const uint8_t *data, size_t len) {\n  char out[16];\n  memcpy(out, data, len);\n"
                  "  return 0;\n}\nint ok(const uint8_t *data, size_t len) {\n  char out[16];\n"
                  "  memcpy(out, data, sizeof(out));\n  return 0;\n}\n", "p.c")
    assert [(p.function, p.cwe, p.language) for p in found] == [("parse", "CWE-120", "c")]
    assert found[0].lines[-1] == 3 and found[0].source in ("data", "len")


def test_c_system_sink():
    (p,) = paths('void run(char *cmd) {\n  char line[64];\n  sprintf(line, "ls %s", cmd);\n  system(line);\n}\n', "s.c")
    assert p.cwe == "CWE-120" and p.lines == [1, 3]            # the first sink on the path is sprintf


def test_go_exec_command_positive():
    (p,) = paths('package x\nfunc H(w http.ResponseWriter, r *http.Request) {\n\tname := r.FormValue("n")\n'
                 '\tout, _ := exec.Command("sh", "-c", "ping "+name).Output()\n\tw.Write(out)\n}\n', "h.go")
    assert p.function == "H" and p.source == "r" and p.cwe == "CWE-78" and p.lines == [2, 3, 4]
    assert p.confidence == 0.9 and p.language == "go"


def test_go_negative_constant_command():
    assert paths('package x\nfunc H(w http.ResponseWriter, r *http.Request) {\n'
                 '\texec.Command("uptime").Run()\n}\n', "n.go") == []


# ---------------------------------------------------------------- demo targets: known paths

def test_finds_the_known_path_in_py_noharness():
    res = structure.scan_structure(DEMO / "py-noharness" / "converter.py")
    (p,) = res.paths
    assert p.function == "convert" and p.source == "spec" and p.cwe == "CWE-78"
    assert p.lines[-1] == 12 and p.file == "converter.py"
    assert res.graph_summary == {"nodes": 3, "edges": 3, "functions": 1, "sinks": 1}


def test_finds_the_known_path_in_c_nolibfuzzer():
    res = structure.scan_structure(DEMO / "c-nolibfuzzer" / "src" / "tlv.c")
    (p,) = res.paths
    assert p.function == "parse_record" and p.cwe == "CWE-120" and p.sink == "memcpy()"
    assert p.lines[0] == 7 and p.lines[-1] == 15
    assert {11, 14} <= set(p.lines)                             # length = data[1]; n = ... length ...


def test_scan_structure_walks_a_tree():
    res = structure.scan_structure(DEMO / "fleet")
    assert {(p.file, p.function) for p in res.paths} == {("ops-tools/handler.py", "run_diagnostic"),
                                                         ("report-worker/worker.py", "render")}
    assert res.graph_summary["functions"] == 3 and res.graph_summary["sinks"] == 2


# ---------------------------------------------------------------- findings: SUSPECTED, never confirmed

def test_to_findings_are_suspected_and_carry_structure():
    res = structure.scan_structure(DEMO / "py-noharness" / "converter.py")
    (f,) = structure.to_findings(res)
    assert f.status is Status.SUSPECTED and f.reproducer is None and not f.is_reportable
    assert f.oracle == "cpg:python" and f.bug_class == "CWE-78"
    assert f.fix_site_set[0].uri == "converter.py" and f.fix_site_set[0].start_line == 12
    assert f.structure["source"] == "spec" and f.structure["lines"][-1] == 12
    assert "no reproducer" in f.structure["evidence"]
    with __import__("pytest").raises(InvariantViolation):
        f.confirm()                                              # no reproducer, no report


def _dynamic(uri: str, line: int, cwe: str) -> Finding:
    g = Finding(oracle="pysecsan:command-injection", bug_class=cwe, language="python", target=uri,
                message="shell=True with crafted input", severity="high",
                frames=[Frame(symbol="convert", uri=uri, line=line)])
    g.add_fix_site(FixSite(uri=uri, rank=0, start_line=line, symbol="convert"))
    g.attach_reproducer(Reproducer.from_bytes(b"x; id", ["python", "harness.py", "crash.bin"], kind=EXPLOIT_REPLAY))
    g.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature="command-injection"))
    g.confirm()
    return g


def test_cross_confirmation_promotes_on_same_file_and_cwe():
    res = structure.scan_structure(DEMO / "py-noharness" / "converter.py")
    (static,) = structure.to_findings(res)
    dynamic = _dynamic("demo-targets/py-noharness/converter.py", 12, "CWE-78")
    survivors = cross_confirm([static, dynamic])
    assert static.status is Status.CONFIRMED and static.reproducer is dynamic.reproducer
    assert survivors == [dynamic] and static.id in dynamic.merged_from


def test_cross_confirmation_refuses_a_different_cwe():
    res = structure.scan_structure(DEMO / "py-noharness" / "converter.py")
    (static,) = structure.to_findings(res)
    other = _dynamic("demo-targets/py-noharness/converter.py", 12, "CWE-120")
    assert cross_confirm([static, other]) == [static, other] and static.status is Status.SUSPECTED


# ---------------------------------------------------------------- graph JSON (training-data hook)

def test_graph_json_features():
    res = structure.scan_structure(DEMO / "c-nolibfuzzer" / "src" / "tlv.c")
    g = structure.graph_json(res)
    by = {n["id"]: n for n in g["nodes"]}
    sink = next(n for n in g["nodes"] if n["is_sink"])
    assert sink["distance_to_sink"] == 0 and sink["cwe"] == "CWE-120"
    assert by["tlv.c::parse_record"]["distance_to_sink"] == 1
    assert by["tlv.c::parse_record::data"]["is_source"] and by["tlv.c::parse_record::data"]["distance_to_sink"] == 1
    assert all({"in_degree", "out_degree", "is_sink", "is_source", "distance_to_sink"} <= set(n) for n in g["nodes"])
    assert g["model"] is None and "no learned model" in g["note"]
    assert {e["kind"] for e in g["edges"]} >= {"param-of", "taints", "contains"}


def test_graph_json_unreachable_is_none_not_zero():
    res = structure.scan_structure(DEMO / "go-decoder")
    g = structure.graph_json(res)
    assert res.paths == [] and all(n["distance_to_sink"] is None for n in g["nodes"])


def test_a_tainted_name_inside_a_string_literal_is_not_a_flow():
    """`printf("sum=%d\\n", r)` must not read as tainted because `n` appears in the escape `\\n`."""
    from raksha.lanes.structure import scan_file
    src = ('int main(int argc, char **argv) {\n  char data[64];\n  size_t n = fread(data, 1, 64, stdin);\n'
           '  printf("sum=%d\\n", 1);\n  printf("src/x.c:11\\n");\n  return 0;\n}\n')
    assert [p for p in scan_file(src, "h.c") if p.cwe == "CWE-134"] == []


def test_a_copy_into_a_buffer_allocated_for_that_length_is_not_flagged():
    from raksha.lanes.structure import scan_file
    ok = ("int stash(const unsigned char *data, int len) {\n  char *copy = (char *) malloc((size_t) len + 1);\n"
          "  memcpy(copy, data, (size_t) len);\n  return 0;\n}\n")
    bad = ("int stash(const unsigned char *data, int len) {\n  char copy[16];\n"
           "  memcpy(copy, data, (size_t) len);\n  return 0;\n}\n")
    assert [p for p in scan_file(ok, "s.c") if p.cwe == "CWE-120"] == []
    assert [p for p in scan_file(bad, "s.c") if p.cwe == "CWE-120"]
