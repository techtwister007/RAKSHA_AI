"""Wave 1 tranche 2: D5 signed journal, C5 fleet roll-up, C2 unpinned boundary, E5/E7 memory."""
from __future__ import annotations

from raksha.finding import (Finding, Reproducer, ReplayResult, Frame, FixSite, GateCheck,
                            RepairLane, utcnow, DETERMINISTIC_MATCH)


def _dep(target, cve="CVE-2021-44228"):
    f = Finding(oracle="osv:version-match", bug_class="CWE-917", language="java", target=target,
                message="log4j", frames=[Frame(symbol="log4j-core", uri=target, line=1)],
                abort_signature=cve)
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["raksha", "match"], kind=DETERMINISTIC_MATCH))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow())); f.confirm()
    return f


def test_c5_fleet_rollup_folds_one_defect_across_targets():
    from raksha.fleet import rollup
    g = rollup([_dep("a/pom.xml"), _dep("b/pom.xml"), _dep("c/pom.xml"), _dep("solo/other.xml", cve="CVE-2222-0001")])
    assert len(g) == 1 and g[0]["count"] == 3 and len(g[0]["targets"]) == 3


def test_d5_journal_signature_covers_the_chain(tmp_path):
    from raksha import journal
    j = journal.Journal(tmp_path / "j.jsonl"); j.emit("a", x=1); j.emit("b", y=2)
    sig = journal.sign(tmp_path / "j.jsonl")
    assert sig["records"] == 2 and sig["final_hash"] and sig.get("alg")


def test_c2_unpinned_dependency_shows_on_the_boundary(tmp_path):
    from raksha.orchestrator import Session
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "package.json").write_text('{"dependencies":{"lodash":"^4.17.20"}}')
    s = Session(); s.ingest_build_free(tmp_path / "pkg", name="pkg")
    assert s.snapshot()["scorecard"]["boundary"]["dependencies_unpinned"] >= 1


def _verified_c():
    f = Finding(oracle="asan", bug_class="CWE-121", language="c", target="t", message="m")
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 40, ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.add_fix_site(FixSite(uri="src/x.c", rank=0, start_line=5)); f.confirm()
    f.mark_patched("--- a/src/x.c\n+++ b/src/x.c\n@@ -5 +5 @@\n"
                   "-    memcpy(dst, src, n);\n+    memcpy(dst, src, n < sizeof(dst) ? n : sizeof(dst));\n",
                   RepairLane.TEMPLATE)
    for c in list(GateCheck): f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow())); f.verify()
    return f


def test_e5_e7_memory_persists_and_demotes(tmp_path):
    from raksha.retrieval import FixMemory
    m = FixMemory(); f = _verified_c(); m.remember(f); assert len(m) == 1
    p = tmp_path / "mem.json"; m.save(p)
    m2 = FixMemory(); assert m2.load(p) == 1
    assert m2.demote(f) == 1 and len(m2) == 0
    assert m2.remember(_verified_c()) is None   # E7: the demoted shape is not relearned
