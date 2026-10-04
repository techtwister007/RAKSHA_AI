"""W0-1: the hash-chained session journal and resume."""
from __future__ import annotations

import json
from pathlib import Path

from raksha import journal
from raksha.orchestrator import Session


def test_chain_verifies_and_detects_tampering(tmp_path):
    j = journal.Journal(tmp_path / "j.jsonl")
    j.emit("a", x=1); j.emit("b", y=2); j.emit("c", z=3)
    ok, problems = journal.verify(tmp_path / "j.jsonl")
    assert ok and not problems
    # flip one byte in the middle record's payload
    lines = (tmp_path / "j.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["y"] = 999; lines[1] = json.dumps(rec, separators=(",", ":"))
    (tmp_path / "j.jsonl").write_text("\n".join(lines) + "\n")
    ok2, problems2 = journal.verify(tmp_path / "j.jsonl")
    assert not ok2 and problems2


def test_a_truncated_final_line_is_dropped_cleanly(tmp_path):
    j = journal.Journal(tmp_path / "j.jsonl"); j.emit("a", x=1); j.emit("b", y=2)
    p = tmp_path / "j.jsonl"
    p.write_text(p.read_text() + '{"seq":2,"kind":"hal')   # a kill mid-write
    recs = journal.read(p)
    assert len(recs) == 2 and journal.verify(p)[0]          # the half line is ignored, chain still valid


def test_resume_restores_the_board_and_scorecard(tmp_path):
    jp = tmp_path / "run.jsonl"
    s = Session(); s.open_journal(jp)
    s.ingest_build_free(Path(__file__).parents[1] / "demo-targets" / "mixed-estate", name="estate")
    before = s.snapshot()
    # the orchestrator "dies"; a fresh process resumes from the journal alone
    r = Session.resume(jp)
    after = r.snapshot()
    assert [t["name"] for t in after["board"]] == [t["name"] for t in before["board"]]
    assert after["scorecard"]["performance"]["findings_reported"] == before["scorecard"]["performance"]["findings_reported"]
    assert after["scorecard"]["performance"]["by_status"] == before["scorecard"]["performance"]["by_status"]
    assert len(r.findings) == len(s.findings)
    assert journal.verify(jp)[0]                            # resume continued the same valid chain
