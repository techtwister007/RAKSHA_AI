"""E8: gated fine-tuning dataset — learns only from gate-verified proofs; never trains."""
from __future__ import annotations

import json

from raksha.finding import (Finding, FixSite, Frame, GateCheck, RepairLane, Reproducer,
                            ReplayResult, utcnow)
from raksha.training import build_dataset, dry_run, eligibility, write_jsonl
from raksha.training.dataset import ENABLED_IN_PIPELINE


def _confirmed():
    f = Finding(oracle="asan", bug_class="CWE-121", language="c", target="t", message="m",
                frames=[Frame(symbol="f", uri="src/s.c", line=10)])
    f.attach_reproducer(Reproducer.from_bytes(b"A" * 40, ["./r"]))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.add_fix_site(FixSite(uri="src/s.c", rank=0, start_line=10)); f.confirm()
    return f


def _verified():
    f = _confirmed()
    f.mark_patched("--- a/s.c\n+++ b/s.c\n@@\n-a\n+b\n", RepairLane.TEMPLATE)
    for c in list(GateCheck): f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow())); f.verify()
    return f


def _patched_failed_gate():
    f = _confirmed()
    f.mark_patched("--- a/s.c\n+++ b/s.c\n@@\n-a\n+c\n", RepairLane.TEMPLATE)
    f.record_gate(GateCheck.COMPILES, True, detail="ok")
    f.record_gate(GateCheck.POV_DEAD, False, detail="still crashes")
    return f


def test_only_verified_findings_enter():
    v, c, p = _verified(), _confirmed(), _patched_failed_gate()
    assert eligibility(v) is None
    assert "VERIFIED" in eligibility(c)
    assert eligibility(p) is not None
    pairs = build_dataset([v, c, p])
    assert len(pairs) == 1
    assert pairs[0]["bug_class"] == "CWE-121" and "src/s.c:10" in pairs[0]["context"]


def test_relaxed_status_still_requires_passing_gate():
    assert eligibility(_patched_failed_gate(), require_verified=False) is not None


def test_dry_run_records_refusals_and_never_trains():
    summary = dry_run([_verified(), _confirmed()])
    assert summary["accepted"] == 1 and summary["refused"] == 1
    assert summary["trained"] is False
    assert ENABLED_IN_PIPELINE is False


def test_write_jsonl(tmp_path):
    out = tmp_path / "d.jsonl"
    assert write_jsonl(build_dataset([_verified()]), out) == 1
    assert json.loads(out.read_text().splitlines()[0])["language"] == "c"
