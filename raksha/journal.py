"""The session journal (W0-1): an append-only, hash-chained event log, and resume from it.

Two needs this serves:

  * **Legibility and audit.** Every pipeline event — a harness synthesized, a crash, a candidate
    judged with its verdict, a status change, an operator action, a red-team round — is appended as
    one JSON line. The live event log, the time-lapse and the signed audit trail all read this.
  * **Continuity.** A 36-hour run must survive the orchestrator dying. Each line carries the hash of
    the line before it, so the log is tamper-evident, and `resume()` replays it to rebuild the board
    and the scorecard exactly as they stood.

The chain: every record holds `prev` (the previous line's hash) and `hash` = sha256(prev + the
record without its hash field, canonically encoded). The first line's `prev` is 64 zeros. A single
altered or dropped line breaks `verify()`.

What is NOT journalled: reproducer bytes. They are exploits at rest (see the reproducer-handling
policy); the journal records a finding's metadata and status so a resumed session shows the board
and scorecard, while the signed evidence bundle remains the one place the bytes live.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .finding import (EXPLOIT_REPLAY, Finding, FixSite, Frame, GateCheck,
                      GateResult, RepairLane, ReplayResult, Reproducer, RoeLevel, Status, Transition,
                      utcnow)

_ZERO = "0" * 64


def _canon(record: dict) -> bytes:
    return json.dumps({k: record[k] for k in record if k != "hash"},
                      sort_keys=True, separators=(",", ":")).encode()


def _chain_hash(prev: str, record: dict) -> str:
    return hashlib.sha256(prev.encode() + _canon(record)).hexdigest()


class Journal:
    """Append-only, hash-chained JSONL. One per session, under the evidence root."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = _ZERO
        self._seq = 0
        if self.path.exists():                       # resuming onto an existing journal
            for rec in read(self.path):
                self._prev = rec.get("hash", self._prev)
                self._seq = rec.get("seq", self._seq) + 1

    def emit(self, kind: str, **fields: Any) -> dict:
        rec = {"seq": self._seq, "ts": utcnow().isoformat(), "mono": round(time.monotonic(), 6),
               "kind": kind, "prev": self._prev, **fields}
        rec["hash"] = _chain_hash(self._prev, rec)
        with self.path.open("a") as fh:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())                     # a 36-hour run must survive an abrupt kill
        self._prev = rec["hash"]
        self._seq += 1
        return rec


def sign(path: str | Path, key: bytes | None = None) -> dict:
    """D5: sign the journal so the run's audit trail is tamper-evident on its own, not only via the
    per-line chain. Signs the final chain hash and the record count with pqsign (PQ when available,
    HMAC otherwise). The signed object is what ships alongside the journal in the evidence bundle."""
    from . import pqsign
    from .bundle import signing_key
    recs = read(path)
    final = recs[-1]["hash"] if recs else _ZERO
    material = f"{len(recs)}:{final}".encode()
    k, key_id = (key, "caller") if key is not None else signing_key()
    sig = pqsign.sign(material, k)
    sig.update({"key_id": key_id, "records": len(recs), "final_hash": final})
    return sig


def read(path: str | Path) -> list[dict]:
    """Every record in order. Skips blank lines; a truncated final line (a kill mid-write) is dropped."""
    out: list[dict] = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            break                                    # a half-written trailing line; stop cleanly
    return out


def verify(path: str | Path) -> tuple[bool, list[str]]:
    """Recompute the chain. Returns (ok, problems). A changed, inserted or dropped line fails."""
    problems: list[str] = []
    prev = _ZERO
    expect_seq = 0
    for rec in read(path):
        if rec.get("prev") != prev:
            problems.append(f"seq {rec.get('seq')}: prev-hash mismatch")
        if rec.get("seq") != expect_seq:
            problems.append(f"expected seq {expect_seq}, saw {rec.get('seq')}")
        if _chain_hash(prev, rec) != rec.get("hash"):
            problems.append(f"seq {rec.get('seq')}: content hash mismatch")
        prev = rec.get("hash", prev)
        expect_seq = (rec.get("seq", expect_seq)) + 1
    return (not problems), problems


# ---- finding snapshot / reconstruction (for resume) --------------------------------------------

def snapshot_finding(f: Finding) -> dict:
    """The fields resume needs to rebuild a finding's board/scorecard state. No reproducer bytes."""
    return {
        "scalars": {"oracle": f.oracle, "bug_class": f.bug_class, "language": f.language,
                    "target": f.target, "message": f.message, "severity": f.severity},
        "id": f.id, "status": f._status.value, "created_at": f.created_at.isoformat(),
        "reproducer": ({"sha256": f.reproducer.artifact_sha256, "cmd": f.reproducer.replay_cmd,
                        "kind": f.reproducer.kind, "size": f.reproducer.size_bytes,
                        "minimised": f.reproducer.minimised} if f.reproducer else None),
        "replay_before": ({"fired": f.replay_before.oracle_fired,
                           "sig": f.replay_before.abort_signature,
                           "at": f.replay_before.at.isoformat() if f.replay_before.at else None}
                          if f.replay_before else None),
        "replay_after": ({"fired": f.replay_after.oracle_fired,
                          "sig": f.replay_after.abort_signature,
                          "at": f.replay_after.at.isoformat() if f.replay_after.at else None}
                         if f.replay_after else None),
        "gate": {c.value: {"passed": g.passed, "quarantined": g.quarantined_inputs,
                           "at": g.at.isoformat() if g.at else None}
                 for c, g in f.gate.items()},
        "fix_sites": [{"uri": s.uri, "rank": s.rank, "line": s.start_line, "symbol": s.symbol,
                       "rationale": s.rationale} for s in f.fix_site_set],
        "frames": [{"symbol": fr.symbol, "uri": fr.uri, "line": fr.line} for fr in f.frames],
        "lane_history": [l.value for l in f.lane_history],
        "repair_lane": f.repair_lane.value if f.repair_lane else None,
        "gate_history": [{"check": g.check.value, "passed": g.passed,
                          "quarantined": g.quarantined_inputs,
                          "at": g.at.isoformat() if g.at else None} for g in f.gate_history],
        "merged_from": list(f.merged_from), "reachability": f.reachability,
        "mission_impact": f.mission_impact, "chain_ids": list(f.chain_ids),
        "evidence_score": f.evidence_score, "parliament": f.parliament, "red_team": f.red_team,
        "frontier": list(f.frontier), "roe_level": f.roe_level.value,
        "operator_actions": list(f.operator_actions), "disputed": f.disputed,
        "history": [{"from": t.from_status.value if t.from_status else None, "to": t.to_status.value,
                     "at": t.at.isoformat(), "reason": t.reason} for t in f.history],
    }


def finding_from_snapshot(d: dict) -> Finding:
    """Rebuild a Finding from a snapshot via the reconstructed-record path (its own history is
    re-validated by Finding.__post_init__, so a forged snapshot is still refused)."""
    from datetime import datetime

    def dt(s): return datetime.fromisoformat(s) if s else None
    repro = None
    if d["reproducer"]:
        r = d["reproducer"]
        repro = Reproducer(artifact_sha256=r["sha256"], replay_cmd=list(r["cmd"]),
                           minimised=r.get("minimised", False), size_bytes=r.get("size"),
                           kind=r.get("kind", EXPLOIT_REPLAY))
    def _replay(x):
        return ReplayResult(oracle_fired=x["fired"], at=dt(x["at"]), abort_signature=x.get("sig")) if x else None
    rb = _replay(d["replay_before"])
    ra = _replay(d.get("replay_after"))
    gate = {GateCheck(k): GateResult(check=GateCheck(k), passed=v["passed"],
                                     at=dt(v.get("at")) or utcnow(), quarantined_inputs=v.get("quarantined", 0))
            for k, v in d.get("gate", {}).items()}
    history = [Transition(Status(h["from"]) if h["from"] else None, Status(h["to"]), dt(h["at"]),
                          h.get("reason")) for h in d["history"]]
    f = Finding(
        **d["scalars"],
        frames=[Frame(symbol=fr["symbol"], uri=fr.get("uri"), line=fr.get("line")) for fr in d["frames"]],
        reproducer=repro, replay_before=rb, replay_after=ra, gate=gate,
        fix_site_set=[FixSite(uri=s["uri"], rank=s["rank"], start_line=s.get("line"),
                              symbol=s.get("symbol"), rationale=s.get("rationale")) for s in d["fix_sites"]],
        lane_history=[RepairLane(x) for x in d["lane_history"]],
        repair_lane=RepairLane(d["repair_lane"]) if d["repair_lane"] else None,
        gate_history=[GateResult(check=GateCheck(g["check"]), passed=g["passed"],
                                 at=dt(g.get("at")) or utcnow(),
                                 quarantined_inputs=g.get("quarantined", 0)) for g in d["gate_history"]],
        merged_from=list(d["merged_from"]), reachability=d.get("reachability"),
        mission_impact=d.get("mission_impact"), chain_ids=list(d.get("chain_ids", [])),
        evidence_score=d.get("evidence_score"), parliament=d.get("parliament"),
        red_team=d.get("red_team"), frontier=list(d.get("frontier", [])),
        operator_actions=list(d.get("operator_actions", [])), disputed=d.get("disputed"),
        roe_level=RoeLevel(d["roe_level"]), id=d["id"], created_at=dt(d["created_at"]),
        history=history, _status=Status(d["status"]),
    )
    return f
