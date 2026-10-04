"""J9 — the time-lapse: scrub a recorded run's journal to see what the system was doing at any hour.

The session journal (W0-1) is an append-only, hash-chained record of every pipeline event. This
module replays it — after verifying the chain, so a scrubbed view is never of an edited history —
into a state at any instant: findings by status, targets on the board, the events in the window
just before (what the system was *doing*), and cumulative throughput. `frames()` samples that state
at even steps for the console's scrub bar.

Record a long run with ``python -m raksha.timelapse record OUT.jsonl --minutes 30`` (it loops the
bundled demo work — estate scans, harness synthesis, the gate, the "says no" beat — into one
journal); replay it with ``python -m raksha.timelapse show OUT.jsonl``.
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from . import journal as _journal

#: Event kinds that describe "doing", mapped to a phrase for the narrative line.
_DOING = {
    "build_free_scanned": "scanning an estate (build-free lanes)",
    "autofuzz_started": "synthesising a harness and fuzzing",
    "harness_synthesized": "synthesising a harness and fuzzing",
    "crash_confirmed": "confirming a crash",
    "candidate_gated": "gating a repair candidate",
    "gate_verdict": "gating a repair candidate",
    "finding_status": "recording a verdict",
    "red_team_round": "red-teaming a verified fix",
    "saysno_beat": "running the refusal beat",
    "intake_started": "ingesting new media",
    "intake_staged": "ingesting new media",
    "operator_action": "an operator acting",
    "checkpoint": "checkpointing",
}


def _t(rec: dict) -> float:
    return datetime.fromisoformat(rec["ts"]).timestamp()


class Recording:
    """A verified journal, replayable to any instant."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.suffix == ".gz":                 # a recorded run shipped compressed
            import gzip
            import tempfile
            tmp = Path(tempfile.mkdtemp(prefix="raksha-tl-")) / self.path.stem
            tmp.write_bytes(gzip.decompress(self.path.read_bytes()))
            self._source = self.path
            self.path = tmp
        ok, problems = _journal.verify(self.path)
        if not ok:
            raise ValueError("journal failed verification: " + "; ".join(problems[:3]))
        self.records = _journal.read(self.path)
        if not self.records:
            raise ValueError("empty journal")
        self.t0 = _t(self.records[0])
        self.duration = _t(self.records[-1]) - self.t0

    def at(self, offset_s: float, *, window_s: float = 60.0, recent: int = 8) -> dict:
        """The run's state `offset_s` seconds after it began."""
        cut = self.t0 + offset_s
        findings: dict[str, dict] = {}
        targets: set[str] = set()
        counts: dict[str, int] = {}
        window: list[dict] = []
        n = 0
        for rec in self.records:
            ts = _t(rec)
            if ts > cut:
                break
            n += 1
            kind = rec.get("kind", "?")
            counts[kind] = counts.get(kind, 0) + 1
            if kind == "checkpoint":
                for d in rec.get("findings", []):
                    sc = d.get("scalars", {})
                    findings[d["id"]] = {"status": d.get("status"), "bug_class": sc.get("bug_class"),
                                         "target": sc.get("target")}
                targets |= {t["name"] for t in rec.get("targets", [])}
            elif kind in ("finding_added", "finding_status") and rec.get("finding"):
                cur = findings.setdefault(rec["finding"], {})
                cur.update({k: rec[k] for k in ("status", "bug_class", "target") if rec.get(k) is not None})
            if rec.get("target") and kind != "checkpoint":
                targets.add(str(rec["target"]))
            if ts >= cut - window_s:
                window.append(rec)
        by_status: dict[str, int] = {}
        for f in findings.values():
            s = f.get("status") or "?"
            by_status[s] = by_status.get(s, 0) + 1
        doing = [_DOING[r["kind"]] for r in reversed(window) if r.get("kind") in _DOING]
        return {
            "offset_s": round(offset_s, 1), "at": datetime.fromtimestamp(cut).isoformat(timespec="seconds"),
            "events_so_far": n, "findings": len(findings), "by_status": by_status,
            "targets": len(targets), "doing": doing[0] if doing else "idle",
            "recent": [{"offset_s": round(_t(r) - self.t0, 1), "kind": r.get("kind"),
                        "target": r.get("target"), "finding": (r.get("finding") or "")[:8] or None,
                        "status": r.get("status")} for r in window[-recent:]],
            "kinds": counts,
        }

    def frames(self, n: int = 60) -> list[dict]:
        """`n` evenly spaced states from start to end (lightweight: no event list)."""
        n = max(2, n)
        out = []
        for i in range(n):
            st = self.at(self.duration * i / (n - 1), recent=0)
            st.pop("recent"); st.pop("kinds")
            out.append(st)
        return out

    def summary(self) -> dict:
        return {"path": getattr(self, "_source", self.path).name, "records": len(self.records),
                "duration_s": round(self.duration, 1),
                "started": self.records[0]["ts"], "ended": self.records[-1]["ts"],
                "chain_verified": True}


#: The recorded long run shipped with the repository (journal of RAKSHA's own demo work only).
RECORDED_RUN = Path(__file__).parents[1] / "docs" / "runs" / "longrun.jsonl.gz"


def for_session(session) -> "Recording | None":
    """The session's own journal when it has one with records, else the shipped recorded run."""
    j = getattr(session, "journal", None)
    if j is not None and j.path.exists() and j.path.stat().st_size:
        try:
            return Recording(j.path)
        except ValueError:
            pass
    return Recording(RECORDED_RUN) if RECORDED_RUN.exists() else None


def record(out: str | Path, *, minutes: float = 30.0, include_saysno: bool = True) -> dict:
    """Run the bundled demo work in a loop for `minutes`, journalled to `out` — a long run to scrub."""
    from .orchestrator import Session
    repo = Path(__file__).parents[1]
    s = Session()
    s.open_journal(out)
    deadline = time.monotonic() + minutes * 60
    rounds = 0
    work = [("mixed-estate", lambda r: s.ingest_build_free(repo / "demo-targets" / "mixed-estate",
                                                           name=f"mixed-estate#{r}")),
            ("c-nolibfuzzer", lambda r: s.ingest_autofuzz(repo / "demo-targets" / "c-nolibfuzzer",
                                                          name=f"c-nolibfuzzer#{r}",
                                                          corpus=[b"\x01\x04abcd", b"\x02zz"])),
            ("py-noharness", lambda r: s.ingest_autofuzz(repo / "demo-targets" / "py-noharness",
                                                         name=f"py-noharness#{r}",
                                                         corpus=[b"10 m to ft", b"warm"]))]
    while time.monotonic() < deadline:
        rounds += 1
        for _name, fn in work:
            if time.monotonic() >= deadline:
                break
            try:
                fn(rounds)
            except Exception as e:  # noqa: BLE001 — a step that fails is itself part of the record
                s.emit("step_failed", error=f"{type(e).__name__}: {e}"[:200])
        if include_saysno and time.monotonic() < deadline:
            from . import saysno
            saysno.run(s)
    s.emit("recording_done", rounds=rounds)
    return {"rounds": rounds, "records": len(_journal.read(out))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m raksha.timelapse")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record"); r.add_argument("out"); r.add_argument("--minutes", type=float, default=30.0)
    r.add_argument("--no-saysno", action="store_true")
    sh = sub.add_parser("show"); sh.add_argument("journal"); sh.add_argument("--frames", type=int, default=12)
    a = ap.parse_args(argv)
    if a.cmd == "record":
        print(record(a.out, minutes=a.minutes, include_saysno=not a.no_saysno))
        return 0
    rec = Recording(a.journal)
    print(rec.summary())
    for fr in rec.frames(a.frames):
        print(f"  +{fr['offset_s']:>8.1f}s  {fr['findings']:>4} findings  {fr['targets']:>3} targets  "
              f"{fr['by_status']}  — {fr['doing']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
