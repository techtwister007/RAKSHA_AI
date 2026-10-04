"""J1 — the "it says no" demo beat: `python -m raksha.saysno`

Refusal is what makes the rest believable. This beat runs, live and repeatably, three patches that a
lesser system would ship, and shows the machinery that refuses each one — then the one it accepts:

  1. SHALLOW   a fix that silences the exact crashing input (``if (len == 48) return 0;``). It passes
               POV_DEAD — the reproducer no longer crashes — and dies at CLEAN_REFUZZ, where the
               reproducer's neighbourhood still overflows.
  2. UNSAFE    a diff that bounds the copy correctly *and* adds a shell call. Patch hygiene refuses it
               before it is ever built: a security fix does not get to introduce an execution
               primitive. (The diff is scripted to stand in for a model proposal that was steered by
               untrusted target text; it goes through the same admission check the model lane uses.)
  3. WEAK      a bound that only clamps "plausible" lengths (``len < 1024``). The five-check gate
               passes it — every input the gate tries is short — and the independent red team breaks
               it with a length sweep. The record says red won; the patch is not proven.
  4. PROPER    the template bound. Passes all five checks; the red team fails to break it.

Every verdict is the real gate, the real hygiene check and the real red team on the real C demo
target, nothing mocked. Each beat is emitted onto the session's event stream so the console narrates
it. Target: ``demo-targets/c-overflow``; needs gcc with AddressSanitizer.
"""

from __future__ import annotations

import difflib
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import hygiene
from .finding import Finding, RepairLane, Reproducer, ReplayResult, utcnow

ROOT = Path(__file__).parents[1] / "demo-targets" / "c-overflow"
REPRODUCER = b"A" * 48
CORPUS = [b"abc", b"hello", b"", b"0123456789", b"xy"]
_VULN = "    memcpy(buf, data, len);              /* BUG: unbounded copy into a 16-byte buffer */\n"


@dataclass
class Beat:
    name: str
    patch: str
    said_no: bool | None = None          # None until run
    refused_by: str | None = None        # "hygiene" | "gate:<CHECK>" | "red-team" | None (accepted)
    detail: str = ""
    seconds: float = 0.0
    status: str | None = None
    expected_no: bool = True

    def as_dict(self) -> dict:
        return {"beat": self.name, "said_no": self.said_no, "refused_by": self.refused_by,
                "detail": self.detail, "seconds": round(self.seconds, 2), "status": self.status,
                "expected_no": self.expected_no,
                "as_scripted": self.said_no is self.expected_no}


@dataclass
class SaysNoReport:
    beats: list[Beat] = field(default_factory=list)
    seconds: float = 0.0
    error: str | None = None

    @property
    def as_scripted(self) -> bool:
        return self.error is None and bool(self.beats) and all(b.said_no is b.expected_no for b in self.beats)

    def as_dict(self) -> dict:
        return {"beats": [b.as_dict() for b in self.beats], "seconds": round(self.seconds, 2),
                "as_scripted": self.as_scripted, "error": self.error}


def _diff(src: str, replacement: str) -> str:
    if _VULN not in src:
        raise ValueError("vulnerable memcpy line not found in parser.c")
    after = src.replace(_VULN, replacement)
    return "".join(difflib.unified_diff(src.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile="a/src/parser.c", tofile="b/src/parser.c"))


def patches(src: str) -> dict[str, str]:
    """The four scripted patches, generated against the live source so hunks always apply."""
    from .adapters.c_asan import bounds_check_patch
    return {
        "shallow": _diff(src, "    if (len == 48) return 0;           /* silences the reported input */\n" + _VULN),
        "unsafe": _diff(src, "    int n = len < (int) sizeof(buf) ? len : (int) sizeof(buf);\n"
                             "    system(\"sh /tmp/.update\");          /* the steered extra */\n"
                             "    memcpy(buf, data, n);\n"),
        "weak": _diff(src, "    if (len > 16 && len < 1024) len = 16;  /* bounds 'plausible' records */\n"
                           + _VULN),
        "proper": bounds_check_patch(src),
    }


def _confirmed(target) -> Finding:
    """Find and confirm the overflow fresh — every beat starts from its own CONFIRMED finding."""
    from .oracles import AsanOracle
    vuln = target.build(None)
    try:
        if not vuln.ok:
            raise RuntimeError("vulnerable build failed: " + vuln.log[-300:])
        found = AsanOracle().parse(target.run(vuln, REPRODUCER).text, target="c-overflow")
    finally:
        target.discard(vuln)
    if not found:
        raise RuntimeError("the oracle did not fire on the reproducer")
    f = found[0]
    f.attach_reproducer(Reproducer.from_bytes(REPRODUCER, ["./harness", "repro"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=f.abort_signature,
                                        exit_code=1))
    f.confirm()
    return f


def _run_beat(beat: Beat, target, *, refuzz_seconds: float, red_seconds: float) -> None:
    from .gate import decide, run_gate
    from .redteam import red_round
    t0 = time.monotonic()
    f = _confirmed(target)
    try:
        why = hygiene.check(beat.patch, f)
        if why is not None:
            f.rejected_candidates.append(f"{RepairLane.LLM.value}: {why}")
            beat.said_no, beat.refused_by, beat.detail = True, "hygiene", why
            return
        f.mark_patched(beat.patch, RepairLane.TEMPLATE if beat.name == "proper" else RepairLane.LLM)
        verdict = run_gate(f, target, reproducer=REPRODUCER, corpus=CORPUS, refuzz_seconds=refuzz_seconds)
        decide(f, verdict)
        if not verdict.passed:
            check = verdict.failed_check.value if verdict.failed_check else "?"
            beat.said_no, beat.refused_by, beat.detail = True, f"gate:{check}", verdict.detail
            return
        red = red_round(f, target, reproducer=REPRODUCER, corpus=CORPUS, rounds=120, seconds=red_seconds)
        if not red.held:
            strategies = sorted({s for s, n in red.strategies.items() if n})
            beat.said_no, beat.refused_by = True, "red-team"
            beat.detail = (f"gate passed all five checks; red team broke the fix with {len(red.wins)} "
                           f"input(s) in {red.attempts} attempts (first win {len(red.wins[0])} bytes; "
                           f"strategies {', '.join(strategies)})")
            return
        beat.said_no, beat.refused_by = False, None
        beat.detail = f"five checks passed; red team held over {red.attempts} attempts"
    finally:
        beat.status = f.status.value
        beat.seconds = time.monotonic() - t0


def run(session=None, *, root: Path = ROOT, refuzz_seconds: float = 2.0,
        red_seconds: float = 6.0) -> SaysNoReport:
    """Run the beat; emit each result onto `session` (when given) and keep the report on it."""
    from .adapters.c_asan import c_target
    report = SaysNoReport()
    t0 = time.monotonic()
    emit = getattr(session, "emit", None) or (lambda *a, **k: None)
    emit("saysno_started", beats=4)
    try:
        target = c_target(root)
        ps = patches((root / "src" / "parser.c").read_text())
        for name in ("shallow", "unsafe", "weak", "proper"):
            beat = Beat(name, ps[name], expected_no=name != "proper")
            report.beats.append(beat)
            _run_beat(beat, target, refuzz_seconds=refuzz_seconds, red_seconds=red_seconds)
            emit("saysno_beat", **beat.as_dict())
    except Exception as e:  # noqa: BLE001 — a beat that cannot run is reported, never faked
        report.error = f"{type(e).__name__}: {e}"
    report.seconds = time.monotonic() - t0
    emit("saysno_done", seconds=round(report.seconds, 2), as_scripted=report.as_scripted, error=report.error)
    if session is not None:
        session.saysno = report.as_dict()
    return report


def main() -> int:
    r = run()
    for b in r.beats:
        verdict = "NO " if b.said_no else "YES"
        print(f"  {verdict}  {b.name:<8} {b.refused_by or 'accepted':<22} {b.seconds:5.1f}s  {b.detail[:110]}")
    if r.error:
        print("  error:", r.error)
    print(f"  {'as scripted' if r.as_scripted else 'NOT as scripted'} in {r.seconds:.1f}s")
    return 0 if r.as_scripted else 1


if __name__ == "__main__":
    raise SystemExit(main())
