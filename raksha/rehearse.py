"""The dress-rehearsal harness — run the whole system for a long time and watch it survive.

The campaign plan's Phase 10 is two full 36-hour runs on fresh targets, nobody touching them
overnight, watching for the endurance failures that only a long run reveals. That execution needs
the finale hardware (GPU, Docker, vLLM) for a real duration; this harness is the thing you point at
it. It loops the pipeline over a target set, samples health on a fixed cadence, records a timeline,
and stops at the configured duration — producing a rehearsal report that says whether the run
survived itself and lists every alert and watchdog restart.

Runnable now for a short self-test (seconds), identical in shape to the 36-hour run (hours); only
`duration_s` changes. It never raises on a failing iteration — a rehearsal that crashes on one bad
target is not a rehearsal, so failures are recorded and the loop continues.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .health import HealthMonitor, HealthSnapshot, Watchdog
from .lanes import scan_target


@dataclass
class TimelineEvent:
    at_s: float
    kind: str          # "iteration" | "health" | "restart" | "error"
    detail: str


@dataclass
class RehearsalReport:
    duration_s: float
    iterations: int = 0
    findings_total: int = 0
    health_samples: list[HealthSnapshot] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    restarts: int = 0
    errors: int = 0

    @property
    def survived(self) -> bool:
        """A run survives if it finished, stayed within caps the whole way, and needed no give-up."""
        return all(s.ok for s in self.health_samples) and self.errors == 0

    def summary(self) -> str:
        worst = [a for s in self.health_samples for a in s.alerts]
        head = (f"rehearsal {self.duration_s:.0f}s: {self.iterations} iterations, "
                f"{self.findings_total} findings, {self.restarts} restarts, {self.errors} errors")
        if self.survived:
            return head + " — SURVIVED (within all caps, no intervention)"
        return head + " — ATTENTION:\n  " + "\n  ".join(dict.fromkeys(worst)) if worst else head + " — errors occurred"

    def as_dict(self) -> dict:
        return {
            "duration_s": self.duration_s, "iterations": self.iterations,
            "findings_total": self.findings_total, "restarts": self.restarts,
            "errors": self.errors, "survived": self.survived,
            "health": [s.as_dict() for s in self.health_samples[-5:]],
        }


@dataclass
class Rehearsal:
    targets: list[Path]
    monitor: HealthMonitor = field(default_factory=HealthMonitor)
    watchdog: Watchdog = field(default_factory=Watchdog)
    health_every_s: float = 2.0
    components: list = field(default_factory=list)   # supervised components for the watchdog
    clock: Callable[[], float] = time.monotonic

    def run(self, *, duration_s: float, work: Callable[[Path], int] | None = None) -> RehearsalReport:
        """Loop the pipeline over the targets until `duration_s` elapses, sampling health."""
        work = work or self._default_work
        report = RehearsalReport(duration_s=duration_s)
        start = self.clock()
        last_health = 0.0
        i = 0
        while self.clock() - start < duration_s:
            target = self.targets[i % len(self.targets)] if self.targets else None
            i += 1
            try:
                n = work(target) if target is not None else 0
                report.findings_total += n
                report.iterations += 1
                report.timeline.append(TimelineEvent(self.clock() - start, "iteration",
                                                      f"{target.name if target else '-'}: {n} findings"))
            except Exception as e:  # noqa: BLE001 — record and continue; a rehearsal does not crash
                report.errors += 1
                report.timeline.append(TimelineEvent(self.clock() - start, "error", str(e)))

            for comp in self.components:
                ev = self.watchdog.tick(comp)
                if ev:
                    report.restarts += 1
                    report.timeline.append(TimelineEvent(self.clock() - start, "restart",
                                                          f"{ev.component} (attempt {ev.attempt})"))

            now = self.clock() - start
            if now - last_health >= self.health_every_s:
                snap = self.monitor.check()
                report.health_samples.append(snap)
                report.timeline.append(TimelineEvent(now, "health",
                                                      "ok" if snap.ok else "; ".join(snap.alerts)))
                last_health = now
        if not report.health_samples:                     # always sample at least once
            report.health_samples.append(self.monitor.check())
        return report

    @staticmethod
    def _default_work(target: Path) -> int:
        """One rehearsal iteration: a build-free scan of the target (fast, deterministic)."""
        return len(scan_target(target).findings)


def main() -> int:
    """`python -m raksha.rehearse [seconds]` — a short local self-test of the harness."""
    import sys
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 6.0
    repo = Path(__file__).parents[1]
    targets = [p for p in [repo / "demo-targets" / "mixed-estate"] if p.exists()]
    rep = Rehearsal(targets, health_every_s=1.0).run(duration_s=seconds)
    print(rep.summary())
    return 0 if rep.survived else 1


if __name__ == "__main__":
    raise SystemExit(main())
