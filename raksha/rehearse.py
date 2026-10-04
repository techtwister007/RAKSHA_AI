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

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

#: The timeline keeps the most recent events only. A 36-hour run loops millions of times; an
#: unbounded list of iteration events would itself become the memory leak the rehearsal hunts for.
#: Alerts, restarts and errors are never lost — they are counted, and kept in their own bounded log.
TIMELINE_LIMIT = 2000
INCIDENT_LIMIT = 5000

from .health import HealthMonitor, Watchdog
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
    health_samples: deque = field(default_factory=lambda: deque(maxlen=TIMELINE_LIMIT))
    timeline: deque = field(default_factory=lambda: deque(maxlen=TIMELINE_LIMIT))
    incidents: deque = field(default_factory=lambda: deque(maxlen=INCIDENT_LIMIT))
    restarts: int = 0
    errors: int = 0
    timeouts: int = 0
    unhealthy_samples: int = 0

    @property
    def survived(self) -> bool:
        """A run survives if it finished, stayed within caps the whole way, and needed no give-up.
        Counted over EVERY sample and iteration, not only the ones still in the bounded window."""
        return self.unhealthy_samples == 0 and self.errors == 0 and self.timeouts == 0

    def summary(self) -> str:
        worst = [e.detail for e in self.incidents if e.kind in ("health", "timeout")]
        head = (f"rehearsal {self.duration_s:.0f}s: {self.iterations} iterations, "
                f"{self.findings_total} findings, {self.restarts} restarts, {self.errors} errors, "
                f"{self.timeouts} timeouts")
        if self.survived:
            return head + " — SURVIVED (within all caps, no intervention)"
        return head + " — ATTENTION:\n  " + "\n  ".join(dict.fromkeys(worst)) if worst else head + " — errors occurred"

    def as_dict(self) -> dict:
        return {
            "duration_s": self.duration_s, "iterations": self.iterations,
            "findings_total": self.findings_total, "restarts": self.restarts,
            "errors": self.errors, "timeouts": self.timeouts, "survived": self.survived,
            "health": [s.as_dict() for s in list(self.health_samples)[-5:]],
            "incidents": [e.__dict__ for e in list(self.incidents)[-20:]],
        }


@dataclass
class Rehearsal:
    targets: list[Path]
    monitor: HealthMonitor = field(default_factory=HealthMonitor)
    watchdog: Watchdog = field(default_factory=Watchdog)
    health_every_s: float = 2.0
    components: list = field(default_factory=list)   # supervised components for the watchdog
    clock: Callable[[], float] = time.monotonic
    #: A single iteration that runs longer than this is a wedged target: recorded, abandoned, and the
    #: loop moves on (the runbook's "a target wedges the loop" row). None disables the limit.
    iteration_timeout_s: float | None = 600.0

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
                n = self._bounded(work, target) if target is not None else 0
                report.findings_total += n
                report.iterations += 1
                report.timeline.append(TimelineEvent(self.clock() - start, "iteration",
                                                      f"{target.name if target else '-'}: {n} findings"))
            except TimeoutError as e:
                report.timeouts += 1
                self._incident(report, start, "timeout", str(e))
            except Exception as e:  # noqa: BLE001 — record and continue; a rehearsal does not crash
                report.errors += 1
                self._incident(report, start, "error", f"{type(e).__name__}: {e}")

            for comp in self.components:
                try:
                    ev = self.watchdog.tick(comp)
                except Exception as e:  # noqa: BLE001 — a failing liveness check is an incident
                    report.errors += 1
                    self._incident(report, start, "error", f"watchdog on {getattr(comp, 'name', '?')}: {e}")
                    continue
                if ev:
                    report.restarts += 1
                    self._incident(report, start, "restart", f"{ev.component} (attempt {ev.attempt})")

            now = self.clock() - start
            if now - last_health >= self.health_every_s:
                self._sample(report, start)
                last_health = now
        if not report.health_samples:                     # always sample at least once
            self._sample(report, start)
        return report

    def _bounded(self, work: Callable[[Path], int], target: Path) -> int:
        """Run one iteration, abandoning it if it exceeds the per-iteration timeout."""
        if self.iteration_timeout_s is None:
            return work(target)
        box: dict = {}

        def run() -> None:
            try:
                box["n"] = work(target)
            except BaseException as e:  # noqa: BLE001 — re-raised in the caller
                box["e"] = e

        t = threading.Thread(target=run, daemon=True, name=f"rehearsal:{target.name}")
        t.start()
        t.join(self.iteration_timeout_s)
        if t.is_alive():
            raise TimeoutError(f"{target.name}: iteration exceeded {self.iteration_timeout_s:.0f}s — wedged")
        if "e" in box:
            raise box["e"]
        return box.get("n", 0)

    def _sample(self, report: RehearsalReport, start: float) -> None:
        try:
            snap = self.monitor.check()
        except Exception as e:  # noqa: BLE001 — a probe that fails is itself a health incident
            report.unhealthy_samples += 1
            self._incident(report, start, "health", f"health probe failed: {type(e).__name__}: {e}")
            return
        report.health_samples.append(snap)
        if not snap.ok:
            report.unhealthy_samples += 1
            self._incident(report, start, "health", "; ".join(snap.alerts))
        else:
            report.timeline.append(TimelineEvent(self.clock() - start, "health", "ok"))

    def _incident(self, report: RehearsalReport, start: float, kind: str, detail: str) -> None:
        ev = TimelineEvent(self.clock() - start, kind, detail)
        report.timeline.append(ev)
        report.incidents.append(ev)

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
