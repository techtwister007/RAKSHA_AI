"""Endurance monitoring — leaks, disk, stuck processes, a dying model server.

Nobody has run the whole system for 36 hours, and that is exactly where the failures live: memory
creeping up, disk filling with fuzzer corpus, subprocesses wedged, the model server falling over at
hour 20. They only show up in a long run, so the dress rehearsal is not optional — but the machinery
that catches them is buildable now and testable without the finale hardware.

Two pieces:
  - HealthMonitor samples disk, memory, corpus size, stuck-process count and model-server liveness
    against configured caps, and raises typed alerts when a cap is breached.
  - Watchdog restarts a component that has stopped responding and records the restart VISIBLY — a
    restart you can see on the Mission Board is a feature; a silent hang is the thing that loses a
    36-hour run.

Probes are injected, so the logic is unit-testable with fakes; the real probes read shutil /
/proc and invoke the component's own liveness check.
"""

from __future__ import annotations

import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class HealthCaps:
    min_disk_free_pct: float = 10.0
    max_mem_used_pct: float = 90.0
    max_corpus_bytes: int = 20 * 1024 * 1024 * 1024   # 20 GB
    max_stuck_procs: int = 0


@dataclass
class HealthSnapshot:
    at: float
    disk_free_pct: float
    mem_used_pct: float
    corpus_bytes: int
    stuck_procs: int
    model_server_ok: bool
    uptime_s: float
    alerts: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.alerts

    def as_dict(self) -> dict:
        return {
            "disk_free_pct": round(self.disk_free_pct, 1),
            "mem_used_pct": round(self.mem_used_pct, 1),
            "corpus_bytes": self.corpus_bytes,
            "stuck_procs": self.stuck_procs,
            "model_server_ok": self.model_server_ok,
            "uptime_s": round(self.uptime_s, 1),
            "alerts": list(self.alerts),
            "ok": self.ok,
        }


# ---- real probes (degrade gracefully where a reading is unavailable, e.g. in a container) ----

def disk_free_pct(path: str | Path = ".") -> float:
    try:
        u = shutil.disk_usage(str(path))
        return 100.0 * u.free / u.total if u.total else 100.0
    except OSError:
        return 100.0


def mem_used_pct() -> float:
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, rest = line.partition(":")
            info[k] = int(rest.strip().split()[0])  # kB
        total, avail = info.get("MemTotal", 0), info.get("MemAvailable", 0)
        return 100.0 * (total - avail) / total if total else 0.0
    except (OSError, ValueError, IndexError):
        return 0.0


def dir_bytes(path: str | Path) -> int:
    """Total size under `path`. Files that vanish mid-walk (a fuzzer rotating its corpus) are
    skipped, not fatal — a probe must never crash the run it is watching."""
    root = Path(path)
    total = 0
    if not root.exists():
        return 0
    for p in root.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def corpus_bytes() -> int:
    """Size of the fuzzing corpus directory (RAKSHA_CORPUS_DIR), or 0 when none is configured."""
    import os
    path = os.environ.get("RAKSHA_CORPUS_DIR")
    return dir_bytes(path) if path else 0


def stuck_children() -> int:
    """Descendant processes that are zombies (never reaped) or stuck in uninterruptible sleep — the
    process states a wedged subprocess actually leaves behind. Read from /proc; 0 where unavailable."""
    import os
    me = os.getpid()
    try:
        entries = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return 0
    parent: dict[int, int] = {}
    state: dict[int, str] = {}
    for pid in entries:
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            after = raw[raw.rindex(")") + 2:].split()      # fields after "(comm)"
            state[int(pid)], parent[int(pid)] = after[0], int(after[1])
        except (OSError, ValueError, IndexError):
            continue
    def descends(pid: int) -> bool:
        seen = 0
        while pid in parent and seen < 64:
            pid = parent[pid]
            if pid == me:
                return True
            seen += 1
        return False
    return sum(1 for pid, st in state.items() if st in ("Z", "D") and descends(pid))


def model_alive() -> bool:
    """True when no model server is configured (nothing to be dead) or it answers."""
    from .inference import model_server_alive
    return model_server_alive() is not False


@dataclass
class HealthMonitor:
    caps: HealthCaps = field(default_factory=HealthCaps)
    # real probes by default; tests inject fakes. The disk probe watches the temp directory, which is
    # where every scratch build and refuzz campaign is written.
    disk_probe: Callable[[], float] = field(default=lambda: disk_free_pct(tempfile.gettempdir()))
    mem_probe: Callable[[], float] = mem_used_pct
    corpus_probe: Callable[[], int] = corpus_bytes
    stuck_probe: Callable[[], int] = stuck_children
    model_probe: Callable[[], bool] = model_alive
    _started: float = field(default_factory=time.monotonic)

    def check(self) -> HealthSnapshot:
        disk = self.disk_probe()
        mem = self.mem_probe()
        corpus = self.corpus_probe()
        stuck = self.stuck_probe()
        model = self.model_probe()
        alerts: list[str] = []
        if disk < self.caps.min_disk_free_pct:
            alerts.append(f"disk low: {disk:.1f}% free (< {self.caps.min_disk_free_pct}%) — minimise corpus")
        if mem > self.caps.max_mem_used_pct:
            alerts.append(f"memory high: {mem:.1f}% used (> {self.caps.max_mem_used_pct}%)")
        if corpus > self.caps.max_corpus_bytes:
            alerts.append(f"corpus large: {corpus} bytes (> {self.caps.max_corpus_bytes}) — run afl-cmin")
        if stuck > self.caps.max_stuck_procs:
            alerts.append(f"{stuck} stuck subprocess(es) — watchdog should reap them")
        if not model:
            alerts.append("model server not responding — degrade to template/retrieval, restart server")
        return HealthSnapshot(time.monotonic(), disk, mem, corpus, stuck, model,
                              time.monotonic() - self._started, alerts)


# ---- the watchdog ----

class Component:
    """What the watchdog needs from a supervised component."""
    name: str
    def is_alive(self) -> bool: ...   # pragma: no cover - protocol
    def restart(self) -> None: ...    # pragma: no cover - protocol


@dataclass
class RestartEvent:
    component: str
    at: float
    attempt: int


@dataclass
class Watchdog:
    """Restarts a component that stopped responding, visibly, up to a cap per component."""
    max_restarts: int = 5
    events: list[RestartEvent] = field(default_factory=list)
    _counts: dict[str, int] = field(default_factory=dict)

    def tick(self, component: Component) -> RestartEvent | None:
        """Check one component; restart it if down and under the cap. Returns the event if it acted."""
        if component.is_alive():
            return None
        n = self._counts.get(component.name, 0)
        if n >= self.max_restarts:
            return None  # give up; the health alert surfaces it instead of a restart loop
        self._counts[component.name] = n + 1
        component.restart()
        ev = RestartEvent(component.name, time.monotonic(), n + 1)
        self.events.append(ev)
        return ev

    def restart_count(self, name: str) -> int:
        return self._counts.get(name, 0)
