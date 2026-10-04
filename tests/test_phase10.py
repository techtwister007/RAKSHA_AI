"""Phase 10 scaffolding: the health monitor, the watchdog, and the rehearsal harness.

These test the endurance machinery with injected probes and a fake clock, so the logic that must
survive a 36-hour run is verified without needing 36 hours or the finale hardware.
"""

from __future__ import annotations

from pathlib import Path

from raksha.health import HealthCaps, HealthMonitor, Watchdog
from raksha.rehearse import Rehearsal


# ---------------------------------------------------------------- health monitor

def test_healthy_snapshot_has_no_alerts():
    m = HealthMonitor(disk_probe=lambda: 80.0, mem_probe=lambda: 40.0,
                      corpus_probe=lambda: 0, stuck_probe=lambda: 0, model_probe=lambda: True)
    snap = m.check()
    assert snap.ok and snap.alerts == []


def test_low_disk_raises_an_alert():
    m = HealthMonitor(caps=HealthCaps(min_disk_free_pct=10.0), disk_probe=lambda: 3.0)
    snap = m.check()
    assert not snap.ok and any("disk low" in a for a in snap.alerts)


def test_high_memory_and_large_corpus_and_stuck_procs_alert():
    m = HealthMonitor(caps=HealthCaps(max_mem_used_pct=90, max_corpus_bytes=100, max_stuck_procs=0),
                      disk_probe=lambda: 99.0, mem_probe=lambda: 95.0,
                      corpus_probe=lambda: 500, stuck_probe=lambda: 2, model_probe=lambda: True)
    snap = m.check()
    assert any("memory high" in a for a in snap.alerts)
    assert any("corpus large" in a for a in snap.alerts)
    assert any("stuck subprocess" in a for a in snap.alerts)


def test_dead_model_server_alerts_with_degrade_guidance():
    m = HealthMonitor(disk_probe=lambda: 99.0, mem_probe=lambda: 10.0, model_probe=lambda: False)
    snap = m.check()
    assert any("model server not responding" in a and "degrade" in a for a in snap.alerts)


def test_snapshot_serialises():
    snap = HealthMonitor(disk_probe=lambda: 50.0).check()
    d = snap.as_dict()
    assert set(d) >= {"disk_free_pct", "mem_used_pct", "corpus_bytes", "alerts", "ok"}


# ---------------------------------------------------------------- watchdog

class FlakyComponent:
    def __init__(self, name, alive_after_restart=True):
        self.name = name
        self._alive = False
        self._alive_after = alive_after_restart
        self.restarts = 0

    def is_alive(self):
        return self._alive

    def restart(self):
        self.restarts += 1
        self._alive = self._alive_after


def test_watchdog_restarts_a_dead_component_visibly():
    w = Watchdog()
    comp = FlakyComponent("vllm")
    ev = w.tick(comp)
    assert ev is not None and ev.component == "vllm" and ev.attempt == 1
    assert comp.restarts == 1 and len(w.events) == 1


def test_watchdog_does_nothing_for_a_live_component():
    w = Watchdog()
    comp = FlakyComponent("vllm")
    comp._alive = True
    assert w.tick(comp) is None and comp.restarts == 0


def test_watchdog_gives_up_after_the_cap_instead_of_looping():
    w = Watchdog(max_restarts=3)
    comp = FlakyComponent("fuzzer", alive_after_restart=False)  # never recovers
    for _ in range(10):
        w.tick(comp)
    assert w.restart_count("fuzzer") == 3        # capped, not an infinite restart loop


# ---------------------------------------------------------------- rehearsal harness

def test_rehearsal_loops_and_reports_with_a_fake_clock():
    # a fake clock advances 1s per reading, so a 5s rehearsal runs a bounded number of iterations
    ticks = iter(i * 0.1 for i in range(100000))
    m = HealthMonitor(disk_probe=lambda: 80.0, mem_probe=lambda: 40.0)
    r = Rehearsal(targets=[Path("x")], monitor=m, health_every_s=1.0, clock=lambda: next(ticks))
    rep = r.run(duration_s=3, work=lambda t: 2)
    assert rep.iterations >= 1 and rep.findings_total >= 2
    assert rep.survived and rep.health_samples


def test_rehearsal_records_errors_and_keeps_going():
    ticks = iter(i * 0.1 for i in range(100000))
    def flaky(_):
        flaky.n += 1
        if flaky.n == 1:
            raise RuntimeError("target wedged")
        return 1
    flaky.n = 0
    r = Rehearsal(targets=[Path("a"), Path("b")], health_every_s=1.0, clock=lambda: next(ticks))
    rep = r.run(duration_s=4, work=flaky)
    assert rep.errors == 1 and rep.iterations >= 1 and not rep.survived   # an error means not survived


def test_rehearsal_surfaces_a_health_breach_as_not_survived():
    ticks = iter(i * 0.1 for i in range(100000))
    m = HealthMonitor(caps=HealthCaps(min_disk_free_pct=10.0), disk_probe=lambda: 2.0)
    r = Rehearsal(targets=[Path("x")], monitor=m, health_every_s=1.0, clock=lambda: next(ticks))
    rep = r.run(duration_s=3, work=lambda t: 0)
    assert not rep.survived and "disk low" in rep.summary()


def test_rehearsal_drives_the_watchdog_over_components():
    ticks = iter(i * 0.1 for i in range(100000))
    comp = FlakyComponent("vllm")
    r = Rehearsal(targets=[Path("x")], components=[comp], health_every_s=10.0, clock=lambda: next(ticks))
    rep = r.run(duration_s=3, work=lambda t: 0)
    assert rep.restarts >= 1 and comp.restarts >= 1


# ---------------------------------------------------------------- endurance of the harness itself

def test_timeline_is_bounded_over_a_long_run():
    from raksha.rehearse import TIMELINE_LIMIT
    ticks = iter(i * 0.0001 for i in range(10_000_000))
    r = Rehearsal(targets=[Path("x")], health_every_s=1e9, clock=lambda: next(ticks),
                  iteration_timeout_s=None)
    rep = r.run(duration_s=8, work=lambda t: 0)
    assert rep.iterations > TIMELINE_LIMIT * 5 and len(rep.timeline) <= TIMELINE_LIMIT


def test_a_wedged_iteration_is_abandoned_not_waited_on():
    import time
    calls = {"n": 0}
    def work(_):
        calls["n"] += 1
        if calls["n"] == 1:
            time.sleep(5)          # wedged target
        return 0
    r = Rehearsal(targets=[Path("w")], health_every_s=1e9, iteration_timeout_s=0.2)
    rep = r.run(duration_s=0.6, work=work)
    assert rep.timeouts == 1 and rep.iterations >= 1 and not rep.survived


def test_a_failing_probe_is_an_incident_not_a_crash():
    def boom():
        raise FileNotFoundError("corpus file vanished")
    m = HealthMonitor(disk_probe=lambda: 80.0, mem_probe=lambda: 10.0, corpus_probe=boom,
                      stuck_probe=lambda: 0, model_probe=lambda: True)
    ticks = iter(i * 0.1 for i in range(100000))
    rep = Rehearsal(targets=[Path("x")], monitor=m, health_every_s=1.0,
                    clock=lambda: next(ticks)).run(duration_s=3, work=lambda t: 0)
    assert not rep.survived and "probe failed" in rep.summary()


def test_stuck_probe_sees_an_unreaped_child():
    import subprocess
    import time
    from raksha.health import stuck_children
    p = subprocess.Popen(["true"])
    time.sleep(0.3)
    assert stuck_children() >= 1
    p.wait()
