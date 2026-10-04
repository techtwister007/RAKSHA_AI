# Dress-rehearsal runbook (Phase 10)

Two full-length rehearsals on the finale hardware, plus the recorded backup. Nobody has run the
whole system for 36 hours; these runs exist to find the endurance failures that only a long run
reveals — before the finale, not during it. This runbook is executed on the real node (GPU, Docker,
vLLM); the harness that drives it is `raksha/rehearse.py` and the watchdog is `raksha/health.py`.

## Why two runs

One run tells you it worked once. Two tell you it repeats. The second run must finish with **no
manual intervention** — that is the exit gate for Phase 10.

## Before each run

1. Install from the sealed SSD with the cable out (`deploy/install.sh`); confirm the badges read
   `NETWORK INTERFACES: 0 · CLOUD CALLS: 0`.
2. Verify the bundle: `python3 deploy/bundle_manifest.py verify <bundle>`.
3. Pick a **fresh** target the system has not seen (not a demo target).
4. Set caps for the box in `HealthCaps` (disk, memory, corpus size, stuck-process count), point
   `RAKSHA_CORPUS_DIR` at the fuzzing corpus, and provision the sandbox
   (`RAKSHA_SANDBOX_IMAGE`, and `RAKSHA_REQUIRE_SANDBOX=1` so nothing runs unsandboxed).
5. Start the recorder for the final demo arc at a safe point (see "The recording").

## Running

```sh
# short self-test first (seconds), to confirm the harness is wired:
python3 -m raksha.rehearse 10

# the full run (seconds = 36h = 129600), on the finale node:
python3 -c "from pathlib import Path; from raksha.rehearse import Rehearsal; \
  r=Rehearsal([Path('/targets/finale')]).run(duration_s=129600); print(r.summary())"
```

The harness loops the pipeline over the target(s), samples health on a fixed cadence, runs the
watchdog over the supervised components you pass it (`components=[...]`: the model server and
fuzzer processes, each with `is_alive()` / `restart()`), and records a bounded timeline. It never
crashes on a bad iteration — a failure or a wedged target is recorded and the loop continues.

## What to watch for (the endurance failures)

| Symptom | Caught by | Response |
|---|---|---|
| Memory creeping up | `HealthMonitor` mem cap (`/proc/meminfo`) | restart the leaking component via the watchdog; note it |
| Disk filling | disk probe on the temp dir (where scratch builds and refuzz output land) | the gate deletes its scratch builds as it goes; the alert fires before the disk is full |
| Corpus growing | corpus probe on `RAKSHA_CORPUS_DIR` | `afl-cmin` minimisation |
| Stuck subprocesses | stuck probe: zombie / uninterruptible children, read from `/proc` | watchdog reaps and restarts |
| Model server dies (~hour 20) | model probe (`GET /models` through the inference interface) + `Watchdog` | restart vLLM; meanwhile the pipeline degrades to template/retrieval — the gate never needed a model |
| A target wedges the loop | per-iteration timeout (`iteration_timeout_s`, default 600s) | recorded as a timeout; the iteration is abandoned and the loop moves to the next target |
| A probe itself fails | the sample is wrapped | recorded as a health incident; the run continues |

The harness keeps a bounded timeline (the last 2,000 events) and a bounded incident log, so a
36-hour run does not become the memory leak it is hunting; every incident is still counted.

A restart you can see on the Mission Board is a feature. A silent hang is the thing that loses the
run — so every restart is a visible timeline event, and `survived` is false if any error occurred or
any cap was breached.

## The recording

Record the full 7-minute demo arc at a safe point before judging, on a target you control, and copy
it to **two devices**. It is the last rung of the fallback ladder: if the live demo dies, narrate
over the recording and lose almost nothing.

## Exit gate

- The **second** 36-hour run finishes with `survived == True` and no manual intervention.
- The recording plays on both backup devices without any software install.
- The CPU-only degraded profile has been run once and its numbers recorded (so the no-GPU path is
  known, not discovered live).

## What this container could and could not do

The harness, the watchdog, the caps and this runbook are built and unit-tested here. The 36-hour
execution, vLLM serving and the long sandboxed container run require the finale hardware and were
not run in the build container — that is the one honest gap, and it is what these two rehearsals
close.
