"""Run profiles as data (W0-4).

Every threshold that was a scattered default — fuzzing budget, the reproducer-variant count, the
perf tolerance, patch-hygiene caps, the minimum behavioural-evidence floor, per-target and parallel
budgets, triage cut-offs — lives here, in three named profiles chosen by `RAKSHA_PROFILE`:

    datacenter  the finale node: generous budgets. Reproduces today's hard-coded numbers exactly.
    node        a single workstation: moderate budgets.
    edge        a constrained box: small budgets, so a demo finishes fast.

A `raksha.toml`/`raksha.json` at the repo root (or `RAKSHA_PROFILE_FILE`) can override any field,
so a deployment tunes without a code change. Stdlib only: TOML via `tomllib` (3.11+), JSON as a
fallback. Nothing here changes behaviour until a consumer reads it; Wave-1 items wire their own
knob to `profile.current().<field>` so `datacenter` is a no-op against the values they replace.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    name: str = "datacenter"
    # fuzzing
    autofuzz_max_execs: int = 20000          # harness.autofuzz default today
    fuzz_plateau_execs: int = 4000           # mutator max_execs_without_progress today
    per_target_budget_s: float = 900.0       # E3: a single target may not eat the whole run
    parallel_workers: int = 4                # E2: concurrent target ingest
    # the gate
    refuzz_seconds: float = 30.0             # run_gate default today
    repair_refuzz_seconds: float = 4.0       # autorepair default today
    pov_variants: int = 24                   # POV_VARIANTS today
    perf_tolerance: float = 5.0              # run_gate perf gate today
    min_stable_inputs: int = 3               # A2: minimum-evidence floor (0 = off, today's behaviour)
    max_repair_rounds: int = 3               # MAX_REPAIR_ROUNDS today
    # patch hygiene
    hygiene_max_added_lines: int = 150       # hygiene.MAX_ADDED_LINES today
    # red team
    red_rounds: int = 200                    # redteam.red_round default
    red_seconds: float = 4.0
    # triage funnel cut-offs (stage min-score)
    triage_worth_deeper: float = 0.35
    triage_top: float = 0.5


#: The three presets. `datacenter` must equal the numbers the code used before this module existed.
_PRESETS: dict[str, Profile] = {
    "datacenter": Profile(name="datacenter"),
    "node": Profile(name="node", autofuzz_max_execs=12000, fuzz_plateau_execs=2500,
                    per_target_budget_s=420.0, parallel_workers=2, refuzz_seconds=15.0,
                    repair_refuzz_seconds=3.0, pov_variants=16, red_rounds=120),
    "edge": Profile(name="edge", autofuzz_max_execs=5000, fuzz_plateau_execs=1200,
                    per_target_budget_s=180.0, parallel_workers=1, refuzz_seconds=6.0,
                    repair_refuzz_seconds=2.0, pov_variants=10, red_rounds=60,
                    min_stable_inputs=2),
}

_CACHE: Profile | None = None


def _overrides(env: dict) -> dict:
    path = env.get("RAKSHA_PROFILE_FILE")
    candidates = [Path(path)] if path else [Path("raksha.toml"), Path("raksha.json")]
    for p in candidates:
        if not p.is_file():
            continue
        try:
            if p.suffix == ".toml":
                import tomllib
                data = tomllib.loads(p.read_text())
            else:
                data = json.loads(p.read_text())
        except (OSError, ValueError) as e:  # a malformed file must not take the system down
            import sys
            print(f"raksha: ignoring {p} ({e})", file=sys.stderr)
            return {}
        known = {f.name for f in fields(Profile)}
        return {k: v for k, v in data.items() if k in known}
    return {}


def current(env: dict | None = None) -> Profile:
    """The active profile: a preset chosen by `RAKSHA_PROFILE` (default datacenter), with any
    `raksha.toml`/`raksha.json` field overrides applied. Cached; call `reset()` after changing env."""
    global _CACHE
    if _CACHE is not None and env is None:
        return _CACHE
    e = env if env is not None else os.environ
    base = _PRESETS.get(e.get("RAKSHA_PROFILE", "datacenter").strip().lower(), _PRESETS["datacenter"])
    ov = _overrides(e)
    prof = replace(base, **ov) if ov else base
    if env is None:
        _CACHE = prof
    return prof


def reset() -> None:
    global _CACHE
    _CACHE = None


def as_dict(env: dict | None = None) -> dict:
    return asdict(current(env))
