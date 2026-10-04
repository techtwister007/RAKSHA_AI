"""Phase: the JavaScript deep lane — `python -m raksha.slice_js`

The JavaScript mirror of `slice_autofuzz`'s Python path: a Node target that ships NO fuzz harness is
driven find -> fix -> prove with no human writing a driver. RAKSHA discovers the entry point, wires
the `jssinkguard` sink-oracle preload as the harness, fuzzes it, confirms the command injection,
rewrites the shell sink to a non-shell argument vector (`js_shell_safe`), and proves the fix through
the same five-check gate every other finding goes through.

Node built-ins only, offline, deterministic. Skips cleanly when `node` is not on the box.
"""

from __future__ import annotations

import pathlib
import shutil
import sys

from .adapters.js_sink import js_autofuzz, js_shell_safe
from .finding import RepairLane, Status
from .gate.runner import decide, run_gate
from .oracles.js_sink import JsSinkOracle

ROOT = pathlib.Path(__file__).parents[1]
G, A, R, B, D, O = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"

#: (directory, a small benign corpus for the differential check — none of these inject)
TARGETS = [
    ("js-noharness", [b"10m", b"5 kg", b"warm", b"status"]),
]


def run_one(name: str, corpus: list[bytes]) -> Status | None:
    root = ROOT / "demo-targets" / name
    if not root.exists():
        return None
    print(f"  {B}{name}{O} {D}(no hand-written harness){O}")
    r = js_autofuzz(root, max_execs=6000)
    if not r.found:
        print(f"    {A}no crash found: {r.note}{O}\n")
        return None
    f = r.finding
    print(f"    synthesized the jssinkguard harness for {B}{r.entrypoint.symbol}{O} → "
          f"{f.bug_class} at {f.fix_site_set[0].uri}:{f.fix_site_set[0].start_line} {G}CONFIRMED{O}")

    diff = js_shell_safe(f, r.target.source_root)
    if not diff:
        print(f"    {A}no template fix produced{O}\n")
        return None
    f.mark_patched(diff, RepairLane.TEMPLATE)
    verdict = run_gate(f, r.target, reproducer=r.crashing_input, corpus=corpus,
                       refuzz_seconds=4.0, oracles=(JsSinkOracle(),))
    status = decide(f, verdict)
    if status is Status.VERIFIED:
        print(f"    fix proven through the five-check gate via the {B}{f.repair_lane.value}{O} lane "
              f"{G}VERIFIED{O}\n")
    else:
        print(f"    gate refused the candidate → {A}{status.value}{O} "
              f"({verdict.failed_check.value if verdict.failed_check else '?'}: {verdict.detail}){O}\n")
    return status


def run() -> int:
    print(f"\n{B}RAKSHA AI — JavaScript deep lane (no hand-written harness){O}")
    print(f"{D}discover → jssinkguard harness → fuzz → fix → prove{O}\n")
    if shutil.which("node") is None:
        print(f"{A}node not found — skipping the JavaScript lane{O}\n")
        return 0
    results = [s for s in (run_one(n, c) for n, c in TARGETS) if s is not None]
    verified = sum(1 for s in results if s is Status.VERIFIED)
    print(f"{B}{verified}/{len(results)} verified{O} from the jssinkguard harness, "
          f"{D}no hand-written driver{O}\n")
    return 0 if results and verified == len(results) else 2


if __name__ == "__main__":
    sys.exit(run())
