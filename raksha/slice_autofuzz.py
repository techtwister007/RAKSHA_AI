"""Phase: automatic harness generation — `python -m raksha.slice_autofuzz`

The headline for the fix score: a target that ships NO fuzz harness is driven find -> fix -> prove
with no human writing a driver. RAKSHA discovers the entry point, synthesizes a harness, fuzzes it,
confirms the crash, and runs the repair ladder through the five-check gate. Two bundled no-harness
targets (a C TLV parser, a Python shell-out helper) in two languages, one pipeline.

Model-free by default (templates + the gcc/python toolchain); set RAKSHA_INFERENCE_BASE_URL to let
the model lane propose patches too — the gate decides either way.
"""

from __future__ import annotations

import pathlib
import sys

from .autorepair import repair
from .finding import Status
from .harness import autofuzz

ROOT = pathlib.Path(__file__).parents[1]
G, A, R, B, D, O = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"

#: (directory, a small benign corpus for the differential check)
TARGETS = [
    ("c-nolibfuzzer", [b"\x01\x04abcd", b"\x02hello", b"\x01\x02ab", b""]),
    ("py-noharness", [b"10 m to ft", b"5 kg to lb", b"warm", b"status"]),
]


def run_one(name: str, corpus: list[bytes]) -> Status | None:
    root = ROOT / "demo-targets" / name
    if not root.exists():
        return None
    print(f"  {B}{name}{O} {D}(no hand-written harness){O}")
    r = autofuzz(root, max_execs=60000)
    if not r.found:
        print(f"    {A}no crash found: {r.note}{O}\n")
        return None
    f = r.finding
    print(f"    synthesized a harness for {B}{r.entrypoint.symbol}{O} → "
          f"{f.bug_class} at {f.fix_site_set[0].uri}:{f.fix_site_set[0].start_line} {G}CONFIRMED{O}")
    out = repair(f, r.target, root=r.target.source_root, reproducer=r.crashing_input, corpus=corpus)
    if out.verified:
        print(f"    fix proven through the five-check gate via the {B}{out.lane.value}{O} lane "
              f"{G}VERIFIED{O}\n")
    else:
        print(f"    gate refused every candidate → {A}{out.status.value}{O} (proven report, no guess)\n")
    if hasattr(r.target, "discard"):
        try:
            r.target.discard(r.target.build(None))
        except Exception:  # noqa: BLE001
            pass
    return out.status


def run() -> int:
    print(f"\n{B}RAKSHA AI — automatic harness generation{O}")
    print(f"{D}no harness written by hand — discover → synthesize → fuzz → fix → prove{O}\n")
    results = [s for s in (run_one(n, c) for n, c in TARGETS) if s is not None]
    verified = sum(1 for s in results if s is Status.VERIFIED)
    print(f"{B}{verified}/{len(results)} verified{O} from synthesized harnesses, "
          f"{D}no hand-written driver{O}\n")
    return 0 if results and verified == len(results) else 2


if __name__ == "__main__":
    sys.exit(run())
