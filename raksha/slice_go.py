"""Go deep lane — `python -m raksha.slice_go`

A Go target that ships no fuzz harness, driven find → fix → prove with native `go test -fuzz`.
RAKSHA discovers the entry point, synthesizes a Go fuzz test, finds the runtime panic, bounds the
slice, and proves the fix through the same five-check gate as C, Java and Python. Offline (stdlib
module, GOPROXY=off). Skips cleanly if the Go toolchain is absent.
"""

from __future__ import annotations

import pathlib
import shutil
import sys

from .adapters.go_fuzz import go_autofuzz
from .autorepair import repair
from .finding import Status

ROOT = pathlib.Path(__file__).parents[1]
G, A, B, D, O = "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"


def run() -> int:
    print(f"\n{B}RAKSHA AI — Go deep lane (native fuzzing, no hand-written harness){O}\n")
    if shutil.which("go") is None:
        print(f"  {A}go toolchain not available — skipping{O}\n")
        return 0
    root = ROOT / "demo-targets" / "go-decoder"
    r = go_autofuzz(root, fuzztime_s=10)
    if not r.found:
        print(f"  {A}no panic found: {r.note}{O}\n")
        return 2
    f = r.finding
    print(f"  synthesized a Go fuzz test for {B}{r.entrypoint.symbol}{O} → {f.bug_class} at "
          f"{f.fix_site_set[0].uri}:{f.fix_site_set[0].start_line} {G}CONFIRMED{O}")
    out = repair(f, r.target, root=root, reproducer=r.crashing_input,
                 corpus=[b"\x02ab", b"\x00", b"\x01z", b""], refuzz_seconds=5)
    if out.verified:
        print(f"  fix proven through the five-check gate via the {B}{out.lane.value}{O} lane {G}VERIFIED{O}\n")
    else:
        print(f"  gate refused every candidate → {A}{out.status.value}{O}\n")
    return 0 if out.status is Status.VERIFIED else 2


if __name__ == "__main__":
    sys.exit(run())
