"""Rust deep lane — `python -m raksha.slice_rust`

A Rust crate that ships no fuzz harness, driven find → fix → prove with stable `cargo test` as the
runner and RAKSHA's own mutation as the engine (no cargo-fuzz / nightly / network). RAKSHA discovers
the entry point, synthesizes a cargo-test harness, finds the runtime panic, clamps the slice, and
proves the fix through the same five-check gate as C, Go, Java and Python. Offline
(CARGO_NET_OFFLINE, crate-local CARGO_HOME). Skips cleanly if the Rust toolchain is absent.
"""

from __future__ import annotations

import pathlib
import shutil
import sys

from .adapters.rust_fuzz import rust_autofuzz, rust_bound_index
from .finding import RepairLane, Status
from .gate.runner import decide, run_gate
from .oracles.rust_panic import RustPanicOracle

ROOT = pathlib.Path(__file__).parents[1]
G, A, B, D, O = "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"


def run() -> int:
    print(f"\n{B}RAKSHA AI — Rust deep lane (cargo test as the engine, no hand-written harness){O}\n")
    if shutil.which("cargo") is None:
        print(f"  {A}cargo toolchain not available — skipping{O}\n")
        return 0
    root = ROOT / "demo-targets" / "rust-nolibfuzzer"
    r = rust_autofuzz(root, fuzztime_s=10)
    if not r.found:
        print(f"  {A}no panic found: {r.note}{O}\n")
        return 2
    f = r.finding
    site = f.fix_site_set[0]
    print(f"  synthesized a cargo-test harness for {B}{r.entrypoint.symbol}{O} → {f.bug_class} at "
          f"{site.uri}:{site.start_line} {G}CONFIRMED{O}")

    diff = rust_bound_index(f, root)
    if not diff:
        print(f"  {A}template produced no diff — cannot bound the slice{O}\n")
        return 2
    f.mark_patched(diff, RepairLane.TEMPLATE)
    verdict = run_gate(f, r.target, reproducer=r.crashing_input,
                       corpus=[b"\x01\x01\x05", b"\x02ab", b"\x00", b""],
                       oracles=(RustPanicOracle(),), refuzz_seconds=5)
    status = decide(f, verdict)
    if status is Status.VERIFIED:
        print(f"  fix proven through the five-check gate via the {B}{RepairLane.TEMPLATE.value}{O} "
              f"lane {G}VERIFIED{O}\n")
    else:
        why = verdict.failed_check.value if verdict.failed_check else "?"
        print(f"  gate refused the candidate ({why}: {verdict.detail}) → {A}{status.value}{O}\n")
    return 0 if status is Status.VERIFIED else 2


if __name__ == "__main__":
    sys.exit(run())
