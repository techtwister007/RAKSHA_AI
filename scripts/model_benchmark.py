#!/usr/bin/env python3
"""Benchmark the model lane: the same mutation-factory variants, without and with a local model.

Development tool. Runs RAKSHA's own demo defects through `mutationfactory.generalisation_report`
twice — model-free, then with the model server at RAKSHA_INFERENCE_BASE_URL — and writes a table:
variants found, fixed through the five-check gate, which lane fixed each, model calls, tokens, and
wall time. The gate decides in both runs; the model can only add candidates.

    RAKSHA_INFERENCE_BASE_URL=http://127.0.0.1:8701/v1 RAKSHA_REPAIR_MODEL=qwen2.5-coder-7b \\
        python3 scripts/model_benchmark.py --out docs/model-benchmark.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from raksha import inference  # noqa: E402
from raksha.mutationfactory import generalisation_report, mutate_source  # noqa: E402

REPO = Path(__file__).parents[1]
SEEDS = [("c-nolibfuzzer", "src/tlv.c", "c/c++"), ("py-noharness", "converter.py", "python")]


def variants():
    out = []
    for target, rel, lang in SEEDS:
        out += mutate_source((REPO / "demo-targets" / target / rel).read_text(), lang, seed=0)
    return out


def run(use_model: bool) -> dict:
    inference.reset_counters()
    client = inference.get_client() if use_model else None
    t0 = time.monotonic()
    rep = generalisation_report(variants(), use_model=use_model, client=client, max_execs=30000)
    rep["seconds"] = round(time.monotonic() - t0, 1)
    rep["counters"] = inference.counters()
    return rep


def markdown(base: dict, model: dict, model_name: str) -> str:
    rows = {v["name"]: v for v in base["by_variant"]}
    L = ["# RAKSHA AI — model-lane benchmark", "",
         f"Model: `{model_name}` served locally (llama.cpp, 4 CPU threads, Q4 quantisation). Set: "
         f"{base['total']} bug-preserving variants of RAKSHA's own demo defects (mutation factory). "
         "The five-check gate decides in both runs; the model can only add repair candidates.", "",
         "| | model-free | with model |", "|---|---|---|",
         f"| variants found | {base['found']}/{base['total']} | {model['found']}/{model['total']} |",
         f"| fixed through the gate | {base['fixed']}/{base['total']} ({base['fix_rate_pct']}%) | "
         f"{model['fixed']}/{model['total']} ({model['fix_rate_pct']}%) |",
         f"| model calls | {base['counters']['inference_calls']} | {model['counters']['inference_calls']} |",
         f"| completion tokens | {base['counters']['completion_tokens']} | {model['counters']['completion_tokens']} |",
         f"| cloud (egress) calls | {base['counters']['egress_calls']} | {model['counters']['egress_calls']} |",
         f"| wall time (s) | {base['seconds']} | {model['seconds']} |", "",
         "## Per variant", "", "| variant | model-free | with model |", "|---|---|---|"]
    for v in model["by_variant"]:
        b = rows.get(v["name"], {})
        fmt = lambda r: ("fixed (" + (r.get("lane") or "?") + ")") if r.get("fixed") else (
            "found, not fixed" if r.get("found") else "not found")
        L.append(f"| {v['name']} | {fmt(b)} | {fmt(v)} |")
    L += ["", "Hardware note: a CPU-only 7B model is the floor, not the finale configuration (a ~32B "
          "model on the GPU). Re-run this script on the finale box to replace these numbers.", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    if not os.environ.get("RAKSHA_INFERENCE_BASE_URL"):
        print("set RAKSHA_INFERENCE_BASE_URL to the local model server first")
        return 2
    base = run(False)
    model = run(True)
    md = markdown(base, model, os.environ.get("RAKSHA_REPAIR_MODEL", "?"))
    if a.out:
        Path(a.out).write_text(md)
    if a.json:
        Path(a.json).write_text(json.dumps({"model_free": base, "with_model": model}, indent=2, default=str))
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
