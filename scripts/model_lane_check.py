#!/usr/bin/env python3
"""Check the model lane end to end with a known-good and a known-bad "model".

The fix templates are switched off, so every fix must come from the model lane. The "model" is a
stand-in client that returns answers written in advance for the eight mutation-factory variants
(`scripts/model_lane_answers/`): `good` holds correct fixes written the way a capable model writes
them (edit blocks, trailing comments dropped); `bad` holds plausible wrong ones (a bound that is too
loose, a blocklist, shell quoting, eval). The pipeline passes this check when the five-check gate
accepts every good fix and none of the bad ones:

    python3 scripts/model_lane_check.py            # expect: good 8/8 fixed, bad 0/8 fixed

It needs no model server and no network. To check a real model instead, use model_benchmark.py.
"""

from __future__ import annotations

import hashlib
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
sys.path.insert(0, str(Path(__file__).parent))

from raksha import autorepair, inference  # noqa: E402

ANSWERS = Path(__file__).parent / "model_lane_answers"


class _Config:
    guided = "off"

    def model_for(self, role):
        return "stand-in"


class AnswerClient:
    """Duck-types InferenceClient: looks up the answer for the source shown in the prompt."""

    def __init__(self, kind: str) -> None:
        self.dir = ANSWERS / kind
        self.config = _Config()
        self.calls = 0

    def complete(self, messages, *, role=None, n=1, temperature=0.2, **_kw):
        self.calls += 1
        u = messages[-1]["content"]
        m = re.search(r"<<<UNTRUSTED SOURCE.*?>>>END UNTRUSTED SOURCE", u, re.S)
        key = hashlib.sha256((m.group(0) if m else u).encode()).hexdigest()[:12]
        f = self.dir / f"{key}.txt"
        return [f.read_text()] if f.exists() else [""]


def run(kind: str) -> dict:
    import model_benchmark as mb
    from raksha.mutationfactory import generalisation_report
    client = AnswerClient(kind)
    t0 = time.monotonic()
    rep = generalisation_report(mb.variants(), use_model=True, client=client, max_execs=30000)
    rep["seconds"] = round(time.monotonic() - t0, 1)
    rep["calls"] = client.calls
    return rep


def main() -> int:
    autorepair.generic_templates = lambda finding, root: []      # model lane only
    inference.reset_counters()
    good, bad = run("good"), run("bad")
    for name, rep in (("good", good), ("bad", bad)):
        lanes = sorted({v["lane"] for v in rep["by_variant"] if v["lane"]})
        print(f"{name:5} found {rep['found']}/{rep['total']}  fixed {rep['fixed']}/{rep['total']}  "
              f"lanes {lanes or '-'}  model calls {rep['calls']}  {rep['seconds']} s")
    ok = good["fixed"] == good["total"] and bad["fixed"] == 0
    print("PASS: the gate accepts correct model fixes and rejects wrong ones" if ok else
          "FAIL: see the per-variant notes above")
    if not ok:
        for name, rep in (("good", good), ("bad", bad)):
            for v in rep["by_variant"]:
                print(f"  {name} {v['name']}: fixed={v['fixed']} lane={v['lane']} {v['note']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
