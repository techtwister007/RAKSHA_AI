"""J5 — the recall answer: measure it, rather than only declining to claim it.

Recall is the share of real defects a system finds. On an open corpus it is unknowable (you cannot
divide by bugs no one has catalogued), which is why the benchmark report declines a population-level
recall claim. But there are two sets where the denominator IS known, and on those recall can be
measured honestly:

  MUTATION FACTORY   every bug-preserving variant of a known demo defect (renamed identifiers,
                     equivalent APIs, reordered context) is, by construction, a real instance of
                     that defect. Recall = variants found / variants generated. (The repair rate on
                     the same variants is the generalise-or-memorise number; recall is the find half.)
  DEMO GROUND TRUTH  the planted defects in demo-targets/ whose family a fuzzing lane can reach
                     (memory / injection — the oracles RAKSHA ships). Recall = reached-and-found /
                     reachable-planted. Defect families with no runtime oracle (a weak-crypto
                     config, an unpinned dependency) are listed as out-of-scope-for-fuzzing, not
                     counted as misses, because a different lane (build-free) owns them.

Every number is measured by running the real lanes; a miss is named. ``--method`` prints how each
figure was computed. ``python -m raksha.recall --report``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

REPO = Path(__file__).parents[1]
DEMO = REPO / "demo-targets"

#: Families a shipped fuzzing oracle can reach (ASan memory, the Python/JS injection sinks). Others
#: are build-free lane territory and are not counted against fuzzing recall.
_FUZZABLE_FAMILIES = {"memory", "injection"}
#: demo target -> (vulnerable source relative to the target, language) for the mutation set.
_MUTATION_SEEDS = [
    ("c-nolibfuzzer", "src/tlv.c", "c/c++"),
    ("py-noharness", "converter.py", "python"),
]


def mutation_recall(*, seed: int = 0, max_execs: int = 40000) -> dict:
    """Recall over every bug-preserving mutation of the seed defects: found / generated."""
    from .mutationfactory import generalisation_report, mutate_source
    variants = []
    for target, rel, lang in _MUTATION_SEEDS:
        src = (DEMO / target / rel).read_text()
        for v in mutate_source(src, lang, seed=seed):
            variants.append(v)
    rep = generalisation_report(variants, use_model=False, max_execs=max_execs)
    found = rep["found"]
    total = rep["total"]
    misses = [p["name"] for p in rep["by_variant"] if not p["found"]]
    return {"set": "mutation factory", "denominator": total, "found": found,
            "recall_pct": round(100.0 * found / total, 1) if total else None,
            "misses": misses,
            "also_fixed": rep["fixed"], "fix_rate_pct": rep["fix_rate_pct"],
            "method": "every variant is a bug-preserving rewrite of a known defect, so the "
                      "denominator is exact; recall = variants whose crash RAKSHA reproduced / variants"}


def groundtruth_recall(*, max_execs: int = 40000) -> dict:
    """Recall over the planted demo defects whose family a fuzzing oracle can reach."""
    from .harness.autofuzz import autofuzz
    g = json.loads((REPO / "raksha" / "data" / "groundtruth.json").read_text())
    reachable = [d for d in g["defects"]
                 if set(d.get("families", [])) & _FUZZABLE_FAMILIES
                 and (DEMO / d["file"].split("/")[0]).is_dir()]
    # one target per defect file; the file's top directory is the ingestable target
    seeds = {"memory": [b"\x01\xff" + b"A" * 48, b"\x01\x04abcd"],
             "injection": [b"x; touch pwn", b"a | id", b"10 m to ft"]}
    found, misses, scoped = 0, [], []
    for d in reachable:
        target = d["file"].split("/")[0]
        if target in scoped:
            continue
        scoped.append(target)
        fam = next(iter(set(d["families"]) & _FUZZABLE_FAMILIES))
        try:
            r = autofuzz(DEMO / target, use_model=False, seed_corpus=seeds[fam], max_execs=max_execs)
        except Exception:  # noqa: BLE001
            r = None
        if r is not None and r.found and r.finding.is_reportable:
            found += 1
        else:
            misses.append(target)
    return {"set": "demo ground truth (fuzzable families)", "denominator": len(scoped),
            "found": found, "recall_pct": round(100.0 * found / len(scoped), 1) if scoped else None,
            "misses": misses,
            "out_of_scope_for_fuzzing": sorted({d["file"] for d in g["defects"]
                                                if not (set(d.get("families", [])) & _FUZZABLE_FAMILIES)}),
            "method": "planted defects whose family a shipped runtime oracle can reach; recall = "
                      "targets where the synthesized-harness lane reproduced the planted crash / such targets"}


def measure(*, max_execs: int = 40000) -> dict:
    t0 = time.monotonic()
    out = {"mutation": mutation_recall(max_execs=max_execs),
           "groundtruth": groundtruth_recall(max_execs=max_execs)}
    out["seconds"] = round(time.monotonic() - t0, 1)
    return out


def markdown(r: dict, *, method: bool = False) -> str:
    L = ["# RAKSHA AI — recall (J5)", "",
         "Recall where the denominator is knowable. On an open corpus recall is undefined (no "
         "catalogue of all real bugs to divide by); these two sets have an exact denominator.", ""]
    for key in ("mutation", "groundtruth"):
        s = r[key]
        L += [f"## {s['set']}", "",
              f"- recall: **{s['recall_pct']}%** ({s['found']} / {s['denominator']})"]
        if s.get("misses"):
            L.append(f"- misses: {', '.join(s['misses'])}")
        if "also_fixed" in s:
            L.append(f"- of those found, fixed through the gate: {s['also_fixed']} "
                     f"({s['fix_rate_pct']}% of variants)")
        if s.get("out_of_scope_for_fuzzing"):
            L.append(f"- out of scope for fuzzing (build-free lane owns these): "
                     f"{', '.join(s['out_of_scope_for_fuzzing'])}")
        if method:
            L.append(f"- method: {s['method']}")
        L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m raksha.recall")
    ap.add_argument("--out"); ap.add_argument("--report", action="store_true")
    ap.add_argument("--method", action="store_true"); ap.add_argument("--max-execs", type=int, default=40000)
    a = ap.parse_args(argv)
    r = measure(max_execs=a.max_execs)
    if a.out:
        Path(a.out).write_text(json.dumps(r, indent=2))
    print(markdown(r, method=a.method) if a.report else json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
