"""G6 — calibrate the evidence-fusion reliabilities (and the attack-graph step costs) on labelled data.

The fusion kernel (`raksha/evidence.py`) turns evidence channels into a confidence with a noisy-OR
over per-channel *reliabilities*: how often a channel firing means a real defect. Those started as
hand-picked numbers. This module measures them.

Corpus (labelled by construction, `raksha/data/groundtruth.json`): every defect planted in
`demo-targets/`, the deliberately safe sister code, and the benchmark's negative controls. Each
channel's firings on that corpus are labelled true or false positive by file and CWE family.

Estimate: the hand value is kept as a weak Beta prior worth ``PRIOR_STRENGTH`` observations, and the
posterior mean ``(k*prior + TP) / (k + n)`` is the calibrated reliability; the Wilson 95% interval of
the raw observed precision is reported beside it. So a handful of observations moves the number a
little and says how uncertain it still is, and a channel with no data stays at its prior, marked
``uncalibrated``. The bands table checks the result end to end: for every labelled observation,
the fused confidence's band against the precision actually observed in that band.

The corpus is small and curated, and the table says so. It is a measured baseline, not a population
estimate; adding ARVO / real-estate labels changes the inputs, not this code.

    python -m raksha.calibrate            # build-free + structural + the fast deep lanes
    python -m raksha.calibrate --deep     # also the Go and Rust lanes (slower)
"""

from __future__ import annotations

import json
import math
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
DEMO = ROOT / "demo-targets"
GROUND_TRUTH = Path(__file__).parent / "data" / "groundtruth.json"
OUT = Path(__file__).parent / "data" / "calibration.json"
PRIOR_STRENGTH = 4.0
BANDS = (("low", 0.0, 0.6), ("moderate", 0.6, 0.85), ("proven", 0.85, 1.0001))


# ---------------------------------------------------------------- labels

@dataclass
class Truth:
    defects: dict[str, set[str]]
    clean: set[str]

    def label(self, rel: str, cwe: str | None) -> bool:
        """True positive iff `rel` is a planted defect's file and the CWE is in its family."""
        from .cwe import family
        rel = rel.lstrip("./")
        fams = self.defects.get(rel)
        if fams is None or rel in self.clean:
            return False
        return "any" in fams or (family(cwe) in fams)


def load_truth(path: Path = GROUND_TRUTH) -> Truth:
    d = json.loads(path.read_text())
    return Truth({e["file"]: set(e["families"]) for e in d["defects"]}, set(d.get("clean", [])))


@dataclass
class Observations:
    by_channel: dict[str, list[bool]] = field(default_factory=dict)
    samples: list[tuple[frozenset, bool]] = field(default_factory=list)   # (channels present, truth)
    notes: list[str] = field(default_factory=list)

    def add(self, channels: set[str], truth: bool) -> None:
        for c in channels:
            self.by_channel.setdefault(c, []).append(truth)
        self.samples.append((frozenset(channels), truth))


# ---------------------------------------------------------------- collection

def _structural(obs: Observations, truth: Truth) -> list:
    from .lanes.structure import scan_structure
    paths = scan_structure(DEMO).paths
    for p in paths:
        obs.add({"structural"}, truth.label(p.file, p.cwe))
    return paths


def _deterministic(obs: Observations, truth: Truth) -> None:
    from .benchmark import NEGATIVE_CONTROLS
    from .lanes.buildfree import scan_target
    for top in ("mixed-estate", "fleet"):
        for f in scan_target(DEMO / top).findings:
            if f.oracle.startswith("cpg:"):
                continue
            obs.add({"deterministic"}, truth.label(f"{top}/{f.target}", f.bug_class))
    with tempfile.TemporaryDirectory() as d:
        for rel, text in NEGATIVE_CONTROLS.items():
            (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(d) / rel).write_text(text)
        neg = scan_target(Path(d)).findings
        for _ in neg:
            obs.add({"deterministic"}, False)
        obs.notes.append(f"{len(NEGATIVE_CONTROLS)} negative-control files scanned; {len(neg)} finding(s) on them")


def _exploit(obs: Observations, truth: Truth, paths: list, deep: bool) -> None:
    from .cwe import same_family
    from .orchestrator import _dispatch_autofuzz
    demos = ["c-nolibfuzzer", "py-noharness", "js-noharness", "java-noharness"]
    if deep:
        demos += ["go-decoder", "rust-nolibfuzzer"]
    for name in demos:
        try:
            r = _dispatch_autofuzz(DEMO / name)
        except Exception as e:  # noqa: BLE001 — a lane whose toolchain is absent contributes nothing
            obs.notes.append(f"{name}: lane did not run ({type(e).__name__})")
            continue
        if not getattr(r, "found", False):
            obs.notes.append(f"{name}: no confirmed exploit ({getattr(r, 'note', '')[:60]})")
            continue
        f = r.finding
        site = f.fix_site_set[0].uri if f.fix_site_set else f.target
        ok = truth.label(f"{name}/{site}", f.bug_class)
        chans = {"exploit"}
        if any(p.file == f"{name}/{site}" and same_family(p.cwe, f.bug_class) for p in paths):
            chans.add("crossconfirm")            # the static path and the reproducer agree
            chans.add("structural")
        obs.add(chans, ok)
        if hasattr(r, "cleanup"):
            try:
                r.cleanup()
            except Exception:  # noqa: BLE001
                pass


def collect(deep: bool = False) -> Observations:
    truth = load_truth()
    obs = Observations()
    paths = _structural(obs, truth)
    _deterministic(obs, truth)
    _exploit(obs, truth, paths, deep)
    return obs


# ---------------------------------------------------------------- estimation

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | tuple[None, None]:
    if n == 0:
        return None, None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)


def estimate(obs: Observations) -> dict:
    from .evidence import _PRIOR_RELIABILITY
    channels = {}
    for name, prior in _PRIOR_RELIABILITY.items():
        xs = obs.by_channel.get(name, [])
        n, tp = len(xs), sum(xs)
        lo, hi = wilson(tp, n)
        post = (PRIOR_STRENGTH * prior + tp) / (PRIOR_STRENGTH + n)
        channels[name] = {"prior": prior, "n": n, "true_positives": tp, "false_positives": n - tp,
                          "observed_precision": round(tp / n, 3) if n else None,
                          "wilson95": [lo, hi], "calibrated": round(post, 3) if n else prior,
                          "status": "calibrated" if n else "uncalibrated: no labelled observations"}
    return channels


def bands(obs: Observations, reliability: dict[str, float]) -> list[dict]:
    from .evidence import fuse_channels
    rows = []
    for name, lo, hi in BANDS:
        xs = [t for chans, t in obs.samples
              if lo <= fuse_channels({c: reliability[c] for c in chans})[0] < hi]
        k, n = sum(xs), len(xs)
        rows.append({"band": name, "range": [lo, min(hi, 1.0)], "n": n, "true_positives": k,
                     "observed_precision": round(k / n, 3) if n else None, "wilson95": list(wilson(k, n))})
    return rows


def run(deep: bool = False, out: Path = OUT) -> dict:
    obs = collect(deep)
    table = estimate(obs)
    rel = {c: v["calibrated"] for c, v in table.items()}
    result = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "corpus": "demo-targets/ (planted defects + safe sister code, raksha/data/groundtruth.json) and "
                  "the benchmark's negative controls" + ("; deep lanes incl. Go and Rust" if deep else ""),
        "method": f"Beta prior at the hand value worth {PRIOR_STRENGTH:g} observations; posterior mean "
                  "reported as 'calibrated'; Wilson 95% interval on the raw observed precision",
        "caveat": "small curated corpus: a reproducible measured baseline, not a population estimate",
        "channels": table,
        "in_sample": {"structural": "its rules were corrected on this corpus (string literals, sized "
                                    "allocations), so its observed precision here is in-sample"},
        "attack_graph": {
            "exploit_step": {"cost": 1.0, "basis": "reference unit"},
            "dependency_step": {"cost": "1.0 if CISA-KEV-listed, else 1 + (1 - EPSS); 1.5 without data",
                                "basis": "measured: offline KEV and FIRST EPSS snapshots (raksha/data)"},
            "unknown_reachability": {"cost": 2.0, "basis": "prior: no labelled exploitation-effort data"},
            "not_imported": {"cost": 4.0, "basis": "prior: no labelled exploitation-effort data"},
        },
        "bands": bands(obs, rel),
        "notes": obs.notes,
    }
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    res = run(deep="--deep" in argv)
    print(f"{'channel':14} {'prior':>6} {'n':>4} {'TP':>4} {'FP':>4} {'observed':>9} {'wilson95':>15} {'calibrated':>11}")
    for name, v in res["channels"].items():
        w = v["wilson95"]
        ws = f"[{w[0]}, {w[1]}]" if w[0] is not None else "-"
        obs = v["observed_precision"] if v["observed_precision"] is not None else "-"
        print(f"{name:14} {v['prior']:>6} {v['n']:>4} {v['true_positives']:>4} {v['false_positives']:>4} "
              f"{obs!s:>9} {ws:>15} {v['calibrated']:>11}")
    print("bands:", [(b["band"], b["n"], b["observed_precision"]) for b in res["bands"]])
    for n in res["notes"]:
        print("note:", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
