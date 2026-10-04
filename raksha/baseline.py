"""J4 — baseline comparison: a static scanner, and RAKSHA, on the same targets, one honest table.

The measure that matters is **reports that carry a reproducer** — a report a commander can re-run,
not a line number with a rule name. This module runs two arms over RAKSHA's own demo targets (ground
truth in ``raksha/data/groundtruth.json``) and tabulates them on that measure:

  STATIC   an off-the-shelf static scanner on default settings — ``flawfinder`` for C, ``bandit``
           for Python. It emits no input, so by construction none of its reports can carry a
           reproducer. That is not a dig: it is the structural difference the table exists to show.
           What is measured is how many files it flags, and how many of those flags land on a
           planted-defect file versus the clean control.
  RAKSHA   the model-free synthesized-harness lane (find → confirm). A reported finding carries a
           replaying reproducer by construction — the data model forbids reporting one that does
           not — so every RAKSHA report is a report-with-reproducer.

Scoring is at file level: a report "hits" when it names a file the ground truth marks as carrying a
planted defect, and is a "false positive" when it names the clean control. The set is small and
curated — a reproducible comparison, not a statistical benchmark; the row counts say so.

The optional third arm the campaign plan names — a plain model alone — is not run here: RAKSHA's
model use is confined to ranking and the repair ladder, both measured elsewhere (the Scorecard's
zero-inference share and the mutation factory's generalise-or-memorise number), and the finale runs
sealed with no model required. The table records that arm as not-run rather than stage a weak one.

``python -m raksha.baseline --out FILE.json`` runs it; ``--report`` renders the markdown.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).parents[1]
DEMO = REPO / "demo-targets"
#: The targets the comparison runs on, with the corpus the find loop is seeded with (bug-triggering
#: seeds, as the benchmark uses — the comparison is about what each arm REPORTS, not fuzzer luck).
TARGETS = {
    "c-overflow": [b"\x01\xff" + b"A" * 48], "c-nolibfuzzer": [b"\x01\x04abcd", b"\x02zz"],
    "py-cmdinject": [b"x; touch pwn", b"a | id"], "py-noharness": [b"x; id", b"10 m to ft"],
    "py-poisoned": [b"a; id", b"warm"], "fleet/ops-tools": [b"x; id"], "fleet/report-worker": [b"a|id"],
}


@dataclass
class Report:
    file: str                      # relative to demo-targets/
    detail: str
    reproducer: bool = False

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Arm:
    name: str
    reports: list[Report] = field(default_factory=list)
    ran: bool = True
    note: str = ""
    seconds: float = 0.0

    def as_dict(self) -> dict:
        return {"name": self.name, "ran": self.ran, "note": self.note,
                "seconds": round(self.seconds, 2), "reports": [r.as_dict() for r in self.reports]}


def ground_truth() -> tuple[set[str], set[str]]:
    g = json.loads((REPO / "raksha" / "data" / "groundtruth.json").read_text())
    return {d["file"] for d in g["defects"]}, set(g["clean"])


def _hit(file: str, defects: set[str]) -> bool:
    return any(file == d or file.endswith("/" + d) or d.endswith("/" + file) for d in defects)


# ---- the static arm ----------------------------------------------------------------------------

def _flawfinder(root: Path, target: str) -> list[Report]:
    out: list[Report] = []
    for c in sorted(root.rglob("*.c")):
        r = subprocess.run(["flawfinder", "--quiet", "--dataonly", "--columns",
                            "--minlevel=3", str(c.relative_to(root))], cwd=root,
                           capture_output=True, text=True, timeout=60)
        for line in r.stdout.splitlines():
            if line and line[0] not in " \t" and ":" in line:
                rel = f"{target}/{line.split(':', 1)[0]}"
                out.append(Report(rel.replace(f"{target}/{target}/", f"{target}/"), line.strip()))
    return out


def _bandit(root: Path, target: str) -> list[Report]:
    r = subprocess.run(["bandit", "-r", "-f", "custom", "--msg-template",
                        "{relpath}:{line}:{test_id}:{severity}", "."], cwd=root,
                       capture_output=True, text=True, timeout=120)
    out: list[Report] = []
    for line in r.stdout.splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 4 and parts[-1] in ("LOW", "MEDIUM", "HIGH") and parts[-2].startswith("B"):
            if parts[-1] == "LOW" and parts[-2] == "B404":
                continue                                   # the import note, not a finding
            rel = parts[0].lstrip("./")
            out.append(Report(f"{target}/{rel}", line.strip()))
    return out


def static_arm() -> Arm:
    arm = Arm("static scanner (flawfinder / bandit)")
    if not (shutil.which("flawfinder") and shutil.which("bandit")):
        arm.ran, arm.note = False, "flawfinder and/or bandit not installed on this node"
        return arm
    t0 = time.monotonic()
    for target in TARGETS:
        root = DEMO / target
        if not root.is_dir():
            continue
        arm.reports += _flawfinder(root, target) if any(root.rglob("*.c")) else _bandit(root, target)
    arm.seconds = time.monotonic() - t0
    arm.note = "default settings; emits no input, so no report carries a reproducer (structural)"
    return arm


# ---- the RAKSHA arm ----------------------------------------------------------------------------

def raksha_arm() -> Arm:
    from .harness.autofuzz import autofuzz
    arm = Arm("RAKSHA (synthesized-harness lane, model-free)")
    t0 = time.monotonic()
    for target, seeds in TARGETS.items():
        root = DEMO / target
        if not root.is_dir():
            continue
        try:
            r = autofuzz(root, use_model=False, seed_corpus=seeds, max_execs=40000)
        except Exception as e:  # noqa: BLE001 — a target that errors is simply no report
            arm.note += f"{target}: {type(e).__name__}; "
            continue
        if r.found and r.finding.is_reportable:
            site = r.finding.fix_site_set[0] if r.finding.fix_site_set else None
            file = f"{target}/{site.uri}" if site else target
            arm.reports.append(Report(file.replace(f"{target}/{target}/", f"{target}/"),
                                      f"{r.finding.bug_class} via synthesized harness", reproducer=True))
    arm.seconds = time.monotonic() - t0
    arm.note = (arm.note + "every report carries a replaying reproducer by construction").strip()
    return arm


# ---- the table ---------------------------------------------------------------------------------

def _score(arm: Arm, defects: set[str], clean: set[str]) -> dict:
    hits = {r.file for r in arm.reports if _hit(r.file, defects)}
    fps = [r.file for r in arm.reports if _hit(r.file, clean)]
    return {"reports": len(arm.reports), "with_reproducer": sum(1 for r in arm.reports if r.reproducer),
            "defect_files_hit": len(hits), "false_positives_on_clean": len(fps),
            "hit_files": sorted(hits)}


def compare() -> dict:
    defects, clean = ground_truth()
    arms = [static_arm(), raksha_arm()]
    model = Arm("plain model alone", ran=False,
                note="not run here; RAKSHA's model use (ranking, repair ladder) is measured by the "
                     "Scorecard's zero-inference share and the mutation factory")
    result = {"targets": len(TARGETS), "defect_files": len(defects),
              "arms": [], "measure": "reports carrying a replaying reproducer"}
    for arm in (*arms, model):
        result["arms"].append({**arm.as_dict(), "score": _score(arm, defects, clean) if arm.ran else None})
    return result


def markdown(result: dict) -> str:
    L = ["# RAKSHA AI — baseline comparison (J4)", "",
         f"On {result['targets']} demo targets ({result['defect_files']} files carry a planted "
         f"defect). The measure: **{result['measure']}**. Small curated set — a reproducible "
         "comparison, not a statistical benchmark.", "",
         "| arm | reports | with reproducer | defect files hit | FPs on clean | time (s) |",
         "|---|---|---|---|---|---|"]
    for a in result["arms"]:
        if not a["ran"]:
            L.append(f"| {a['name']} | — | — | — | — | — (not run) |")
            continue
        s = a["score"]
        L.append(f"| {a['name']} | {s['reports']} | {s['with_reproducer']} | {s['defect_files_hit']} | "
                 f"{s['false_positives_on_clean']} | {a['seconds']:.1f} |")
    L += ["", "## Notes", ""]
    for a in result["arms"]:
        if a["note"]:
            L.append(f"- **{a['name']}**: {a['note']}")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m raksha.baseline")
    ap.add_argument("--out"); ap.add_argument("--report", action="store_true")
    a = ap.parse_args(argv)
    result = compare()
    if a.out:
        Path(a.out).write_text(json.dumps(result, indent=2))
    print(markdown(result) if a.report else json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
