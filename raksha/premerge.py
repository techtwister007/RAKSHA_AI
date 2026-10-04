"""K20 — the pre-merge check: stop known problems before they ship.

``python -m raksha.premerge PATH [--name NAME]`` scans the tree with the build-free lanes (fast, no
build, nothing executed) and refuses the merge (exit 1) when any finding:

  * belongs to a weakness family covered by an **approved** guideline (K8) — the guideline is named;
  * is a **regression**: a weakness this project's report history shows was fixed before;
  * is **critical**.

Everything else passes (exit 0) with a short note. It reads the project store but never writes a
report — a pre-merge check is a gate on a change, not a run of record.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import reports
from .learning import Learning, _fam
from .projects import Store


def check(root: str | Path, *, name: str | None = None, store: Store | None = None) -> dict:
    from .lanes import scan_target
    root = Path(root)
    st = store or Store()
    project = st.identify(root, name=name, save=False)
    rows = [reports._row(f, project.tier) for f in scan_target(root).findings if f.is_reportable]
    fixed_before: set[str] = set()
    for b in reports.history(st, project.id):
        fixed_before |= set(b["diff"].get("fixed", []))
    approved = {g["family"]: g for g in Learning(st).approved_guidelines()}
    blocks = []
    for r in rows:
        fam = _fam(r)
        if fam in approved:
            g = approved[fam]
            blocks.append({"title": r["title"], "why": f"approved guideline {g['id']}: {g['rule']}"})
        elif r["key"] in fixed_before:
            blocks.append({"title": r["title"], "why": "regression: this was fixed in an earlier report"})
        elif r["severity"] == "critical":
            blocks.append({"title": r["title"], "why": "critical severity"})
    return {"project": project.id, "known_project": bool(reports.versions(st, project.id)),
            "findings": len(rows), "blocked": bool(blocks), "blocks": blocks}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m raksha.premerge")
    ap.add_argument("path"); ap.add_argument("--name")
    a = ap.parse_args(argv)
    r = check(a.path, name=a.name)
    if r["blocked"]:
        print(f"MERGE BLOCKED ({r['project']}): {len(r['blocks'])} item(s)")
        for b in r["blocks"]:
            print(f"  - {b['title'][:100]} — {b['why']}")
        return 1
    print(f"ok ({r['project']}): {r['findings']} finding(s), none blocking")
    return 0


if __name__ == "__main__":
    sys.exit(main())
