"""Phase 3 — the build-free lanes, end to end: `python -m raksha.slice_buildfree [path]`

Scans a target directory and produces proven findings with no build, no network and no language
runtime — the opening move on any unknown target, and the fallback when a build fails. Then it
generates dependency-bump patches for the findings that have a fixed version, and prints the
scorecard. Every finding is CONFIRMED by a deterministic match, labelled as such.

Default target is the bundled mixed-language estate (JS, Python, Go manifests + a secrets file),
which demonstrates "all languages" and "findings fast" in one run.
"""

from __future__ import annotations

import json
import sys
import pathlib

from .lanes import bump, scan_target
from .metrics import scorecard
from .finding import to_sarif_log

ROOT = pathlib.Path(__file__).parents[1]
DEFAULT = ROOT / "demo-targets" / "mixed-estate"
G, A, D, B, O = "\033[32m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def run(target: str | pathlib.Path = DEFAULT) -> int:
    target = pathlib.Path(target)
    print(f"\n{B}RAKSHA AI — build-free lanes{O}  {D}{target.name} · no build · no network{O}\n")
    res = scan_target(target)

    print(f"{B}Scanned{O} {res.files_scanned} files, {res.manifests_found} manifests "
          f"in {D}{res.seconds}s{O} — lanes: {res.by_lane()}\n")

    print(f"{B}Proven findings{O} {D}(every one CONFIRMED by deterministic match){O}")
    patchable = 0
    for f in sorted(res.findings, key=lambda x: (x.language, -_sev(x))):
        print(f"  {_c(f.severity)}{f.severity:8}{O} {f.language:11} {f.bug_class:9} "
              f"{D}{f.message[:66]}{O}")
        # Generate a bump patch where the advisory has a fixed version.
        patch = _try_bump(target, f)
        if patch:
            patchable += 1
            print(f"           {G}→ patch ready{O} {D}(dependency bump, zero inference){O}")

    card = scorecard(res.findings).as_dict()
    print(f"\n{B}Scorecard{O} {D}(from the records){O}")
    print(f"  Performance   {len(res.findings)} proven findings across "
          f"{card['scalability']['language_count']} languages: "
          f"{', '.join(card['scalability']['languages_covered'])}")
    print(f"  Precision     {card['precision']['reports_with_reproducer_pct']}% reports with a "
          f"replaying reproducer · evidence: {card['precision']['evidence_kind']}")
    print(f"  Patches       {patchable} ready as zero-inference dependency bumps")
    print(f"  Speed         all findings in {res.seconds}s, no build required")
    print(f"  Posture       network interfaces {card['posture']['network_interfaces']} · "
          f"cloud calls {card['posture']['cloud_calls']}")

    out = ROOT / "raksha-buildfree.sarif"
    out.write_text(json.dumps(to_sarif_log(res.findings), indent=2))
    print(f"\n{D}  wrote {out.name} — valid SARIF 2.1.0{O}\n")
    return 0


def _try_bump(root: pathlib.Path, finding) -> str:
    """Generate a bump patch for a supply-chain finding whose advisory has a fixed version."""
    if not finding.oracle.startswith("osv") or not finding.reproducer:
        return ""
    detail = finding.reproducer.detail or ""
    if "fixed in " not in detail:
        return ""
    fixed = detail.split("fixed in ", 1)[1].strip().rstrip(".")
    site = finding.fix_site_set[0]
    manifest = root / site.uri
    if not manifest.exists():
        return ""
    eco = {"java": "Maven", "javascript": "npm", "python": "PyPI", "go": "Go"}.get(finding.language)
    if not eco:
        return ""
    # npm pins the resolved version in the lockfile but the bump belongs in package.json, so for
    # npm we edit the sibling manifest the version range actually lives in.
    if eco == "npm":
        pkg = manifest.parent / "package.json"
        if pkg.exists():
            return bump.bump(eco, pkg.read_text(), site.symbol, fixed)
        return ""
    return bump.bump(eco, manifest.read_text(), site.symbol, fixed)


def _sev(f) -> int:
    return {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(f.severity, 0)


def _c(sev: str) -> str:
    return {"critical": "\033[31m", "high": "\033[33m"}.get(sev, "\033[2m")


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
