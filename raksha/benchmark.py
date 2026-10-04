"""The benchmark harness — our own numbers, measured, with losses shown next to wins.

Every figure we quote in the room must come from our own run, never a borrowed general-coding
score — a judge will ask where a number came from. This runs the pipeline over a target set and
records, per target: what was found, whether a fix was proven, how it was proven (exploit vs
deterministic match), the repair lane, and the stage timings. It then writes a report with the
methodology stated and the losses listed beside the wins.

Honesty is the point. The bundled set is small and curated (our demo targets), so the aggregates
are a reproducible baseline, NOT a statistical security fix-rate — the report says exactly that. The
full baseline plugs in ARVO (~6,100 real bugs with gold patches) and AutoPatchBench as additional
case sources on a networked prep machine; the harness takes a list of cases, so adding them changes
the inputs, not this code.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .finding import INFERENCE_LANES, Finding, Status
from .metrics import NOT_A_LANGUAGE


@dataclass
class CaseResult:
    name: str
    language: str
    bug_class: str
    status: str
    fixed: bool
    report_only: bool
    time_to_pov_s: float | None
    time_to_patch_s: float | None
    lane: str | None
    evidence: str | None
    wall_s: float | None = None
    note: str = ""

    @classmethod
    def from_finding(cls, name: str, f: Finding, *, wall_s: float | None = None, note: str = "") -> "CaseResult":
        return cls(
            name=name, language=f.language, bug_class=f.bug_class, status=f.status.value,
            fixed=f.status is Status.VERIFIED, report_only=f.status is Status.REPORT_ONLY,
            time_to_pov_s=f.time_to_pov_seconds, time_to_patch_s=f.time_to_patch_seconds,
            lane=f.repair_lane.value if f.repair_lane else None,
            evidence=f.reproducer.kind if f.reproducer else None, wall_s=wall_s, note=note,
        )

    @classmethod
    def error(cls, name: str, note: str) -> "CaseResult":
        return cls(name, "?", "?", "ERROR", False, False, None, None, None, None, note=note)


def _median(xs: list[float]) -> float | None:
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    n = len(xs)
    return round(xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2, 2)


@dataclass
class BenchReport:
    results: list[CaseResult] = field(default_factory=list)
    #: Clean artifacts scanned as negative controls, and the findings (all false positives) they drew.
    negative_controls: int = 0
    false_positives: int = 0
    false_positive_notes: list[str] = field(default_factory=list)
    provenance: str = ""

    def aggregates(self) -> dict:
        r = self.results
        real = [c for c in r if c.status != "ERROR"]
        fixed = [c for c in real if c.fixed]
        reported = [c for c in real if c.status in ("CONFIRMED", "PATCHED", "VERIFIED", "REPORT_ONLY")]
        langs = sorted({c.language for c in real if c.language != "?"} - NOT_A_LANGUAGE)
        exploit = [c for c in reported if c.evidence == "exploit-replay"]
        match = [c for c in reported if c.evidence == "deterministic-match"]
        zero_inf = [c for c in fixed if c.lane and c.lane not in {l.value for l in INFERENCE_LANES}]
        return {
            "cases": len(r),
            "ran": len(real),
            "errors": len(r) - len(real),
            "reported": len(reported),
            "verified_fixed": len(fixed),
            "report_only": sum(1 for c in real if c.report_only),
            "languages": langs,
            "language_count": len(langs),
            "evidence": {"exploit_replay": len(exploit), "deterministic_match": len(match)},
            "fix_rate_on_this_set_pct": round(100.0 * len(fixed) / len(reported), 1) if reported else None,
            "zero_inference_fix_pct": round(100.0 * len(zero_inf) / len(fixed), 1) if fixed else None,
            "median_time_to_pov_s": _median([c.time_to_pov_s for c in real]),
            "median_time_to_patch_s": _median([c.time_to_patch_s for c in real]),
            # deep cases (build + hunt + repair + gate) and the build-free scan are different
            # operations; a single median over both would be dominated by the scan rows
            "median_end_to_end_deep_s": _median([c.wall_s for c in real
                                                 if c.wall_s is not None and c.evidence == "exploit-replay"]),
            "build_free_scan_s": next((c.wall_s for c in real if c.evidence == "deterministic-match"
                                       and c.wall_s is not None), None),
            "negative_controls": self.negative_controls,
            "false_positives_on_controls": self.false_positives,
        }

    def markdown(self) -> str:
        a = self.aggregates()
        lines = [
            "# RAKSHA AI — Benchmark Report",
            "",
            "## Methodology",
            "",
            "Every number below is measured by running the actual pipeline over the target set named "
            "in the Results table and reading the finding records — none is borrowed from a published "
            "general-coding score. The pipeline is identical to the one demonstrated: ingest → oracle "
            "→ confirm (reproducer replays) → repair ladder → five-check gate → signed bundle.",
            "",
            "**Scope, stated plainly.** This bundled set is small and curated (our demo targets across "
            "C, Java, Python and the build-free lanes). The aggregates are a *reproducible baseline*, "
            "not a statistical security fix-rate — a fix-rate claim requires the full ARVO / "
            "AutoPatchBench run, which plugs into this same harness as additional cases on a networked "
            "prep machine. We quote the set size with every number.",
            "",
            "## Results",
            "",
            "**Timing columns.** *End-to-end* is wall-clock for the whole case: build, hunt, repair "
            "and the five-check gate (deep cases), or the whole estate scan (build-free). *Confirm* "
            "and *patch* are measured from the finding record's creation; in these deep cases the "
            "reproducer is seeded rather than discovered by a fuzzing campaign, so *confirm* is "
            "record latency, not time-to-discovery — the end-to-end column is the honest speed number.",
            "",
            "| Target | Lang | Bug | Status | Fixed | Evidence | Lane | end-to-end (s) | confirm (s) | patch (s) |",
            "|--------|------|-----|--------|-------|----------|------|----------------|-------------|-----------|",
        ]
        for c in self.results:
            lines.append(
                f"| {c.name} | {c.language} | {c.bug_class} | {c.status} | "
                f"{'yes' if c.fixed else ('report' if c.report_only else '—')} | "
                f"{c.evidence or '—'} | {c.lane or '—'} | "
                f"{c.wall_s if c.wall_s is not None else '—'} | "
                f"{c.time_to_pov_s if c.time_to_pov_s is not None else '—'} | "
                f"{c.time_to_patch_s if c.time_to_patch_s is not None else '—'} |")
        lines += [
            "",
            "## Aggregates (on this set)",
            "",
            f"- Targets run: **{a['ran']}** of {a['cases']} ({a['errors']} errors)",
            f"- Proven findings reported: **{a['reported']}**",
            f"- Verified fixes: **{a['verified_fixed']}**  ·  report-only: **{a['report_only']}**",
            f"- Fix rate on this set: **{a['fix_rate_on_this_set_pct']}%** "
            f"(of reported findings; small-set baseline, not a security fix-rate)",
            f"- Zero-inference fixes: **{a['zero_inference_fix_pct']}%**",
            f"- Languages covered: **{a['language_count']}** ({', '.join(a['languages'])})",
            f"- Evidence: {a['evidence']['exploit_replay']} exploit-proven, "
            f"{a['evidence']['deterministic_match']} match-proven",
            f"- Deep cases, median end-to-end (build → hunt → fix → five-check gate): "
            f"**{a['median_end_to_end_deep_s']}s**",
            f"- Build-free estate scan, all {a['evidence']['deterministic_match']} match-proven findings: "
            f"**{a['build_free_scan_s']}s**",
            "",
            "## Losses, shown beside the wins",
            "",
        ]
        losses = [c for c in self.results if not c.fixed]
        if losses:
            for c in losses:
                why = c.note or ("proven but no validated fix (REPORT_ONLY)" if c.report_only
                                 else f"status {c.status}")
                lines.append(f"- **{c.name}** ({c.language}): {why}")
        else:
            lines.append("- None on this set. The honest caveat above (small curated set) still applies.")
        lines += ["", "## Precision", "",
                  "100% of reported findings carry a replaying reproducer, by construction — the data "
                  "model forbids reporting one that does not. That is a structural property; it says "
                  "every report is *evidenced*, not that no evidence is ever wrong. So false positives "
                  "are measured separately, against negative controls: a clean estate built from the "
                  "same shapes as the vulnerable one — fixed dependency versions on every patched "
                  "release line, secrets read from the environment, references in config, AWS "
                  "documentation keys, ranges in manifests, an authenticated API.",
                  "",
                  f"- Negative controls scanned: **{a['negative_controls']}** clean artifacts",
                  f"- False positives on them: **{a['false_positives_on_controls']}**", ""]
        lines += [f"  - {n}" for n in self.false_positive_notes]
        if self.provenance:
            lines += ["", "---", "", f"_{self.provenance}_", ""]
        return "\n".join(lines)


def run_cases(cases: list[tuple[str, Callable[[], Finding]]]) -> BenchReport:
    """Run each case (name, runner-returning-a-Finding) and time it."""
    report = BenchReport()
    for name, runner in cases:
        t0 = time.monotonic()
        try:
            f = runner()
            report.results.append(CaseResult.from_finding(name, f, wall_s=round(time.monotonic() - t0, 2)))
        except Exception as e:  # noqa: BLE001 — a case that errors is recorded, not fatal
            report.results.append(CaseResult.error(name, f"runner raised: {e}"))
    return report


def deep_cases() -> list[tuple[str, Callable[[], Finding]]]:
    """The three deep slices as benchmark cases (need gcc / python / maven)."""
    from .slice_three import run_c, run_java, run_python
    return [("c-overflow", run_c), ("py-cmdinject", run_python), ("java-log4shell", run_java)]


#: The clean twin of the vulnerable estate: every file here must produce ZERO findings.
NEGATIVE_CONTROLS: dict[str, str] = {
    "log4j/pom.xml": "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
                     "<artifactId>log4j-core</artifactId><version>2.17.1</version></dependency>"
                     "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind"
                     "</artifactId><version>2.12.6.1</version></dependency></dependencies></project>",
    "log4j-backport/pom.xml": "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
                              "<artifactId>log4j-core</artifactId><version>2.12.4</version></dependency>"
                              "</dependencies></project>",
    "web/package.json": '{"dependencies":{"lodash":"^4.17.20","minimist":"~1.2.6"}}',
    "web/package-lock.json": '{"packages":{"node_modules/lodash":{"version":"4.17.21"},'
                             '"node_modules/minimist":{"version":"1.2.6"}}}',
    "py/requirements.txt": "pyyaml==5.4\nrequests==2.31.0\nflask>=2.0\n",
    "py/pyproject.toml": '[build-system]\nrequires = ["setuptools>=61"]\n[project]\nname = "x"\n'
                         'dependencies = ["requests>=2.25.1"]\n',
    "go/go.mod": "module x\nrequire github.com/gin-gonic/gin v1.7.7\n",
    "py/settings.py": 'import os\nDB_PASSWORD = os.environ["DB_PASSWORD"]\n'
                      'token = make_token(user)\nsecret_key = settings.SECRET_KEY\npwd = os.getcwd()\n'
                      'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    "config/application.yml": "db:\n  password: ${DB_PASSWORD}\n  secret: SECRET_KEY_FROM_VAULT\n",
    "config/app.properties": "api.key=changeme\nplaceholder.token=<your-token-here>\n",
    "api/openapi.json": '{"openapi":"3.0.0","security":[{"bearer":[]}],"paths":{"/orders":'
                        '{"post":{"responses":{}}}}}',
}


def negative_controls(report: BenchReport) -> None:
    """Scan the clean estate; every finding on it is a false positive and is recorded by name."""
    import pathlib
    import tempfile
    from .lanes import scan_target
    root = pathlib.Path(tempfile.mkdtemp(prefix="raksha-negctl-"))
    try:
        for rel, text in NEGATIVE_CONTROLS.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        found = scan_target(root).findings
        report.negative_controls = len(NEGATIVE_CONTROLS)
        report.false_positives = len(found)
        report.false_positive_notes = [f"{f.target}: {f.message[:100]}" for f in found]
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def _why_not_fixed(f: Finding) -> str:
    """The honest reason a proven build-free finding carries no verified fix."""
    if f.oracle.startswith("osv:"):
        site = f.fix_site_set[0] if f.fix_site_set else None
        bump = site.rationale if site and site.rationale else "no fixed version"
        return (f"proven by version match; zero-inference patch prepared ({bump}) but not gate-verified "
                "— the gate needs a build, and this case ran build-free")
    if f.oracle.startswith("secrets:"):
        return "proven by re-match; the fix is rotating the credential — an operator action, not a code patch"
    if f.oracle.startswith("service:"):
        return "proven from the API spec; the fix is an authorization policy change, reviewed by a human"
    return f"status {f.status.value}"


def main() -> int:
    """`python -m raksha.benchmark` — run the deep slices + build-free estate, write the report."""
    import pathlib
    import subprocess
    from datetime import datetime, timezone
    from .lanes import scan_target
    repo = pathlib.Path(__file__).parents[1]
    report = run_cases(deep_cases())
    estate = repo / "demo-targets" / "mixed-estate"
    if estate.exists():
        t0 = time.monotonic()
        scan = scan_target(estate)
        wall = round(time.monotonic() - t0, 3)
        for f in scan.findings:
            site = f.fix_site_set[0] if f.fix_site_set else None
            where = (f"{site.uri}:{site.start_line or site.symbol}" if site else f.target)
            report.results.append(CaseResult.from_finding(
                f"estate:{f.oracle.split(':', 1)[-1]}@{where}", f, wall_s=wall, note=_why_not_fixed(f)))
    negative_controls(report)
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=repo,
                                capture_output=True, text=True).stdout.strip() or "unknown"
    except OSError:
        commit = "unknown"
    report.provenance = (f"Generated by `python -m raksha.benchmark` at commit {commit} on "
                         f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC. Re-run it to reproduce every number.")
    out = pathlib.Path(__file__).parents[1] / "docs" / "benchmark-report.md"
    out.write_text(report.markdown())
    a = report.aggregates()
    print(f"ran {a['ran']} cases · {a['verified_fixed']} fixed · {a['reported']} reported · "
          f"{a['language_count']} languages · wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
