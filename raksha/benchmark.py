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

from .finding import Finding, Status


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

    def aggregates(self) -> dict:
        r = self.results
        real = [c for c in r if c.status != "ERROR"]
        fixed = [c for c in real if c.fixed]
        reported = [c for c in real if c.status in ("CONFIRMED", "PATCHED", "VERIFIED", "REPORT_ONLY")]
        langs = sorted({c.language for c in real if c.language != "?"})
        exploit = [c for c in reported if c.evidence == "exploit-replay"]
        match = [c for c in reported if c.evidence == "deterministic-match"]
        zero_inf = [c for c in fixed if c.lane == "TEMPLATE"]
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
            "| Target | Lang | Bug | Status | Fixed | Evidence | Lane | t-PoV (s) | t-patch (s) |",
            "|--------|------|-----|--------|-------|----------|------|-----------|-------------|",
        ]
        for c in self.results:
            lines.append(
                f"| {c.name} | {c.language} | {c.bug_class} | {c.status} | "
                f"{'yes' if c.fixed else ('report' if c.report_only else '—')} | "
                f"{c.evidence or '—'} | {c.lane or '—'} | "
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
            f"- Median time-to-PoV: **{a['median_time_to_pov_s']}s**  ·  "
            f"median time-to-validated-patch: **{a['median_time_to_patch_s']}s**",
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
                  "model forbids reporting one that does not. This is a structural property, not a "
                  "tuned result, and it holds on every set.", ""]
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


def main() -> int:
    """`python -m raksha.benchmark` — run the deep slices + build-free estate, write the report."""
    import pathlib
    from .lanes import scan_target
    report = run_cases(deep_cases())
    estate = pathlib.Path(__file__).parents[1] / "demo-targets" / "mixed-estate"
    if estate.exists():
        for f in scan_target(estate).findings:
            report.results.append(CaseResult.from_finding(f"estate:{f.oracle}", f))
    out = pathlib.Path(__file__).parents[1] / "docs" / "benchmark-report.md"
    out.write_text(report.markdown())
    a = report.aggregates()
    print(f"ran {a['ran']} cases · {a['verified_fixed']} fixed · {a['reported']} reported · "
          f"{a['language_count']} languages · wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
