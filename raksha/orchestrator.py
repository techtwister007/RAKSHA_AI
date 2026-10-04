"""The orchestrator — holds the live session and serves the operator console.

This is the entrypoint the deployment image runs (`python -m raksha.orchestrator`). It keeps the
session state the console renders: the targets on the Mission Board, every finding, and the
scorecard computed from the records. Ingesting a target runs the build-free lanes (fast, any
language, no build) and records the findings; a target that is built would also run the deep lanes,
but the console only needs the record stream, which every lane already emits.

Kept dependency-free on purpose: the console is served by stdlib http.server (see console/server.py),
so the air-gap guard stays simple and the runtime carries no third-party package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .finding import Finding, RoeLevel, Status
from .lanes import scan_target
from .metrics import scorecard


@dataclass
class Target:
    """One Mission Board card."""

    name: str
    languages: list[str] = field(default_factory=list)
    build_status: str = "amber"      # green = built · amber = build-free, still finding · red = could not ingest
    roe_level: RoeLevel = RoeLevel.R1
    finding_ids: list[str] = field(default_factory=list)
    note: str = ""

    def card(self, findings: dict[str, Finding]) -> dict:
        mine = [findings[i] for i in self.finding_ids if i in findings]
        verified = sum(1 for f in mine if f.status is Status.VERIFIED)
        return {
            "name": self.name,
            "languages": self.languages,
            "build_status": self.build_status,
            "roe_level": self.roe_level.value,
            "findings": len(mine),
            "verified": verified,
            "note": self.note,
            "status": self._status(mine),
        }

    @staticmethod
    def _status(mine: list[Finding]) -> str:
        if not mine:
            return "scanning"
        if any(f.status is Status.VERIFIED for f in mine):
            return "fixing"
        return "finding"


@dataclass
class Session:
    targets: list[Target] = field(default_factory=list)
    findings: dict[str, Finding] = field(default_factory=dict)
    #: Fleet variants found per verified fix by the vaccine sweep. None until a sweep runs, so the
    #: scorecard shows the row as honestly-unmeasured rather than a faked zero.
    vaccine_variants: int | None = None

    # -- ingest -------------------------------------------------------------------------------
    def add_finding(self, f: Finding) -> None:
        self.findings[f.id] = f

    def ingest_build_free(self, root: str | Path, *, name: str | None = None,
                          roe: RoeLevel = RoeLevel.R1) -> Target:
        """Ingest a target directory through the build-free lanes and add it to the board."""
        root = Path(root)
        name = name or root.name
        try:
            result = scan_target(root)
        except Exception as e:  # noqa: BLE001 — a target we cannot read is red, not a crash
            t = Target(name=name, build_status="red", note=f"could not ingest: {e}")
            self.targets.append(t)
            return t
        langs = sorted({f.language for f in result.findings})
        t = Target(name=name, languages=langs, build_status="amber", roe_level=roe,
                   note="build-free mode, still finding")
        for f in result.findings:
            self.add_finding(f)
            t.finding_ids.append(f.id)
        self.targets.append(t)
        return t

    def attach_target(self, name: str, findings: list[Finding], *, build_status: str = "green",
                      roe: RoeLevel = RoeLevel.R1, languages: list[str] | None = None) -> Target:
        """Attach a target whose findings came from the deep lanes (e.g. the Java slice)."""
        t = Target(name=name, build_status=build_status, roe_level=roe,
                   languages=languages or sorted({f.language for f in findings}))
        for f in findings:
            self.add_finding(f)
            t.finding_ids.append(f.id)
        self.targets.append(t)
        return t

    # -- snapshots for the console ------------------------------------------------------------
    def board(self) -> list[dict]:
        return [t.card(self.findings) for t in self.targets]

    def scorecard(self) -> dict:
        return scorecard(self.findings.values(), vaccine_variants=self.vaccine_variants).as_dict()

    def run_vaccine_sweep(self, codebases: dict[str, Path]) -> int:
        """Mine a vaccine rule from every VERIFIED fix, sweep the codebases, record the count.

        This is the scalability beat made into a live metric: one verified fix, how many fleet
        variants of the same mistake it finds. Read-only (R0-safe); hits are only SUSPECTED.
        """
        from .vaccine import extract_rule, sweep
        total = 0
        for f in list(self.findings.values()):
            if f.status is not Status.VERIFIED:
                continue
            rule = extract_rule(f)
            if rule is None:
                continue
            total += len(sweep(rule, codebases))
        self.vaccine_variants = total
        return total

    def finding_rows(self) -> list[dict]:
        """Compact rows for the finding list, newest-looking order: severity then language."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows = []
        for f in self.findings.values():
            rows.append({
                "id": f.id,
                "bug_class": f.bug_class,
                "severity": f.severity,
                "language": f.language,
                "status": f.status.value,
                "target": f.target,
                "message": f.message,
                "oracle": f.oracle,
                "evidence": f.reproducer.kind if f.reproducer else None,
            })
        rows.sort(key=lambda r: (order.get(r["severity"], 9), r["language"]))
        return rows

    def finding_detail(self, finding_id: str) -> dict | None:
        f = self.findings.get(finding_id)
        return f.proof_block() if f else None

    def risk_register(self) -> list[dict]:
        from .risk import register
        return [r.as_dict() for r in register(self.findings.values())]

    def commanders_brief(self, finding_id: str) -> dict | None:
        from .brief import jssd_brief, plain_summary
        f = self.findings.get(finding_id)
        if f is None or not f.is_reportable:
            return None
        return {"id": f.id, "plain": plain_summary(f), "jssd": jssd_brief(f)}

    def verify_bundle(self, finding_id: str) -> dict | None:
        """Build the finding's signed bundle in a temp dir and verify it — the live Vault check."""
        import tempfile
        from .bundle import build_bundle, verify_bundle as _verify
        f = self.findings.get(finding_id)
        if f is None or not f.is_reportable:
            return None
        out = tempfile.mkdtemp(prefix="raksha-bundle-")
        build_bundle(f, out)
        res = _verify(out)
        return {"id": f.id, "ok": res.ok, "summary": res.summary(), "path": out}

    def pipeline_stages(self) -> list[dict]:
        """The status machine with a live count at or past each state — for the Live Pipeline.

        REPORT_ONLY is shown as its own row (a proven finding with no validated fix), not folded
        into CONFIRMED, so the board never discards findings it is actually holding.
        """
        from .finding import Status
        order = [Status.SUSPECTED, Status.CONFIRMED, Status.PATCHED, Status.VERIFIED,
                 Status.REPORT_ONLY]
        rank = {Status.SUSPECTED: 0, Status.CONFIRMED: 1, Status.PATCHED: 2, Status.VERIFIED: 3}
        rank[Status.REPORT_ONLY] = rank[Status.CONFIRMED]  # proven, no validated fix
        counts = {s.value: 0 for s in order}
        for f in self.findings.values():
            counts[f.status.value] = counts.get(f.status.value, 0) + 1
        rows = []
        for s in order:
            if s is Status.REPORT_ONLY:
                at_or_past = counts["REPORT_ONLY"]           # a terminal state, counted on its own
            else:
                at_or_past = sum(1 for f in self.findings.values() if rank.get(f.status, 0) >= rank[s])
            rows.append({"status": s.value, "count": counts.get(s.value, 0), "at_or_past": at_or_past})
        return rows

    def snapshot(self) -> dict:
        return {"board": self.board(), "findings": self.finding_rows(), "scorecard": self.scorecard(),
                "risk": self.risk_register(), "pipeline": self.pipeline_stages()}


def demo_session(repo_root: Path | None = None) -> Session:
    """Seed a session for the console demo: the mixed-language estate via the build-free lanes."""
    repo_root = repo_root or Path(__file__).parents[1]
    s = Session()
    estate = repo_root / "demo-targets" / "mixed-estate"
    if estate.exists():
        s.ingest_build_free(estate, name="mixed-estate")
    return s


def three_language_session(repo_root: Path | None = None, *, include_java: bool = True) -> Session:
    """Seed a session that shows three deep targets (C, Python, Java) beside the build-free estate —
    the 'three languages, one screen' scalability beat on the Mission Board."""
    from .slice_three import run_c, run_python
    repo_root = repo_root or Path(__file__).parents[1]
    s = Session()
    deep = [("c-overflow", run_c, "c/c++"), ("py-cmdinject", run_python, "python")]
    if include_java:
        try:
            from .slice_three import run_java
            deep.append(("audit-svc", run_java, "java"))
        except ImportError:
            pass
    for name, fn, lang in deep:
        try:
            f = fn()
            s.attach_target(name, [f], build_status="green", languages=[lang])
        except Exception:  # noqa: BLE001 — a slice that will not run is simply absent from the board
            pass
    estate = repo_root / "demo-targets" / "mixed-estate"
    if estate.exists():
        s.ingest_build_free(estate, name="mixed-estate")
    # One verified fix, fleet-wide: sweep the demo targets for the same mistake and record the
    # variant count, so the scalability row on the Scorecard is a live number, not a claim.
    codebases = {p.name: p for p in (repo_root / "demo-targets").glob("*") if p.is_dir()}
    if codebases:
        s.run_vaccine_sweep(codebases)
    return s


def main() -> int:
    from console.server import serve  # local import so the package has no server dependency at import
    import os
    port = int(os.environ.get("RAKSHA_CONSOLE_PORT", "8080"))
    return serve(demo_session(), port=port)


if __name__ == "__main__":
    raise SystemExit(main())
