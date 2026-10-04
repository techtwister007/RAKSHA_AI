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

from datetime import datetime

from .finding import Finding, RoeLevel, Status, utcnow
from .lanes import scan_target
from .metrics import live_counters, scorecard


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
    #: Where sealed evidence bundles are kept (one directory per finding); created on first use.
    evidence_root: Path | None = None
    #: When the run began, and the live counters at that moment: the scorecard reports this run's
    #: own wall-clock, model calls, tokens and executions — not the whole process's.
    started_at: datetime = field(default_factory=utcnow)
    counter_baseline: dict = field(default_factory=live_counters)

    # -- ingest -------------------------------------------------------------------------------
    def add_finding(self, f: Finding) -> None:
        self.findings[f.id] = f

    def ingest_build_free(self, root: str | Path, *, name: str | None = None,
                          roe: RoeLevel = RoeLevel.R1, note: str | None = None) -> Target:
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
                   note=note or "build-free mode, still finding")
        for f in result.findings:
            self.add_finding(f)
            t.finding_ids.append(f.id)
        self.targets.append(t)
        return t

    def ingest(self, root: str | Path, runner=None, *, name: str | None = None,
               roe: RoeLevel = RoeLevel.R1) -> Target:
        """Ingest a target the way the finale does: try to build, and on any build failure fall
        through to the build-free lanes. This is the graceful-degradation claim, actually wired —
        the build agent's `degraded` flag is consumed here, not merely set and dropped.

        `runner` executes the build commands; when None (no toolchain wired, as in this container)
        the agent still degrades cleanly to build-free, which is the behaviour that must never fail.
        """
        from .buildagent import BuildAgent
        root = Path(root)
        name = name or root.name
        if runner is not None:
            try:
                outcome = BuildAgent(runner).build(root)
            except Exception as e:  # noqa: BLE001 — a build that cannot even start degrades too
                return self.ingest_build_free(root, name=name, roe=roe,
                                              note=f"build could not start ({type(e).__name__}: {e}), "
                                                   "degraded to build-free")
            if outcome.ok:
                # A built target would additionally run the deep lanes; the build-free lanes still
                # run so the record stream is never empty. Board shows green.
                t = self.ingest_build_free(root, name=name, roe=roe,
                                           note=f"built ({outcome.summary}); build-free lanes also run")
                if t.build_status != "red":          # a target we could not read stays red
                    t.build_status = "green"
                return t
            # Build failed → degrade. Exactly the path the dossier calls the choice that turns
            # 36% into 85%: a target that will not build still yields proven findings.
            return self.ingest_build_free(root, name=name, roe=roe,
                                          note=f"build failed, degraded to build-free ({outcome.summary})")
        return self.ingest_build_free(root, name=name, roe=roe)

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
        return scorecard(self.findings.values(), vaccine_variants=self.vaccine_variants,
                         started_at=self.started_at, counter_baseline=self.counter_baseline).as_dict()

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
            # the codebase the fix came from is not "the fleet": re-finding the original bug there
            # (the source tree is unpatched — the gate patches a copy) would be a self-hit
            others = {name: root for name, root in codebases.items() if name != f.target}
            total += len(sweep(rule, others))
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
        if f is None:
            return None
        detail = f.proof_block()
        detail["patch_diff"] = f.patch_diff     # shown on the detail screen, rendered as text
        return detail

    def risk_register(self) -> list[dict]:
        from .risk import register
        return [r.as_dict() for r in register(self.findings.values())]

    def commanders_brief(self, finding_id: str) -> dict | None:
        from .brief import jssd_brief, plain_summary
        f = self.findings.get(finding_id)
        if f is None or not f.is_reportable:
            return None
        return {"id": f.id, "plain": plain_summary(f), "jssd": jssd_brief(f)}

    def bundle_dir(self, finding_id: str) -> Path | None:
        """The finding's sealed evidence bundle — built once, then kept, so it can be re-verified."""
        from .bundle import build_bundle
        f = self.findings.get(finding_id)
        if f is None or not f.is_reportable:
            return None
        if self.evidence_root is None:
            import tempfile
            self.evidence_root = Path(tempfile.mkdtemp(prefix="raksha-evidence-"))
        out = self.evidence_root / f.id
        if not (out / "bundle.json").exists():
            build_bundle(f, out)
        return out

    def verify_bundle(self, finding_id: str) -> dict | None:
        """Re-verify the SEALED bundle on disk — the live Vault check.

        The bundle is sealed once (on first request) and every later verify recomputes its hashes and
        signature from the files as they are now, so tampering with the stored bundle is detected.
        """
        from .bundle import verify_bundle as _verify
        out = self.bundle_dir(finding_id)
        if out is None:
            return None
        res = _verify(out)
        return {"id": finding_id, "ok": res.ok, "summary": res.summary(), "bundle": out.name}

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
    targets = repo_root / "demo-targets"
    codebases = {p.name: p for p in targets.glob("*") if p.is_dir() and p.name != "fleet"}
    codebases.update({p.name: p for p in (targets / "fleet").glob("*") if p.is_dir()})
    if codebases:
        s.run_vaccine_sweep(codebases)
    return s


def finale_session(targets_dir: Path, out_dir: Path | None = None) -> Session:
    """The session the deployment runs: every directory under `targets_dir` is ingested (build
    attempted where a toolchain is present, build-free lanes always), and the jury submission plus a
    sealed evidence bundle per reportable finding are written to `out_dir`."""
    from .export import export
    from .buildagent import ShellRunner
    s = Session()
    runner = ShellRunner()
    try:
        for root in sorted(p for p in targets_dir.iterdir() if p.is_dir()):
            s.ingest(root, runner, name=root.name)
    finally:
        runner.cleanup()
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        export(list(s.findings.values()), out_dir / "submission")
        s.evidence_root = out_dir / "evidence"
        for fid, f in s.findings.items():
            if f.is_reportable:
                s.bundle_dir(fid)
    return s


def main() -> int:
    from console.server import serve  # local import so the package has no server dependency at import
    import os
    port = int(os.environ.get("RAKSHA_CONSOLE_PORT", "8080"))
    host = os.environ.get("RAKSHA_CONSOLE_HOST", "127.0.0.1")
    targets = Path(os.environ.get("RAKSHA_TARGETS", "/targets"))
    out = os.environ.get("RAKSHA_OUT")
    if targets.is_dir() and any(p.is_dir() for p in targets.iterdir()):
        session = finale_session(targets, Path(out) if out else None)
    else:
        session = demo_session()          # no targets mounted: the bundled demo estate
    return serve(session, port=port, host=host)


if __name__ == "__main__":
    raise SystemExit(main())
