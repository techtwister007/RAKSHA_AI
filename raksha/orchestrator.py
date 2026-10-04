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
        return scorecard(self.findings.values()).as_dict()

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

    def snapshot(self) -> dict:
        return {"board": self.board(), "findings": self.finding_rows(), "scorecard": self.scorecard()}


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
    for name, fn, lang in [("c-overflow", run_c, "c/c++"), ("py-cmdinject", run_python, "python")]:
        try:
            f = fn()
            s.attach_target(name, [f], build_status="green", languages=[lang])
        except Exception:  # noqa: BLE001 — a slice that will not run is simply absent from the board
            pass
    if include_java:
        try:
            from .slice_three import run_all
        except Exception:  # noqa: BLE001
            pass
    estate = repo_root / "demo-targets" / "mixed-estate"
    if estate.exists():
        s.ingest_build_free(estate, name="mixed-estate")
    return s


def main() -> int:
    from console.server import serve  # local import so the package has no server dependency at import
    import os
    port = int(os.environ.get("RAKSHA_CONSOLE_PORT", "8080"))
    return serve(demo_session(), port=port)


if __name__ == "__main__":
    raise SystemExit(main())
