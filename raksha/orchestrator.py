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
from . import assets as _assets
from . import journal as _journal
from .gate.crossconfirm import cross_confirm
from .lanes import structure as _structure
from . import profile as _profile
from .signature import signature as _sig


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
    #: The asset registry (mission tiers per codebase), loaded once; drives mission-impact and ROE.
    registry: _assets.Registry = field(default_factory=_assets.load)
    #: Cryptographic primitives seen across the estate, for the post-quantum migration report.
    crypto_uses: list = field(default_factory=list)
    #: C2: open-range dependencies seen across the estate (exposure of unknown status), for the boundary.
    unpinned_deps: list = field(default_factory=list)
    #: Per-target structural graph summaries (nodes/edges/sinks) for the console.
    structure_summaries: dict = field(default_factory=dict)
    #: Where sealed evidence bundles are kept (one directory per finding); created on first use.
    evidence_root: Path | None = None
    #: When the run began, and the live counters at that moment: the scorecard reports this run's
    #: own wall-clock, model calls, tokens and executions — not the whole process's.
    started_at: datetime = field(default_factory=utcnow)
    counter_baseline: dict = field(default_factory=live_counters)
    #: The append-only, hash-chained session journal (W0-1). None keeps the session journal-free
    #: (tests, the demo); set it via open_journal() or the journal_path argument to record and resume.
    journal: "_journal.Journal | None" = None

    def open_journal(self, path: str | Path) -> None:
        """Begin (or continue) journalling pipeline events to `path`."""
        self.journal = _journal.Journal(path)
        self.emit("session_open", targets=len(self.targets), findings=len(self.findings))

    def emit(self, kind: str, **fields) -> None:
        """Append one event to the journal if one is open; a no-op otherwise. Never raises."""
        if self.journal is None:
            return
        try:
            self.journal.emit(kind, **fields)
        except Exception:  # noqa: BLE001 — journalling must never take the run down
            pass

    def _journal_finding(self, f: Finding, event: str) -> None:
        self.emit(event, finding=f.id, status=f.status.value, bug_class=f.bug_class,
                  language=f.language, target=f.target, snapshot=_journal.snapshot_finding(f))

    def checkpoint(self) -> None:
        """Emit a full board+findings snapshot, so resume() can restore this exact state. Cheap
        enough to call after every ingest; the per-event records remain for the live log."""
        self.emit("checkpoint",
                  targets=[{"name": t.name, "languages": list(t.languages),
                            "build_status": t.build_status, "roe_level": t.roe_level.value,
                            "finding_ids": list(t.finding_ids), "note": t.note} for t in self.targets],
                  findings=[_journal.snapshot_finding(f) for f in self.findings.values()],
                  crypto_uses=len(self.crypto_uses))

    @classmethod
    def resume(cls, path: str | Path) -> "Session":
        """Rebuild a session from its journal's latest checkpoint and continue appending to it.

        The hash chain is verified first; a broken chain raises. Findings are reconstructed through
        the same record-validation path a deserialised finding uses, so a tampered snapshot is
        refused exactly as a forged record would be."""
        ok, problems = _journal.verify(path)
        if not ok:
            raise ValueError("journal failed verification: " + "; ".join(problems[:3]))
        last = None
        for rec in _journal.read(path):
            if rec.get("kind") == "checkpoint":
                last = rec
        s = cls()
        if last is not None:
            for d in last["findings"]:
                f = _journal.finding_from_snapshot(d)
                s.findings[f.id] = f
            for td in last["targets"]:
                s.targets.append(Target(name=td["name"], languages=list(td["languages"]),
                                        build_status=td["build_status"],
                                        roe_level=RoeLevel(td["roe_level"]),
                                        finding_ids=list(td["finding_ids"]), note=td["note"]))
        s.journal = _journal.Journal(path)       # continue the same chain
        s.emit("session_resumed", targets=len(s.targets), findings=len(s.findings))
        return s

    # -- ingest -------------------------------------------------------------------------------
    def add_finding(self, f: Finding) -> None:
        self.findings[f.id] = f
        self._journal_finding(f, "finding_added")

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
        self.crypto_uses.extend(result.crypto_uses)
        self.unpinned_deps.extend(getattr(result, "unpinned", []))
        found = list(result.findings)
        # Structural (CPG) hypotheses: SUSPECTED source->sink paths that exist to be cross-confirmed
        # by a lane that lands a reproducer on the same site+CWE, and otherwise to feed triage. They
        # never become reports on their own — "no reproducer, no report" holds.
        try:
            sres = _structure.scan_structure(root)
            self.structure_summaries[name] = sres.graph_summary
            extra = list(_structure.to_findings(sres))
            # "Take" lanes (Semgrep/Gitleaks/OSV-Scanner) only when a binary is present AND its flag
            # is set — on a bare box this is a no-op; when enabled, their findings cross-confirm ours.
            from .lanes.take import run_take_lanes
            extra += run_take_lanes(str(root))
            found = cross_confirm([*found, *extra])
        except Exception:  # noqa: BLE001 — a tree we cannot parse structurally is not a crash
            pass
        _assets.annotate(found, self.registry, target=name)
        langs = sorted({f.language for f in found if f.language not in ("any", "api")})
        t = Target(name=name, languages=langs, build_status="amber", roe_level=roe,
                   note=note or "build-free mode, still finding")
        for f in found:
            self.add_finding(f)
            t.finding_ids.append(f.id)
        self.targets.append(t)
        self._annotate_evidence()
        self.checkpoint()
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

    def ingest_campaign(self, root: str | Path, *, name: str | None = None, max_bugs: int = 6,
                        budget_s: float | None = None, corpus: list[bytes] | None = None,
                        roe: RoeLevel = RoeLevel.R1) -> Target:
        """B1: drive ONE target to as many proven fixes as the budget allows. Find a bug, fix and
        prove it, APPLY the proven patch to a working copy, then fuzz again so the next round meets
        the next defect — until the tree is clean, the per-target budget is spent, or a bug cannot
        be fixed (which would otherwise be re-found forever). A real codebase has many bugs; one
        find-fix is not a campaign.
        """
        import shutil
        import tempfile
        import time as _time
        from .autorepair import repair as _repair
        root = Path(root)
        name = name or root.name
        budget = budget_s if budget_s is not None else _profile.current().per_target_budget_s
        work = Path(tempfile.mkdtemp(prefix="raksha-campaign-")) / root.name
        try:
            shutil.copytree(root, work, symlinks=True)
        except Exception as e:  # noqa: BLE001
            t = Target(name=name, build_status="red", note=f"campaign could not copy target: {e}")
            self.targets.append(t); return t
        found: list[Finding] = []
        seen: set[str] = set()
        t0 = _time.monotonic()
        for _round in range(max_bugs):
            if _time.monotonic() - t0 > budget:
                self.emit("campaign_budget_spent", target=name, found=len(found))
                break
            r = _dispatch_autofuzz(work)
            if not r.found:
                self.emit("campaign_clean", target=name, found=len(found), round=_round)
                break
            f = r.finding
            sig = _sig(f)
            if sig in seen:            # a bug we already handled — stop rather than loop on it
                break
            seen.add(sig)
            self.emit("campaign_crash", target=name, finding=f.id, signature=sig, round=_round)
            _repair(f, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                    corpus=(corpus or [b"ok", b"test", b"\x01\x02"]) + list(getattr(r, "benign_corpus", [])))
            self.add_finding(f); found.append(f)
            if hasattr(r, "cleanup"):
                try: r.cleanup()
                except Exception: pass  # noqa: BLE001
            if f.status is Status.VERIFIED and f.patch_diff:
                if not self._apply_to_tree(f.patch_diff, work):
                    self.emit("campaign_patch_unapplied", target=name, finding=f.id); break
                self.emit("campaign_patch_applied", target=name, finding=f.id, signature=sig)
            else:
                # could not prove a fix; applying nothing would re-find it next round, so stop here
                self.emit("campaign_unfixed", target=name, finding=f.id, status=f.status.value)
                break
        shutil.rmtree(work.parent, ignore_errors=True)
        return self.attach_target(name, found, build_status="green", roe=roe,
                                  languages=sorted({f.language for f in found}) or None)

    @staticmethod
    def _apply_to_tree(patch_diff: str, tree: Path) -> bool:
        """Apply a proven patch to the campaign's working copy so the next round sees fixed code."""
        import subprocess
        patch = tree / ".raksha.campaign.patch"
        patch.write_text(patch_diff)
        for cmd in (["git", "apply", "-p1", str(patch)], ["patch", "-p1", "-i", str(patch)]):
            try:
                r = subprocess.run(cmd, cwd=str(tree), capture_output=True, timeout=60)
                if r.returncode == 0:
                    patch.unlink(missing_ok=True)
                    return True
            except (OSError, subprocess.SubprocessError):
                continue
        patch.unlink(missing_ok=True)
        return False

    def ingest_autofuzz(self, root: str | Path, *, name: str | None = None,
                        repair_it: bool = True, corpus: list[bytes] | None = None,
                        red_team: bool = True, roe: RoeLevel = RoeLevel.R1) -> Target:
        """Deep-ingest a target that ships no fuzz harness: synthesize one, find a bug, and (by
        default) drive the repair ladder through the gate. This is the find→fix→prove loop on an
        unknown target with no human writing a driver."""
        from .autorepair import repair as _repair
        root = Path(root)
        name = name or root.name
        r = _dispatch_autofuzz(root)
        if not r.found:
            t = Target(name=name, build_status="amber", roe_level=roe,
                       note=f"autofuzz found no crash: {r.note}")
            self.targets.append(t)
            return t
        f = r.finding
        if repair_it:
            _repair(f, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                    corpus=(corpus or [b"ok", b"test", b"\x01\x02"]) + list(getattr(r, "benign_corpus", [])))
            # Independent red team: once the gate says VERIFIED, try to falsify the fix. A patch
            # that cannot survive a fresh adversary is not actually proven. Bounded and offline.
            if f.status is Status.VERIFIED and red_team:
                try:
                    from .redteam import red_round
                    red_round(f, r.target, reproducer=r.crashing_input,
                              corpus=corpus or [b"ok", b"test", b"\x01\x02"], rounds=120, seconds=4.0)
                except Exception:  # noqa: BLE001 — the red team is a check, not a gate; never fatal
                    pass
            if hasattr(r.target, "discard"):
                try:
                    r.target.discard(r.target.build(None))
                except Exception:  # noqa: BLE001
                    pass
        return self.attach_target(name, [f], build_status="green",
                                  languages=[f.language])

    def attach_target(self, name: str, findings: list[Finding], *, build_status: str = "green",
                      roe: RoeLevel = RoeLevel.R1, languages: list[str] | None = None) -> Target:
        """Attach a target whose findings came from the deep lanes (e.g. the Java slice)."""
        _assets.annotate(findings, self.registry, target=name)
        t = Target(name=name, build_status=build_status, roe_level=roe,
                   languages=languages or sorted({f.language for f in findings}))
        for f in findings:
            self.add_finding(f)
            t.finding_ids.append(f.id)
        self.targets.append(t)
        self._annotate_evidence()
        self.checkpoint()
        return t

    # -- snapshots for the console ------------------------------------------------------------
    def board(self) -> list[dict]:
        return [t.card(self.findings) for t in self.targets]

    def scorecard(self) -> dict:
        degraded = len([t for t in self.targets if t.build_status in ("amber", "red")])
        return scorecard(self.findings.values(), vaccine_variants=self.vaccine_variants,
                         targets_degraded=degraded, targets_total=len(self.targets),
                         attack_graph=self.attack_graph(), pqc=self.pqc_report(),
                         fleet=self.fleet_rollup(), unpinned_deps=self.unpinned_deps,
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
        detail["frontier"] = list(f.frontier)   # the candidates that passed, and which was chosen
        detail["red_team"] = f.red_team
        from .grade import deploy_grade
        detail["deploy_grade"] = deploy_grade(f)   # D2: A/B/C readiness with the factors behind it
        return detail

    def risk_register(self) -> list[dict]:
        from .risk import register
        return [r.as_dict() for r in register(self.findings.values())]

    def commanders_brief(self, finding_id: str) -> dict | None:
        from .brief import jssd_brief, plain_summary
        f = self.findings.get(finding_id)
        if f is None or not f.is_reportable:
            return None
        from .brief import _HINDI
        return {"id": f.id, "plain": plain_summary(f), "jssd": jssd_brief(f, hindi=True),
                "hindi": _HINDI.get(f.status, "सुभेद्यता पाई गई।")}

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

    def purge_reproducers(self, *, exploit_only: bool = True) -> int:
        """D6: remove stored reproducer bytes from the node by policy, keeping each signed record
        valid (hash + replay command retained). Returns how many were purged. By default only
        exploit-replay bytes (the sensitive ones) are purged; deterministic-match inputs are
        benign identifiers and left in place."""
        from .finding import EXPLOIT_REPLAY
        n = 0
        for f in self.findings.values():
            if exploit_only and (f.reproducer is None or f.reproducer.kind != EXPLOIT_REPLAY):
                continue
            if f.purge_reproducer():
                n += 1
                self.emit("reproducer_purged", finding=f.id)
        return n

    def _annotate_evidence(self) -> None:
        """Fuse independent evidence on every finding, and record the model parliament's read
        (offline: a single-source verdict and the deterministic epistemic-conflict signal). Neither
        can change status — only the gate does; these annotate the record and raise scrutiny."""
        from . import evidence, parliament
        from .inference import get_client
        client = get_client()
        for f in self.findings.values():
            try:
                parliament.convene(f, client=client)
            except Exception:  # noqa: BLE001 — a model that will not answer must not stop the run
                pass
            if f.parliament is None or f.parliament.get("disagreement") is None:
                ec = parliament.epistemic_conflict(f)
                if ec is not None:
                    f.parliament = {**(f.parliament or {}), "epistemic_conflict": ec}
        evidence.fuse_all(self.findings.values())

    def fleet_rollup(self) -> list[dict]:
        """C5: defects that span two or more targets, folded into one row each."""
        from . import fleet
        return fleet.rollup(self.findings.values())

    def mark_finding_wrong(self, finding_id: str) -> int:
        """E7: an operator says a shipped fix was wrong. Demote its learned shape from the fix
        memory so it is never re-offered, and record it on the journal."""
        from .retrieval import default_memory
        f = self.findings.get(finding_id)
        if f is None:
            return 0
        n = default_memory().demote(f)
        self.emit("finding_marked_wrong", finding=finding_id, demoted=n)
        return n

    def save_memory(self, path=None):
        """E5: persist the fix memory so a learned fix survives a reboot."""
        from .retrieval import default_memory
        p = Path(path) if path else (self.evidence_root or Path(".")) / "fix_memory.json"
        default_memory().save(p)
        return p

    def load_memory(self, path=None) -> int:
        from .retrieval import default_memory
        p = Path(path) if path else (self.evidence_root or Path(".")) / "fix_memory.json"
        return default_memory().load(p)

    def sign_journal(self) -> dict | None:
        """D5: sign the run's audit trail. None when no journal is open."""
        if self.journal is None:
            return None
        from . import journal as _j
        return _j.sign(self.journal.path)

    def attack_graph(self) -> dict:
        """Chains of individually-moderate findings into a path to impact, scored by attack
        economics. Built over the whole estate at snapshot time."""
        from . import attackgraph
        g = attackgraph.build(list(self.findings.values()), assets=self.registry,
                              critical_scopes=self.registry.critical_names())
        attackgraph.annotate(list(self.findings.values()), g)
        return g.as_dict()

    def pqc_report(self) -> dict:
        """Post-quantum readiness across the estate: which cryptography must migrate, and to what."""
        from .lanes import crypto
        return crypto.pqc_report(self.crypto_uses)

    def triage(self) -> dict:
        """The decision funnel over the current findings: cheap deterministic scoring that would,
        at estate scale, decide where the expensive lanes spend their budget. Here it shows the
        honest reduction (all findings -> worth-deep-work -> top priorities)."""
        from . import triage as _triage
        fs = list(self.findings.values())
        res = _triage.funnel(fs, stages=[("all findings", 0.0, len(fs) or 1),
                                         ("worth deeper work", 0.35, max(1, len(fs))),
                                         ("top priorities", 0.5, 10)])
        return {"stages": res.stages, "reduction_ratio": res.reduction_ratio,
                "top": [f.id for f in res.kept]}

    def snapshot(self) -> dict:
        return {"board": self.board(), "findings": self.finding_rows(), "scorecard": self.scorecard(),
                "risk": self.risk_register(), "pipeline": self.pipeline_stages(),
                "attack_graph": self.attack_graph(), "pqc": self.pqc_report(),
                "triage": self.triage(), "structure": self.structure_summaries,
                "fleet": self.fleet_rollup()}


def _dispatch_autofuzz(root: Path):
    """Pick the deep lane by what the target ships, so one ingest covers every language with a
    synthesized-harness lane. Each lane returns a result exposing .found/.finding/.crashing_input/
    .target; we normalise the two Go/Rust/JS shapes to the C/Python AutofuzzResult surface the
    caller already handles. C/Python is the fallback (ASan/sink via the stdlib engine)."""
    import shutil
    from .harness.autofuzz import autofuzz as _c_py_autofuzz
    has = lambda *names: any((root / n).exists() for n in names)
    globx = lambda pat: any(root.rglob(pat))
    # Rust
    if has("Cargo.toml") and shutil.which("cargo"):
        from .adapters.rust_fuzz import rust_autofuzz
        return rust_autofuzz(root)
    # Go
    if has("go.mod") and shutil.which("go"):
        from .adapters.go_fuzz import go_autofuzz
        return go_autofuzz(root)
    # JavaScript / TypeScript
    if (has("package.json") or globx("*.js")) and shutil.which("node"):
        from .adapters.js_sink import js_autofuzz
        return js_autofuzz(root)
    # C / Python (stdlib engine, always available)
    return _c_py_autofuzz(root)


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


def autofuzz_session(repo_root: Path | None = None) -> Session:
    """Seed a session from targets that ship NO fuzz harness: RAKSHA synthesizes the harness, finds
    the bug, and proves the fix — the Mission Board shows deep findings with no hand-written driver."""
    repo_root = repo_root or Path(__file__).parents[1]
    s = Session()
    for name, corpus in [("c-nolibfuzzer", [b"\x01\x04abcd", b"\x02zz"]),
                         ("py-noharness", [b"10 m to ft", b"warm"])]:
        root = repo_root / "demo-targets" / name
        if root.exists():
            try:
                s.ingest_autofuzz(root, corpus=corpus)
            except Exception:  # noqa: BLE001 — a target whose toolchain is absent is simply skipped
                pass
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
