"""The unified finding record — the architectural keystone.

Every finder, in every language, emits *this* record. One gate consumes it. That is the
whole "one pipeline, every language" claim, and it lives or dies here.

The record is SARIF 2.1.0 (the OASIS standard every static tool already emits) plus a
proof block carried in the standard `properties` bag under the `raksha/` namespace. We
extend SARIF rather than inventing a format, so every existing tool's output can enter
the pipeline and our output can leave it into anything that reads SARIF.

The structural invariant that makes precision real
--------------------------------------------------

    A finding without a reproducer that actually replays can NEVER leave SUSPECTED.

This is enforced *here*, mechanically, by raising `InvariantViolation` — not by
convention, not by code review, and not by a promise on a slide. That is what lets us
say "100% precision on reports, by construction": the reportable set is exactly the set
of findings whose reproducer was replayed and observed to fire the oracle.

Scoring note: this record is also the telemetry source. It timestamps every status
transition (so time-to-PoV and time-to-validated-patch are computable, not estimated)
and records which repair lane produced the fix (so "% of fixes with zero inference" is
computable). A criterion you cannot measure is a criterion you cannot score.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
PROOF_KEY = "raksha/proof"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


class InvariantViolation(Exception):
    """A transition was attempted that the data model forbids.

    Raised, never logged-and-continued. If this escapes, the pipeline has a bug; it must
    never be caught and turned into a report.
    """


class Status(str, Enum):
    """Where a finding sits in the pipeline.

    SUSPECTED    something looks wrong; NOT reportable
    CONFIRMED    a reproducer was replayed and the oracle fired; reportable
    PATCHED      a candidate fix exists but has not cleared the gate
    VERIFIED     all five gate checks passed and the PoV is dead (the bundling layer
                 is what signs it; this state attests the proof, not the signature)
    REPORT_ONLY  proven real, no fix validated; a verified vulnerability report
    """

    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    PATCHED = "PATCHED"
    VERIFIED = "VERIFIED"
    REPORT_ONLY = "REPORT_ONLY"


class GateCheck(str, Enum):
    """The five checks. All five must pass for VERIFIED. Order is cheapest-first."""

    COMPILES = "COMPILES"
    POV_DEAD = "POV_DEAD"
    DIFFERENTIAL_CORPUS = "DIFFERENTIAL_CORPUS"
    COVERAGE_HELD = "COVERAGE_HELD"
    CLEAN_REFUZZ = "CLEAN_REFUZZ"


GATE_ORDER: tuple[GateCheck, ...] = (
    GateCheck.COMPILES,
    GateCheck.POV_DEAD,
    GateCheck.DIFFERENTIAL_CORPUS,
    GateCheck.COVERAGE_HELD,
    GateCheck.CLEAN_REFUZZ,
)


class RepairLane(str, Enum):
    """Which lane produced the patch.

    Only the LLM lane spends model tokens. TEMPLATE (a known bug shape → a known fix),
    RETRIEVAL (the nearest historical fix) and MITIGATION (a provably-safe hardening floor)
    are all deterministic and cost zero inference — which is what the resource metric counts.
    """

    TEMPLATE = "TEMPLATE"
    RETRIEVAL = "RETRIEVAL"
    LLM = "LLM"
    MITIGATION = "MITIGATION"


#: The only lane that spends model tokens. Everything else is zero-inference. The resource
#: metric ("% fixes at zero inference", "inference attempts") is defined against this set, so
#: a retrieval or mitigation fix is never miscounted as model spend.
INFERENCE_LANES: frozenset[RepairLane] = frozenset({RepairLane.LLM})


class RoeLevel(str, Enum):
    """Rules of Engagement — the authority level in force for this finding's asset."""

    R0 = "R0"  # Observe        — scan only
    R1 = "R1"  # Recommend      — prove and draft, never apply
    R2 = "R2"  # Act w/ approval— stage a verified patch, deploy after sign-off
    R3 = "R3"  # Act autonomous — deploy verified fixes directly


@dataclass(frozen=True)
class Frame:
    """One stack frame, normalised across languages."""

    symbol: str
    uri: str | None = None
    line: int | None = None
    column: int | None = None

    def normalised(self) -> str:
        """Symbol + basename only — stable across build paths, for the dedup key."""
        base = self.uri.rsplit("/", 1)[-1] if self.uri else ""
        return f"{self.symbol}@{base}"


#: How a finding's evidence is established. Both are replayable and both are honest; they are
#: kept distinct so the risk register can rank exploit-proven findings above match-proven ones,
#: and so we never *claim* an exploit we do not have.
EXPLOIT_REPLAY = "exploit-replay"          # a crafted input replays and an oracle aborts
DETERMINISTIC_MATCH = "deterministic-match"  # a detector deterministically re-matches (dep CVE, secret)

#: Frames from language runtimes and fuzzing harnesses: never the bug's own code, so never its identity.
RUNTIME_FRAME_PREFIXES = (
    "java.", "javax.", "jdk.", "sun.", "com.sun.", "com.code_intelligence.jazzer", "kotlin.",
    "__libc_", "__interceptor_", "__asan_", "__sanitizer", "LLVMFuzzer", "fuzzer::",
)

#: Reproducers up to this size are carried in the record and shipped in the evidence bundle.
MAX_REPRO_BYTES = 1_000_000
#: A reproducer larger than MAX_REPRO_BYTES is kept zlib-compressed up to this compressed size, so a
#: large proof input still ships and replays (D3) rather than being silently dropped.
MAX_REPRO_COMPRESSED_BYTES = 4_000_000


@dataclass(frozen=True)
class Reproducer:
    """The evidence that a finding is real, and how to replay it.

    Without one of these, a finding is stuck at SUSPECTED forever. This is the object the
    precision claim rests on. `kind` records what sort of evidence it is: an exploit that replays,
    or a deterministic detector that re-matches. The build-free lanes produce the latter — a
    dependency version matched against the offline vuln DB, or a secret still present at a
    location — which is proof, but not an exploit, and the record says so.
    """

    artifact_sha256: str
    replay_cmd: list[str]
    artifact_path: str | None = None
    minimised: bool = False
    size_bytes: int | None = None
    kind: str = EXPLOIT_REPLAY
    detail: str | None = None  # e.g. "pkg@1.2.3 vulnerable per OSV GHSA-xxxx (fixed in 1.2.4)"
    #: The reproducer bytes themselves, kept (up to MAX_REPRO_BYTES) so the evidence bundle can ship
    #: them and a replay can actually run. Never part of equality or the printed record.
    data: bytes | None = field(default=None, repr=False, compare=False)
    #: D3: `data` holds zlib-compressed bytes (a large reproducer kept shippable). `raw_bytes()`
    #: transparently decompresses. D6: `purged` records that the bytes were deliberately removed
    #: from this node by policy, the content hash and replay command kept so the record stays valid.
    compressed: bool = field(default=False, compare=False)
    purged: bool = field(default=False, compare=False)

    def raw_bytes(self) -> bytes | None:
        """The real reproducer bytes, decompressing if stored compressed. None when absent/purged."""
        if self.data is None:
            return None
        if self.compressed:
            import zlib
            return zlib.decompress(self.data)
        return self.data

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        replay_cmd: list[str],
        *,
        artifact_path: str | None = None,
        minimised: bool = False,
        kind: str = EXPLOIT_REPLAY,
        detail: str | None = None,
    ) -> "Reproducer":
        kept, compressed = bytes(data), False
        if len(data) > MAX_REPRO_BYTES:
            import zlib
            packed = zlib.compress(bytes(data), 9)
            kept, compressed = (packed, True) if len(packed) <= MAX_REPRO_COMPRESSED_BYTES else (None, False)
        return cls(
            artifact_sha256=hashlib.sha256(data).hexdigest(),
            replay_cmd=list(replay_cmd),
            artifact_path=artifact_path,
            minimised=minimised,
            size_bytes=len(data),
            kind=kind,
            detail=detail,
            data=kept,
            compressed=compressed,
        )


@dataclass(frozen=True)
class ReplayResult:
    """What happened when the reproducer was actually run.

    `oracle_fired` is the single bit the invariant turns on. Before the patch it must be
    True for CONFIRMED; after the patch it must be False for VERIFIED.
    """

    oracle_fired: bool
    at: datetime
    abort_signature: str | None = None
    exit_code: int | None = None
    stderr_excerpt: str | None = None


@dataclass(frozen=True)
class FixSite:
    """A candidate place to fix, as ranked by deterministic localisation.

    The model is handed these; it does not search for them. `rank` 0 is best.
    """

    uri: str
    rank: int
    start_line: int | None = None
    symbol: str | None = None
    rationale: str | None = None


@dataclass(frozen=True)
class GateResult:
    check: GateCheck
    passed: bool
    at: datetime
    detail: str | None = None
    quarantined_inputs: int = 0


@dataclass(frozen=True)
class Signature:
    key_id: str
    signer: str
    signature: str
    at: datetime


@dataclass(frozen=True)
class Transition:
    """One status change, timestamped. This is the Speed criterion's raw data.

    `at` is wall-clock, for display and the record. `mono` is a monotonic-clock reading taken at the
    same instant, used for *durations*: an air-gapped node's real-time clock can step backwards
    (no NTP), which would make a wall-clock delta negative. The monotonic delta cannot. `mono` is
    None for a transition reconstructed from a serialised history (no monotonic value was stored),
    and the duration helpers then fall back to a wall-clock delta clamped at zero.
    """

    from_status: Status | None
    to_status: Status
    at: datetime
    reason: str | None = None
    mono: float | None = None


# Legal status transitions. Everything absent here is forbidden.
_ALLOWED: dict[Status, frozenset[Status]] = {
    Status.SUSPECTED: frozenset({Status.CONFIRMED}),
    Status.CONFIRMED: frozenset({Status.PATCHED, Status.REPORT_ONLY}),
    # A failed gate sends the finding back for another repair round (cap enforced by
    # the caller, ~3 rounds).
    Status.PATCHED: frozenset({Status.VERIFIED, Status.CONFIRMED, Status.REPORT_ONLY}),
    Status.VERIFIED: frozenset(),
    Status.REPORT_ONLY: frozenset(),
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


@dataclass
class Finding:
    """One finding, moving through the five states of the status machine.

    Construct it in SUSPECTED (the only legal birth state — enforced in `__post_init__`),
    attach evidence, then drive it with the transition methods. The methods refuse illegal
    moves, and the constructor refuses a forged birth state.
    """

    oracle: str
    bug_class: str
    language: str
    target: str
    message: str
    severity: str = "medium"
    frames: list[Frame] = field(default_factory=list)
    abort_signature: str | None = None
    raw_excerpt: str | None = None
    #: Where the fuzzer said it wrote the crashing input. A *hint* only -- it is
    #: not a reproducer until the pipeline hashes it and replays it.
    artifact_hint: str | None = None

    reproducer: Reproducer | None = None
    replay_before: ReplayResult | None = None
    replay_after: ReplayResult | None = None

    fix_site_set: list[FixSite] = field(default_factory=list)
    patch_diff: str | None = None
    #: The regression test the model wrote. Set ONLY after it has been shown to fail on the
    #: vulnerable build and pass on the patched one; an unverified test never enters here.
    regression_test: str | None = None
    #: Findings that were merged into this one by lane cross-confirmation (their ids).
    merged_from: list[str] = field(default_factory=list)
    repair_lane: RepairLane | None = None
    #: Every lane tried, in order. The last entry is `repair_lane`. Kept so that
    #: inference spent on a candidate the gate then rejected stays visible in the
    #: resource metric instead of disappearing with the failed patch.
    lane_history: list[RepairLane] = field(default_factory=list)
    repair_rounds: int = 0

    #: Gate results for the CURRENT candidate patch only. Cleared on every new
    #: repair round, so a candidate can never inherit another candidate's passes.
    gate: dict[GateCheck, GateResult] = field(default_factory=dict)
    #: Every gate result ever recorded, across all repair rounds. Append-only.
    #: This is what the scorecard measures, so rejected candidates stay counted.
    gate_history: list[GateResult] = field(default_factory=list)
    roe_level: RoeLevel = RoeLevel.R1
    signatures: list[Signature] = field(default_factory=list)

    model_version: str | None = None
    prompt_version: str | None = None
    #: Candidate diffs refused by patch hygiene before any gate run, with the reason. Kept so
    #: inference spent on a candidate we would not even apply stays visible.
    rejected_candidates: list[str] = field(default_factory=list)
    # ---- assurance layers (each written by its own stage; None/empty = that stage did not run) ----
    #: Structural evidence from the code-property-graph lane: the source→sink path it found.
    structure: dict | None = None
    #: Fused confidence over independent evidence channels (exploit, structural, votes, ...).
    evidence_score: dict | None = None
    #: Votes from the model parliament on this finding, and the measured disagreement.
    parliament: dict | None = None
    #: The independent red-team round(s) run against the VERIFIED patch, and their outcome.
    red_team: dict | None = None
    #: Every candidate that cleared the gate, with its cost axes; the chosen one is `patch_diff`.
    frontier: list[dict] = field(default_factory=list)
    #: Patched-vs-baseline wall-time ratio over the differential corpus (1.0 = unchanged).
    perf_delta: float | None = None
    #: Compensating controls proposed when (or in addition to) a code patch: isolate, restrict, ...
    remediation: list[dict] = field(default_factory=list)
    #: Attack chains (ids) this finding is a link of.
    chain_ids: list[str] = field(default_factory=list)
    #: Mission-impact tier of the asset this finding sits on, from the asset registry.
    mission_impact: str | None = None
    #: For a dependency match: whether the codebase imports the vulnerable package —
    #: "imported" / "not-imported" / "unknown" (no source for that language was seen). Proven
    #: present is not proven reached; the risk register ranks accordingly.
    reachability: str | None = None
    #: D4: resources this finding's repair consumed, measured (getrusage deltas) around the gate.
    cpu_seconds: float | None = None
    peak_rss_kb: int | None = None

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=utcnow)
    #: Monotonic-clock reading at construction, paired with created_at, so durations are immune to
    #: real-time-clock steps. Not serialised; a reconstructed finding falls back to wall-clock.
    created_mono: float = field(default_factory=time.monotonic, repr=False, compare=False)
    history: list[Transition] = field(default_factory=list)
    _status: Status = Status.SUSPECTED

    def __post_init__(self) -> None:
        # Own the history list: dataclasses.replace() hands the same list to the copy, and a shared
        # history would let one record's transitions rewrite another's.
        self.history = list(self.history)
        if self.history:
            self._check_reconstructed()
            return
        # A freshly constructed finding is born SUSPECTED and nothing else. Every other state
        # is reachable only through the transition methods, which enforce "no reproducer, no
        # report". Passing `_status=` to the constructor to skip that is a bypass this guard forbids.
        if self._status is not Status.SUSPECTED:
            raise InvariantViolation(
                f"finding {self.id}: a finding's only legal birth state is SUSPECTED, not "
                f"{self._status.value}. Reach any other state through confirm()/verify(), "
                "which enforce the precision invariant."
            )
        self.history.append(
            Transition(None, Status.SUSPECTED, self.created_at, "created", mono=self.created_mono)
        )

    def _check_reconstructed(self) -> None:
        """A record rebuilt from its own history (e.g. deserialised) must be one the transition
        methods could have produced: born SUSPECTED, every step legal, ending at the declared
        status, and carrying the evidence that status requires. Anything else is a forged record."""
        def forged(why: str) -> InvariantViolation:
            return InvariantViolation(f"finding {self.id}: reconstructed record refused — {why}")

        first = self.history[0]
        if first.from_status is not None or first.to_status is not Status.SUSPECTED:
            raise forged("history does not begin with a SUSPECTED birth")
        for prev, step in zip(self.history, self.history[1:]):
            if step.from_status is not prev.to_status or step.to_status not in _ALLOWED[prev.to_status]:
                raise forged(f"illegal step {prev.to_status.value} -> {step.to_status.value}")
        if self.history[-1].to_status is not self._status:
            raise forged(f"declared status {self._status.value} does not match its history "
                         f"(ends at {self.history[-1].to_status.value})")
        if self._status is not Status.SUSPECTED and not (
                self.reproducer is not None and self.replay_before is not None
                and self.replay_before.oracle_fired):
            raise forged(f"{self._status.value} without a reproducer that replayed and fired")
        if self._status is Status.VERIFIED and not (
                self.gate_passed and self.replay_after is not None and not self.replay_after.oracle_fired):
            raise forged("VERIFIED without all five gate checks passed and the PoV dead")

    # ---------------------------------------------------------------- status

    @property
    def status(self) -> Status:
        return self._status

    def _transition(self, to: Status, reason: str | None = None) -> None:
        if to not in _ALLOWED[self._status]:
            raise InvariantViolation(
                f"illegal transition {self._status.value} -> {to.value} "
                f"(finding {self.id})"
            )
        at = utcnow()
        self.history.append(Transition(self._status, to, at, reason, mono=time.monotonic()))
        self._status = to

    # ------------------------------------------------------------- evidence

    def purge_reproducer(self) -> bool:
        """D6: remove the stored reproducer BYTES from this node (they are exploit material at
        rest), keeping the content hash, size and replay command so the signed record stays valid
        and a judge can still see what the proof was. Returns True when bytes were present to purge."""
        import dataclasses as _dc
        if self.reproducer is None or self.reproducer.data is None:
            return False
        self.reproducer = _dc.replace(self.reproducer, data=None, purged=True)
        return True

    def attach_reproducer(self, reproducer: Reproducer) -> None:
        self.reproducer = reproducer

    def record_replay_before(self, result: ReplayResult) -> None:
        """Record the result of replaying the reproducer against the *unpatched* build."""
        self.replay_before = result
        if result.abort_signature and not self.abort_signature:
            self.abort_signature = result.abort_signature

    def record_replay_after(self, result: ReplayResult) -> None:
        """Record the result of replaying the reproducer against the *patched* build."""
        self.replay_after = result

    def add_fix_site(self, site: FixSite) -> None:
        self.fix_site_set.append(site)
        self.fix_site_set.sort(key=lambda s: s.rank)

    def record_gate(
        self,
        check: GateCheck,
        passed: bool,
        *,
        detail: str | None = None,
        quarantined_inputs: int = 0,
    ) -> GateResult:
        result = GateResult(
            check=check,
            passed=passed,
            at=utcnow(),
            detail=detail,
            quarantined_inputs=quarantined_inputs,
        )
        self.gate[check] = result
        self.gate_history.append(result)
        return result

    def add_signature(self, signature: Signature) -> None:
        self.signatures.append(signature)

    # ---------------------------------------------------------- transitions

    def confirm(self, reason: str | None = None) -> None:
        """SUSPECTED -> CONFIRMED. The precision invariant lives in this method.

        Refuses unless a reproducer exists AND replaying it was observed to fire the
        oracle. A static-only finding therefore cannot be reported, ever, until someone
        attaches a reproducer that actually replays.
        """
        if self.reproducer is None:
            raise InvariantViolation(
                f"cannot confirm finding {self.id}: no reproducer. "
                "No reproducer, no report — a finding without one stays SUSPECTED."
            )
        if self.replay_before is None:
            raise InvariantViolation(
                f"cannot confirm finding {self.id}: reproducer was never replayed. "
                "Possessing an artifact is not evidence; replaying it is."
            )
        if not self.replay_before.oracle_fired:
            raise InvariantViolation(
                f"cannot confirm finding {self.id}: replay did not fire the oracle. "
                "The finding is not reproducible and must not be reported."
            )
        self._transition(Status.CONFIRMED, reason or "reproducer replayed, oracle fired")

    def mark_patched(
        self,
        patch_diff: str,
        lane: RepairLane,
        *,
        model_version: str | None = None,
        prompt_version: str | None = None,
    ) -> None:
        """CONFIRMED -> PATCHED. A candidate fix exists; it has proven nothing yet.

        Clears the gate. Every candidate must earn all five checks on its own: a
        round-2 patch that inherited round-1's passes would reach VERIFIED having
        been tested only by the check that rejected its predecessor. The history is
        kept, so nothing is forgotten -- only the current verdict is reset.
        """
        if not patch_diff.strip():
            raise InvariantViolation(
                f"cannot patch finding {self.id}: empty diff"
            )
        self.patch_diff = patch_diff
        self.repair_lane = lane
        self.lane_history.append(lane)
        self.gate = {}
        self.repair_rounds += 1
        if model_version:
            self.model_version = model_version
        if prompt_version:
            self.prompt_version = prompt_version
        self._transition(Status.PATCHED, f"candidate patch from {lane.value} lane")

    def verify(self, reason: str | None = None) -> None:
        """PATCHED -> VERIFIED. Refuses unless all five checks passed and the PoV is dead.

        This is the only door a patch can leave through. Nothing unproven ships.
        """
        missing = [c.value for c in GATE_ORDER if c not in self.gate]
        if missing:
            raise InvariantViolation(
                f"cannot verify finding {self.id}: gate checks not run: "
                f"{', '.join(missing)}"
            )
        failed = [c.value for c in GATE_ORDER if not self.gate[c].passed]
        if failed:
            raise InvariantViolation(
                f"cannot verify finding {self.id}: gate checks failed: "
                f"{', '.join(failed)}"
            )
        if self.replay_after is None:
            raise InvariantViolation(
                f"cannot verify finding {self.id}: the patched build was never "
                "re-attacked; POV_DEAD has no evidence behind it."
            )
        if self.replay_after.oracle_fired:
            raise InvariantViolation(
                f"cannot verify finding {self.id}: the original attack still fires "
                "the oracle on the patched build."
            )
        self._transition(Status.VERIFIED, reason or "all five gate checks passed")

    def gate_failed(self, reason: str) -> None:
        """PATCHED -> CONFIRMED. The gate refused this patch; go round again."""
        self._transition(Status.CONFIRMED, f"gate rejected patch: {reason}")

    def report_only(self, reason: str) -> None:
        """-> REPORT_ONLY. A proven vulnerability, no proven fix. Never a guess.

        Only reachable from CONFIRMED or PATCHED, which means it is only reachable for a
        finding that was *proven real* first. We never issue an unproven report.
        """
        self._transition(Status.REPORT_ONLY, reason)

    # ------------------------------------------------------------- queries

    @property
    def is_reportable(self) -> bool:
        """True only for findings backed by a replayed reproducer.

        The Precision metric is `len([f for f in findings if f.is_reportable])` over the
        set we actually report — 100% by construction, because nothing else is reported.
        """
        return self._status is not Status.SUSPECTED

    @property
    def gate_passed(self) -> bool:
        return all(c in self.gate and self.gate[c].passed for c in GATE_ORDER)

    @property
    def zero_inference(self) -> bool:
        """True if the fix cost no model tokens. Feeds the resource-utilisation metric.

        Zero-inference is every lane except LLM: template, retrieval and mitigation are all
        deterministic. Counting only TEMPLATE here understated the resource advantage and made
        the headline "% fixes at zero inference" wrong against its own definition.
        """
        return self.repair_lane is not None and self.repair_lane not in INFERENCE_LANES

    def dedup_key(self, depth: int = 3) -> str:
        """The identity used by the Normalise stage to collapse duplicate records.

        Two kinds of finding, two notions of "the same bug":

        - A deterministic match (a dependency CVE, a secret, a spec exposure) IS its location: the
          same advisory in two services, or two passwords in one file, are separate findings. Keyed
          on oracle, class, advisory/rule, full path, line and symbol.
        - A crash is keyed on its stack, so 800 inputs reaching one bug collapse to one record. The
          top frame carries its line (one function can hold two distinct overflows) and runtime /
          fuzzer frames are skipped (two command injections both pass through
          ProcessBuilder.start, but are different bugs in different callers).
        """
        if self.reproducer is not None and self.reproducer.kind == DETERMINISTIC_MATCH:
            loc = self.frames[0] if self.frames else Frame(symbol="")
            material = "|".join(str(x) for x in (
                self.oracle, self.bug_class, self.abort_signature or "", loc.uri or self.target,
                loc.line or "", loc.symbol))
        else:
            own = [f for f in self.frames if not f.symbol.startswith(RUNTIME_FRAME_PREFIXES)] or self.frames
            top = [own[0].normalised() + f":{own[0].line or ''}"] if own else []
            top += [f.normalised() for f in own[1:depth]]
            material = "|".join([self.bug_class, *top])
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    def _transition_at(self, status: Status) -> datetime | None:
        for t in self.history:
            if t.to_status is status:
                return t.at
        return None

    def _transition_obj(self, status: Status) -> "Transition | None":
        for t in self.history:
            if t.to_status is status:
                return t
        return None

    def _elapsed_to(self, status: Status) -> float | None:
        """Seconds from creation to a transition, measured on the monotonic clock when both ends
        carry a monotonic reading; otherwise a wall-clock delta clamped at zero (a clock step must
        never produce a negative duration)."""
        t = self._transition_obj(status)
        if t is None:
            return None
        if t.mono is not None and self.created_mono is not None:
            return max(0.0, t.mono - self.created_mono)
        return max(0.0, (t.at - self.created_at).total_seconds())

    @property
    def time_to_pov_seconds(self) -> float | None:
        """Created -> CONFIRMED. The Speed criterion's first metric (monotonic)."""
        return self._elapsed_to(Status.CONFIRMED)

    @property
    def time_to_patch_seconds(self) -> float | None:
        """Created -> VERIFIED. The Speed criterion's second metric (monotonic)."""
        return self._elapsed_to(Status.VERIFIED)

    # ---------------------------------------------------------------- SARIF

    def proof_block(self) -> dict[str, Any]:
        """The `raksha/proof` property bag — everything SARIF has no field for."""
        return {
            "id": self.id,
            "oracle": self.oracle,
            "bug_class": self.bug_class,
            "language": self.language,
            "target": self.target,
            "status": self._status.value,
            "severity": self.severity,
            "abort_signature": self.abort_signature,
            "dedup_key": self.dedup_key(),
            "artifact_hint": self.artifact_hint,
            "reproducer": (
                {
                    "artifact_sha256": self.reproducer.artifact_sha256,
                    "artifact_path": self.reproducer.artifact_path,
                    "replay_cmd": self.reproducer.replay_cmd,
                    "minimised": self.reproducer.minimised,
                    "size_bytes": self.reproducer.size_bytes,
                    "kind": self.reproducer.kind,
                    "detail": self.reproducer.detail,
                }
                if self.reproducer
                else None
            ),
            "replay_before": (
                {
                    "oracle_fired": self.replay_before.oracle_fired,
                    "abort_signature": self.replay_before.abort_signature,
                    "exit_code": self.replay_before.exit_code,
                    "at": _iso(self.replay_before.at),
                }
                if self.replay_before
                else None
            ),
            "replay_after": (
                {
                    "oracle_fired": self.replay_after.oracle_fired,
                    "abort_signature": self.replay_after.abort_signature,
                    "exit_code": self.replay_after.exit_code,
                    "at": _iso(self.replay_after.at),
                }
                if self.replay_after
                else None
            ),
            "fix_site_set": [
                {
                    "uri": s.uri,
                    "rank": s.rank,
                    "start_line": s.start_line,
                    "symbol": s.symbol,
                    "rationale": s.rationale,
                }
                for s in self.fix_site_set
            ],
            "regression_test_verified": self.regression_test is not None,
            "merged_from": list(self.merged_from),
            "repair": {
                "lane": self.repair_lane.value if self.repair_lane else None,
                "lane_history": [l.value for l in self.lane_history],
                "rounds": self.repair_rounds,
                "zero_inference": self.zero_inference,
                "model_version": self.model_version,
                "prompt_version": self.prompt_version,
                "rejected_before_gate": list(self.rejected_candidates),
            },
            "reachability": self.reachability,
            "resource": {"cpu_seconds": self.cpu_seconds, "peak_rss_kb": self.peak_rss_kb},
            "assurance": {
                "structure": self.structure,
                "evidence_score": self.evidence_score,
                "parliament": self.parliament,
                "red_team": self.red_team,
                "frontier": list(self.frontier),
                "perf_delta": self.perf_delta,
                "remediation": list(self.remediation),
                "chain_ids": list(self.chain_ids),
                "mission_impact": self.mission_impact,
            },
            "gate": {
                c.value: (
                    {
                        "passed": self.gate[c].passed,
                        "detail": self.gate[c].detail,
                        "quarantined_inputs": self.gate[c].quarantined_inputs,
                        "at": _iso(self.gate[c].at),
                    }
                    if c in self.gate
                    else None
                )
                for c in GATE_ORDER
            },
            "gate_passed": self.gate_passed,
            "roe_level": self.roe_level.value,
            "signatures": [
                {
                    "key_id": s.key_id,
                    "signer": s.signer,
                    "signature": s.signature,
                    "at": _iso(s.at),
                }
                for s in self.signatures
            ],
            "metrics": {
                "created_at": _iso(self.created_at),
                "time_to_pov_seconds": self.time_to_pov_seconds,
                "time_to_patch_seconds": self.time_to_patch_seconds,
            },
            "history": [
                {
                    "from": t.from_status.value if t.from_status else None,
                    "to": t.to_status.value,
                    "at": _iso(t.at),
                    "reason": t.reason,
                }
                for t in self.history
            ],
        }

    def to_sarif_result(self) -> dict[str, Any]:
        """One SARIF `result` object, with the proof block in `properties`."""
        locations = []
        for f in self.frames:
            if not f.uri:
                continue
            region: dict[str, Any] = {}
            if f.line is not None and f.line >= 1:
                region["startLine"] = f.line
            if f.column is not None and f.column >= 1:  # SARIF columns are 1-based
                region["startColumn"] = f.column
            loc: dict[str, Any] = {
                "physicalLocation": {"artifactLocation": {"uri": f.uri}}
            }
            if region:
                loc["physicalLocation"]["region"] = region
            if f.symbol:
                loc["logicalLocations"] = [{"name": f.symbol}]
            locations.append(loc)

        return {
            "ruleId": self.bug_class,
            "level": _SARIF_LEVEL.get(self.severity.lower(), "warning"),
            "message": {"text": self.message},
            "locations": locations,
            "partialFingerprints": {"raksha/dedupKey": self.dedup_key()},
            "properties": {PROOF_KEY: self.proof_block()},
        }


def to_sarif_log(findings: Iterable[Finding], *, tool_version: str = "0.1.0") -> dict[str, Any]:
    """Emit a SARIF 2.1.0 log for a set of findings.

    Valid SARIF, so any SARIF consumer reads our output; the proof block rides along in
    `properties` where a standard consumer will simply ignore it.
    """
    findings = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(
            f.bug_class,
            {"id": f.bug_class, "shortDescription": {"text": f.bug_class}},
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RAKSHA AI",
                        "version": tool_version,
                        "informationUri": "https://github.com/techtwister007/RAKSHA_AI",
                        "rules": list(rules.values()),
                    }
                },
                "results": [f.to_sarif_result() for f in findings],
            }
        ],
    }


def dedup(findings: Iterable[Finding]) -> list[Finding]:
    """Normalise stage: collapse findings that share a dedup key, keeping the first."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.dedup_key(), f)
    return list(seen.values())


def reportable(findings: Iterable[Finding]) -> list[Finding]:
    """The only set that may ever be shown to a human or counted in a score."""
    return [f for f in findings if f.is_reportable]
