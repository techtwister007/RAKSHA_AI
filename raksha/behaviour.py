"""B12 — behavioural baseline: learn what a target touches on benign input, flag what is new.

Some defects never crash. A path traversal that reads a file outside the document root, an
injected command, an SSRF connect: no sanitizer fires, so the crash oracles are blind. What
changes is BEHAVIOUR — the files, sockets and processes the target touches.

How it works, deterministically and offline:

1. Run the target under `raksha/harness/raksha_observe.c` (LD_PRELOAD; no ptrace, so it works in
   a sealed container) on a benign corpus. Every open / connect / exec is logged. Connects and
   execs are recorded and NOT performed.
2. Normalise each event (paths under the target root become `<root>/...`, the input file becomes
   `<input>`, temp paths and digit runs are collapsed) and take the union: the **baseline**.
   Fewer than `MIN_BASELINE` benign inputs means no baseline and therefore no findings — the A2
   evidence floor, applied here.
3. Run candidate inputs (the caller's, plus a small structural probe set). An event outside the
   baseline is an anomaly only when it is security-relevant: a process spawn (CWE-78), a network
   connect (CWE-918), a read outside the target root (CWE-22) or a write outside it (CWE-73).
   Loader, locale and interpreter-stdlib reads are ignored by prefix.
4. Replay the input twice more; the same novel event must recur both times. Only then is the
   finding CONFIRMED, with the input as its reproducer. "No reproducer, no report" holds.

The lane reports PRESENCE of anomalous behaviour, never its absence: a target with no anomaly is
not thereby "safe".
"""

from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import Finding, FixSite, Frame, Reproducer, ReplayResult, utcnow

SHIM_SOURCE = Path(__file__).parent / "harness" / "raksha_observe.c"
MIN_BASELINE = 3

_IGNORE_PREFIXES = (
    "/usr/lib", "/lib", "/lib64", "/usr/lib64", "/usr/local/lib", "/etc/ld.so", "/usr/share/locale",
    "/usr/lib/locale", "/usr/share/zoneinfo", "/etc/localtime", "/dev/null", "/dev/urandom",
    "/dev/random", "/dev/tty", "/proc/self", "/sys/devices/system/cpu", "/etc/nsswitch.conf",
    "/etc/gai.conf", "/usr/share/ca-certificates", "/etc/ssl/certs/ca-certificates",
)
_STDLIB = tuple(sorted({sys.prefix, sys.base_prefix, sys.exec_prefix}))

_CWE = {"exec": "CWE-78", "connect": "CWE-918", "read-outside": "CWE-22", "write-outside": "CWE-73"}
_SEVERITY = {"exec": "critical", "connect": "high", "read-outside": "high", "write-outside": "high"}

#: Structural probes appended to / substituted into benign inputs. Each targets one behaviour class.
_PROBES = [b"../../../../../../etc/hostname", b"/etc/hostname", b"..%2f..%2f..%2fetc%2fhostname",
           b"; id", b"$(id)", b"`id`", b"| id", b"http://127.0.0.1:9/", b"127.0.0.1:9"]


@dataclass(frozen=True)
class Event:
    kind: str                       # "open" | "connect" | "exec"
    what: str                       # normalised path / address / command
    mode: str = ""                  # "r" | "w" for opens

    def category(self) -> str | None:
        """The security-relevant class of this event, or None when it is ordinary."""
        if self.kind == "exec":
            return "exec"
        if self.kind == "connect":
            return "connect"
        if self.kind == "open" and not self.what.startswith(("<root>", "<input>", "<tmp>")):
            return "write-outside" if self.mode == "w" else "read-outside"
        return None


def build_shim(cc: str = "gcc", *, out_dir: str | os.PathLike[str] | None = None) -> Path | None:
    """Compile the observer shim; None when there is no compiler (the lane then does not run)."""
    if shutil.which(cc) is None:
        return None
    base = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="raksha-observe-"))
    base.mkdir(parents=True, exist_ok=True)
    so = base / "raksha_observe.so"
    p = subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", str(so), str(SHIM_SOURCE), "-ldl"],  # raksha-own
                       capture_output=True)
    return so if p.returncode == 0 and so.exists() else None


def _normalise(kind: str, what: str, mode: str, root: str, input_path: str, ignore: tuple[str, ...]) -> Event | None:
    if kind == "open":
        path = what if what.startswith("/") else os.path.normpath(os.path.join(root, what))
        try:
            real = os.path.realpath(path)
        except (OSError, ValueError):
            real = path
        if real == input_path or path == input_path:
            return Event("open", "<input>", mode)
        if real.startswith(ignore) or path.startswith(ignore):
            return None
        if real == root or real.startswith(root + os.sep):
            rel = real[len(root):].lstrip(os.sep)
            if rel.endswith((".pyc", ".so")) or "__pycache__" in rel:
                return None
            return Event("open", "<root>/" + re.sub(r"\d+", "#", rel), mode)
        tmp = os.path.realpath(tempfile.gettempdir())
        if real.startswith(tmp + os.sep):
            return Event("open", "<tmp>/*", mode)
        return Event("open", re.sub(r"/proc/\d+", "/proc/#", real), mode)
    if kind == "connect":
        return Event("connect", what)
    if kind == "exec":
        return Event("exec", re.sub(r"\s+", " ", what.strip())[:200])
    return None


class Observer:
    """Runs one target command under the observe shim. `argv` may contain `{input}`, replaced by the
    input file's path; the input bytes are also fed on stdin, so both input styles work."""

    def __init__(self, argv: list[str], root: str | os.PathLike[str], shim: str | os.PathLike[str], *,
                 timeout: float = 10.0, env: dict[str, str] | None = None) -> None:
        self.argv = [str(a) for a in argv]
        self.root = os.path.realpath(str(root))
        self.shim = str(shim)
        self.timeout = timeout
        self.env = dict(env or os.environ)
        self.ignore = _IGNORE_PREFIXES + _STDLIB + (os.path.realpath(self.shim),)

    def run(self, data: bytes) -> set[Event]:
        from .sandbox import run_target
        # Everything the run needs lives under the target root, so the same run works inside the
        # sandbox (which mounts only the root): the shim, the input, the event log.
        with tempfile.TemporaryDirectory(prefix=".raksha-obs-", dir=self.root) as d:
            inp = os.path.join(d, "input")
            log = os.path.join(d, "events.log")
            shim = os.path.join(d, "observe.so")
            shutil.copy2(self.shim, shim)
            Path(inp).write_bytes(data)
            env = dict(self.env)
            env["RAKSHA_OBSERVE_LOG"] = log
            prior = env.get("LD_PRELOAD", "").strip()
            env["LD_PRELOAD"] = f"{shim}:{prior}" if prior else shim
            argv = [a.replace("{input}", inp) for a in self.argv]
            try:
                run_target(argv, self.root, input=data, env=env, timeout=self.timeout)
            except (subprocess.TimeoutExpired, OSError):
                pass
            events: set[Event] = set()
            if not os.path.exists(log):
                return events
            ignore = self.ignore + (os.path.realpath(d),)
            for line in Path(log).read_text(errors="replace").splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                if parts[0] == "open" and os.path.realpath(parts[1]) == os.path.realpath(inp):
                    events.add(Event("open", "<input>", parts[2] if len(parts) > 2 else "r"))
                    continue
                if parts[0] == "open" and os.path.realpath(parts[1]).startswith(os.path.realpath(d)):
                    continue
                ev = _normalise(parts[0], parts[1], parts[2] if len(parts) > 2 else "", self.root,
                                os.path.realpath(inp), ignore)
                if ev is not None:
                    events.add(ev)
            return events


@dataclass
class Baseline:
    events: set[Event] = field(default_factory=set)
    inputs: int = 0

    @property
    def sufficient(self) -> bool:
        return self.inputs >= MIN_BASELINE


def learn(observer: Observer, corpus: list[bytes]) -> Baseline:
    b = Baseline()
    for data in corpus:
        b.events |= observer.run(data)
        b.inputs += 1
    return b


def probes(corpus: list[bytes], *, budget: int = 64, seed: int = 0) -> list[bytes]:
    """Structural candidates: each probe appended to, and substituted after the last separator of,
    each benign input; deterministic for a seed, capped at `budget`."""
    out: list[bytes] = []
    for base in corpus:
        for p in _PROBES:
            out.append(base + p)
            cut = max(base.rfind(c) for c in (b":", b"=", b"/", b" "))
            if cut >= 0:
                out.append(base[:cut + 1] + p)
            out.append(p)
    seen: set[bytes] = set()
    uniq = [x for x in out if not (x in seen or seen.add(x))]
    random.Random(seed).shuffle(uniq)
    return uniq[:budget]


@dataclass
class BehaviourResult:
    findings: list[Finding] = field(default_factory=list)
    baseline: Baseline = field(default_factory=Baseline)
    candidates: int = 0
    note: str = ""


def _finding(ev: Event, cat: str, data: bytes, observer: Observer, target: str, language: str) -> Finding:
    detail = f"{ev.kind} {ev.what}" + (f" ({ev.mode})" if ev.mode else "")
    f = Finding(oracle=f"behaviour:{cat}", bug_class=_CWE[cat], language=language, target=target,
                message=(f"Behavioural anomaly: input caused {detail}, never seen across the benign "
                         f"baseline — {cat.replace('-', ' ')}"),
                severity=_SEVERITY[cat], frames=[Frame(symbol=f"{ev.kind}:{ev.what}", uri=target, line=None)])
    f.add_fix_site(FixSite(uri=target, rank=0, symbol=f"{ev.kind}:{ev.what}",
                           rationale=f"the code path that performs this {ev.kind} on attacker input"))
    f.attach_reproducer(Reproducer.from_bytes(
        data, ["raksha-observe", *observer.argv], minimised=False,
        detail=f"behavioural anomaly: {detail} (observe shim, baseline of {MIN_BASELINE}+ benign inputs)"))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=f"{cat}:{ev.what}"))
    f.confirm(reason="the novel behaviour recurred on two independent replays of the same input")
    return f


def scan(observer: Observer, corpus: list[bytes], *, candidates: list[bytes] | None = None,
         target: str = "target", language: str = "c/c++", budget: int = 64) -> BehaviourResult:
    """Learn the baseline from `corpus`, then flag candidates whose behaviour leaves it."""
    base = learn(observer, corpus)
    if not base.sufficient:
        return BehaviourResult(baseline=base, note=f"baseline needs >= {MIN_BASELINE} benign inputs; "
                                                    f"got {base.inputs} — no behavioural findings")
    cands = list(candidates or []) + probes(corpus, budget=budget)
    findings: list[Finding] = []
    reported: set[tuple[str, str]] = set()
    for data in cands:
        novel = [(ev, ev.category()) for ev in observer.run(data) - base.events]
        novel = [(ev, cat) for ev, cat in novel if cat is not None and (cat, ev.what) not in reported]
        if not novel:
            continue
        again1, again2 = observer.run(data), observer.run(data)       # agreement: it must recur
        for ev, cat in sorted(novel, key=lambda x: (x[1], x[0].what)):
            if ev in again1 and ev in again2:
                findings.append(_finding(ev, cat, data, observer, target, language))
                reported.add((cat, ev.what))
    return BehaviourResult(findings=findings, baseline=base, candidates=len(cands),
                           note=f"{len(base.events)} baseline event(s) from {base.inputs} benign input(s); "
                                f"{len(cands)} candidate(s) observed")
