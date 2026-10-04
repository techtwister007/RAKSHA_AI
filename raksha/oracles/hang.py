"""Hang / resource-exhaustion oracle — language-agnostic.

Some defects are not a crash and not a sink: the program simply never comes back. A run
that exceeds its time budget is a denial-of-service defect (CWE-400), and when the code is
stuck inside a regular-expression routine it is catastrophic backtracking / ReDoS
(CWE-1333). This oracle turns that "did not return in time" signal into the unified record
so the same five-check gate proves a bound/guard fix the way it proves a bounds check.

Its input is not a sanitizer report. It is a small structured signal the runner emits — the
run's wall-time, the configured budget, whether the run was killed on timeout, and the last
frames seen. For a native target the runner is "run under a timeout" and the frames are
whatever the harness captured; for an in-process Python target the frames come from a
lightweight periodic sampler of the interpreter stack (``sys._current_frames``), taken while
the call is still running.

Public surface:

* ``detect_hang(run_seconds, budget_seconds, frames, *, killed=True, ...) -> Finding | None``
  — the core decision. Returns a finding when the run overran its budget (or was killed on
  timeout), and ``None`` for a benign slow-but-finite run that returned inside the budget.
* ``sample_python_stack`` / ``run_under_budget`` — the in-process Python sampler and a small
  budgeted runner that produces a ``HangSignal`` using it.
* ``HangOracle`` — the plugin wrapper: parses the ``=== RAKSHA HANG ===`` signal text and
  delegates to ``detect_hang``. It claims only that banner, so it never fires on another
  oracle's output or on a clean run.

Heuristics, stated plainly:

* "Overran the budget" is ``killed`` OR ``run_seconds >= budget_seconds``. A finite run that
  returned inside the budget is never a hang, however slow — slowness is not a defect, a
  non-return is.
* "ReDoS vs generic DoS" is decided by whether any of the top frames is a regular-expression
  routine (the ``re`` / ``sre`` module, path-independent markers). A regex engine the sampler
  did not catch on the stack degrades to the generic CWE-400 rather than losing the finding.
"""

from __future__ import annotations

import re
import sys
import threading
import time
from dataclasses import dataclass, field

from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

CWE_RESOURCE_EXHAUSTION = "CWE-400"
CWE_REDOS = "CWE-1333"

_SELF_FILE = __file__
_SAMPLER_EXCLUDE = (_SELF_FILE, "threading.py")

#: Path-independent markers of a regular-expression routine, so a stack stuck in the engine is
#: recognised as ReDoS whether the stdlib lives under /usr/lib, a venv or a conda prefix.
_REGEX_MARKERS = ("/re/__init__.py", "/re.py", "sre_compile.py", "sre_parse.py",
                  "/_sre", "sre_", "/regex/")

# ---- the structured signal the runner emits, and the oracle parses -----------------------------

_HANG_BANNER = re.compile(r"===\s*RAKSHA HANG\s*===")
_RUN = re.compile(r"run_seconds:\s*(?P<v>[\d.]+)")
_BUDGET = re.compile(r"budget_seconds:\s*(?P<v>[\d.]+)")
_KILLED = re.compile(r"killed:\s*(?P<v>true|false|yes|no|1|0)", re.IGNORECASE)
# "  #0 scan /path/redos.py:20"  — the frame lines carried in the signal.
_SIGNAL_FRAME = re.compile(r"^\s*#\d+\s+(?P<symbol>\S+)\s+(?P<uri>[^\s:]+):(?P<line>\d+)")
# A CPython / faulthandler traceback frame: 'File "<uri>", line <N> in <sym>' (faulthandler omits
# the comma before `in`, a normal traceback keeps it). faulthandler prints most-recent-call-first,
# so these parse innermost-first, the order the rest of the pipeline expects.
_TB_FRAME = re.compile(r'File\s+"(?P<uri>[^"]+)",?\s+line\s+(?P<line>\d+),?\s+in\s+(?P<symbol>\S+)')


@dataclass
class HangSignal:
    """What a budgeted run observed: how long it ran, its budget, whether it overran, and the
    last stack sample taken while it was still running."""

    run_seconds: float
    budget_seconds: float
    killed: bool
    frames: list[Frame] = field(default_factory=list)

    def as_text(self, *, note: str = "") -> str:
        """Render the ``=== RAKSHA HANG ===`` signal text the oracle parses."""
        lines = ["=== RAKSHA HANG ===",
                 f"run_seconds: {self.run_seconds:.4f}",
                 f"budget_seconds: {self.budget_seconds:.4f}",
                 f"killed: {'true' if self.killed else 'false'}"]
        if note:
            lines.append(f"note: {note}")
        lines.append("frames:")
        for i, fr in enumerate(self.frames):
            lines.append(f"  #{i} {fr.symbol} {fr.uri or '?'}:{fr.line or 0}")
        lines.append("=== END HANG ===")
        return "\n".join(lines) + "\n"


def frames_from_traceback(text: str) -> list[Frame]:
    """Parse the frames out of a faulthandler dump (or a CPython traceback), innermost first.

    This is the robust "last frames seen" source for a Python target that is wedged inside a C
    routine (a backtracking regex) where ``sys._current_frames`` cannot preempt the held GIL:
    ``faulthandler.dump_traceback_later`` runs in its own non-Python thread and dumps the stack
    anyway. We read that dump here.
    """
    return [
        Frame(symbol=m.group("symbol"), uri=m.group("uri"), line=int(m.group("line")))
        for line in text.splitlines()
        if (m := _TB_FRAME.search(line))
    ]


def _is_regex_frame(frame: Frame) -> bool:
    hay = f"{frame.uri or ''} {frame.symbol}".lower()
    return any(m in hay for m in _REGEX_MARKERS)


def detect_hang(
    run_seconds: float,
    budget_seconds: float,
    frames: list[Frame],
    *,
    killed: bool = True,
    target: str = "<target>",
    language: str = "python",
) -> Finding | None:
    """Turn a budgeted run into a SUSPECTED hang finding, or ``None`` for a benign finite run.

    A hang is a non-return: ``killed`` on timeout, or ``run_seconds`` reaching the budget. A run
    that returned inside the budget is never a hang. ReDoS (CWE-1333) is distinguished from
    generic resource exhaustion (CWE-400) by a regular-expression frame among the top of stack.
    """
    overran = bool(killed) or (budget_seconds is not None and run_seconds >= budget_seconds)
    if not overran:
        return None
    frames = list(frames)
    redos = any(_is_regex_frame(f) for f in frames[:6])
    bug_class = CWE_REDOS if redos else CWE_RESOURCE_EXHAUSTION
    detail = (" — catastrophic backtracking in a regular expression"
              if redos else " — unbounded work on this input")
    message = (f"hang: no return within {budget_seconds:.3g}s budget "
               f"(ran {run_seconds:.3g}s){detail}")
    finding = Finding(
        oracle="hang:timeout",
        bug_class=bug_class,
        language=language,
        target=target,
        message=message,
        severity="high",
        frames=frames,
        abort_signature=abort_signature(bug_class, frames),
        raw_excerpt=excerpt(message),
    )
    seed_fix_site(finding, frames)
    return finding


# ---- in-process Python sampler -----------------------------------------------------------------


def sample_python_stack(thread_id: int, *, exclude: tuple[str, ...] = _SAMPLER_EXCLUDE) -> list[Frame]:
    """A snapshot of a thread's Python stack, innermost frame first.

    Uses ``sys._current_frames`` — the only stdlib way to read another thread's stack — and drops
    this module's own and threading's frames so the sample is the target's code. Returns ``[]`` if
    the thread is not currently in the table (it finished, or has not started).
    """
    top = sys._current_frames().get(thread_id)
    frames: list[Frame] = []
    f = top
    while f is not None:
        fn = f.f_code.co_filename
        if not any(x in fn for x in exclude):
            frames.append(Frame(symbol=f.f_code.co_name, uri=fn, line=f.f_lineno))
        f = f.f_back
    return frames


def run_under_budget(fn, *, budget_seconds: float, sample_interval: float = 0.02,
                     join_timeout: float = 30.0) -> HangSignal:
    """Run ``fn()`` in a worker thread, sampling its stack, and report whether it overran.

    Returns a ``HangSignal``. When ``fn`` returns inside the budget the signal says so
    (``killed=False``) and the worker is joined. When it does not, the last stack sample is kept
    and ``killed=True`` — the worker is a daemon, so it cannot wedge the process. There is no
    portable way to kill a thread stuck in a C routine (a backtracking regex), which is exactly
    why the deployed runner for a non-return uses a killable subprocess timeout; this in-process
    runner exists for the Python sampler path and for tests.
    """
    state: dict[str, object] = {}

    def worker() -> None:
        try:
            state["value"] = fn()
        except BaseException as exc:          # noqa: BLE001 - recorded, not swallowed
            state["error"] = exc

    t = threading.Thread(target=worker, daemon=True)
    start = time.monotonic()
    t.start()
    last_sample: list[Frame] = []
    while True:
        elapsed = time.monotonic() - start
        if not t.is_alive():
            break
        if elapsed >= budget_seconds:
            last_sample = sample_python_stack(t.ident) or last_sample
            break
        sample = sample_python_stack(t.ident)
        if sample:
            last_sample = sample
        time.sleep(sample_interval)
    killed = t.is_alive()
    if not killed:
        t.join(timeout=join_timeout)
    run_seconds = time.monotonic() - start
    return HangSignal(run_seconds=run_seconds, budget_seconds=budget_seconds,
                      killed=killed, frames=last_sample)


# ---- the plugin wrapper ------------------------------------------------------------------------


class HangOracle(Oracle):
    name = "hang"
    language = "any"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        if not _HANG_BANNER.search(raw):
            return []
        run = _RUN.search(raw)
        budget = _BUDGET.search(raw)
        killed_m = _KILLED.search(raw)
        run_seconds = float(run.group("v")) if run else 0.0
        budget_seconds = float(budget.group("v")) if budget else 0.0
        killed = bool(killed_m) and killed_m.group("v").lower() in ("true", "yes", "1")
        frames = [
            Frame(symbol=m.group("symbol"), uri=m.group("uri"), line=int(m.group("line")))
            for line in raw.splitlines()
            if (m := _SIGNAL_FRAME.match(line))
        ]
        language = "python" if any(fr.uri and fr.uri.endswith(".py") for fr in frames) else "c/c++"
        finding = detect_hang(run_seconds, budget_seconds, frames, killed=killed,
                              target=target, language=language)
        return [finding] if finding else []
