"""J2 — bring-your-own-target intake: a judge's media goes in, a first finding comes out, no restart.

The intake path is the one place an unknown, possibly hostile tree enters the system, so it is
built to be boring:

  * **Allow-listed roots.** Only paths under the configured media roots (``RAKSHA_INTAKE_ROOTS``,
    colon-separated; default ``/media:/mnt:/run/media:/targets``) are accepted.
  * **Copied as data, bounded.** The tree is staged into a private scratch directory before
    anything reads it: at most ``max_files`` files, ``max_bytes`` in total, ``max_file_bytes`` per
    file and ``max_depth`` levels. Symlinks, devices, sockets and FIFOs are skipped and counted,
    never followed; execute bits are dropped; a name that would escape the stage is refused. A tree
    over a budget is staged up to the budget and the record says it was truncated.
  * **Scanned off the live session.** Lanes run on a scratch session in a worker thread; only the
    finished results are merged into the live session, under its lock, so the console keeps
    serving while a target is read and never sees a half-written board.
  * **One at a time.** A second intake while one is running is refused, not queued.

Time-to-first-finding is measured with a monotonic clock from the moment the media is accepted to
the moment the first finding is on the live board, and shown ticking on the console. The deep
(synthesized-harness) lane is opt-in: it executes target code (inside the sandbox door) and can take
minutes, so the default intake is the build-free lanes only.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ROOTS = ("/media", "/mnt", "/run/media", "/targets")


def allowed_roots() -> list[Path]:
    raw = os.environ.get("RAKSHA_INTAKE_ROOTS")
    parts = raw.split(":") if raw else list(DEFAULT_ROOTS)
    return [Path(p).resolve() for p in parts if p]


@dataclass
class Limits:
    max_files: int = 20000
    max_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_depth: int = 32


@dataclass
class StageReport:
    files: int = 0
    bytes: int = 0
    skipped_links: int = 0
    skipped_special: int = 0
    skipped_large: int = 0
    refused_names: int = 0
    truncated: bool = False

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _inside(path: Path, roots: list[Path]) -> bool:
    for r in roots:
        try:
            path.relative_to(r)
            return True
        except ValueError:
            continue
    return False


def stage(src: str | Path, dest: str | Path, limits: Limits | None = None) -> StageReport:
    """Copy the tree at `src` into `dest` as plain data, within `limits`. Never follows a link."""
    limits = limits or Limits()
    src, dest = Path(src), Path(dest)
    rep = StageReport()
    dest.mkdir(parents=True, exist_ok=True)
    dest_r = dest.resolve()
    stack: list[tuple[Path, Path, int]] = [(src, dest, 0)]
    while stack:
        here, there, depth = stack.pop()
        try:
            entries = sorted(os.scandir(here), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            if e.name in (".", "..") or "/" in e.name or "\0" in e.name:
                rep.refused_names += 1
                continue
            out = there / e.name
            if not str(out.resolve(strict=False)).startswith(str(dest_r)):
                rep.refused_names += 1
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                rep.skipped_links += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                if depth + 1 > limits.max_depth:
                    rep.truncated = True
                    continue
                out.mkdir(exist_ok=True)
                stack.append((Path(e.path), out, depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                rep.skipped_special += 1
                continue
            if st.st_size > limits.max_file_bytes:
                rep.skipped_large += 1
                continue
            if rep.files + 1 > limits.max_files or rep.bytes + st.st_size > limits.max_bytes:
                rep.truncated = True
                return rep
            # O_NOFOLLOW: the entry was a regular file at stat time; refuse it if it was swapped
            fd = os.open(e.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as fin, open(out, "wb") as fout:
                shutil.copyfileobj(fin, fout, 1 << 20)
            os.chmod(out, 0o644)                       # data, never executable
            rep.files += 1
            rep.bytes += st.st_size
    return rep


@dataclass
class IntakeJob:
    path: str
    name: str
    deep: bool = False
    state: str = "queued"          # queued | staging | scanning | deep | done | failed | refused
    started_mono: float = field(default_factory=time.monotonic)
    started_at: str = ""
    first_finding_s: float | None = None
    total_s: float | None = None
    findings: int = 0
    stage: dict | None = None
    error: str | None = None
    project: str | None = None

    def as_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "started_mono"}
        d["elapsed_s"] = round(time.monotonic() - self.started_mono, 2) if self.total_s is None else self.total_s
        return d


class Intake:
    """The intake desk for one live session. `submit` returns at once; work runs in a thread."""

    def __init__(self, session, *, roots: list[Path] | None = None, limits: Limits | None = None,
                 scratch: str | Path | None = None) -> None:
        self.session = session
        self.roots = roots if roots is not None else allowed_roots()
        self.limits = limits or Limits()
        self.scratch = Path(scratch) if scratch else None
        self.job: IntakeJob | None = None
        self.history: list[dict] = []
        self._busy = threading.Lock()
        self._thread: threading.Thread | None = None

    def status(self) -> dict:
        return {"current": self.job.as_dict() if self.job else None, "history": self.history[-10:],
                "roots": [str(r) for r in self.roots]}

    def submit(self, path: str, *, name: str | None = None, deep: bool = False) -> dict:
        try:
            p = Path(path).resolve(strict=True)
        except (OSError, RuntimeError):
            return {"ok": False, "error": f"{path!r} does not exist"}
        if not p.is_dir():
            return {"ok": False, "error": f"{path!r} is not a directory"}
        if not _inside(p, self.roots):
            return {"ok": False, "error": f"{path!r} is outside the intake roots "
                                          f"({', '.join(str(r) for r in self.roots)})"}
        if not self._busy.acquire(blocking=False):
            return {"ok": False, "error": "an intake is already running; one at a time"}
        nm = name or p.name or "intake"
        existing = {t.name for t in self.session.targets}
        base, i = nm, 2
        while nm in existing:
            nm, i = f"{base}-{i}", i + 1
        from .finding import utcnow
        self.job = IntakeJob(path=str(p), name=nm, deep=deep, started_at=utcnow().isoformat())
        self._thread = threading.Thread(target=self._run, args=(p, self.job), daemon=True,
                                        name="raksha-intake")
        self._thread.start()
        return {"ok": True, "job": self.job.as_dict()}

    def wait(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    # -- the worker -------------------------------------------------------------------------
    def _run(self, src: Path, job: IntakeJob) -> None:
        from .orchestrator import Session, _merge_scratch
        sess = self.session
        tmp = Path(tempfile.mkdtemp(prefix="raksha-intake-", dir=self.scratch))
        try:
            job.state = "staging"
            sess.emit("intake_started", target=job.name, deep=job.deep)
            staged = tmp / job.name
            rep = stage(src, staged, self.limits)
            job.stage = rep.as_dict()
            sess.emit("intake_staged", target=job.name, **rep.as_dict())
            if rep.files == 0:
                raise ValueError("nothing readable on the media")
            job.state = "scanning"
            scratch = Session(registry=sess.registry)
            scratch.ingest_build_free(staged, name=job.name,
                                      note="intake: build-free lanes" + (" (truncated)" if rep.truncated else ""))
            n = _merge_scratch(sess, scratch)
            job.findings += n
            if n and job.first_finding_s is None:
                job.first_finding_s = round(time.monotonic() - job.started_mono, 3)
                sess.emit("intake_first_finding", target=job.name, seconds=job.first_finding_s)
            if job.deep:
                job.state = "deep"
                deep = Session(registry=sess.registry)
                try:
                    deep.ingest_autofuzz(staged, name=f"{job.name}:deep")
                except Exception as e:  # noqa: BLE001 — the deep lane is best-effort on unknown media
                    sess.emit("intake_deep_skipped", target=job.name, reason=f"{type(e).__name__}: {e}"[:200])
                m = _merge_scratch(sess, deep)
                job.findings += m
                if m and job.first_finding_s is None:
                    job.first_finding_s = round(time.monotonic() - job.started_mono, 3)
                    sess.emit("intake_first_finding", target=job.name, seconds=job.first_finding_s)
            try:                                   # K2: the media becomes a project with a report
                live = sess.record_project_run(job.name, root=staged, project_name=Path(job.path).name)
                job.project = live.get("project")
            except Exception:  # noqa: BLE001 — a report failure never fails the intake
                pass
            job.state = "done"
        except Exception as e:  # noqa: BLE001 — a bad medium is a red row, never a dead console
            job.state, job.error = "failed", f"{type(e).__name__}: {e}"[:300]
        finally:
            job.total_s = round(time.monotonic() - job.started_mono, 3)
            sess.emit("intake_done", target=job.name, state=job.state, findings=job.findings,
                      first_finding_s=job.first_finding_s, seconds=job.total_s, error=job.error)
            self.history.append(job.as_dict())
            if job.state != "done":
                shutil.rmtree(tmp, ignore_errors=True)   # a good stage stays for the session's evidence
            self._busy.release()
