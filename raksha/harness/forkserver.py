"""A fork-server client, so fuzzing a synthesized harness is fast without losing isolation.

Spawning a fresh process per input makes the find loop thousands of times slower than the bug needs
and was the autofuzz bottleneck. A fork server is the standard answer (AFL's): the harness starts
ONCE, imports/loads the target ONCE, then forks a child per input — the child runs the target and
dies, the parent is untouched. Untrusted target code still runs only in a short-lived child process,
never in RAKSHA's own, so isolation holds; it is just not paid for with a process start each time.

Protocol, deliberately tiny: the driver writes a 4-byte big-endian length then that many input bytes;
the harness replies with one status byte (1 = the input crashed / the oracle sink fired, 0 = clean).
Length 0xFFFFFFFF means shut down. The harness also runs one-shot (`harness <file>`) for the gate and
for replay, where the full sanitizer / detector output is what matters.
"""

from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path

_SHUTDOWN = 0xFFFFFFFF


class ForkClient:
    """Drive a fork-server harness. `run_one(data)` returns True when the input crashed."""

    def __init__(self, argv: list[str], cwd: str | Path, env: dict | None = None) -> None:
        self.argv = argv
        self.cwd = str(cwd)
        self.env = env
        self.proc: subprocess.Popen | None = None
        self.restarts = 0
        self._spawn()

    def _spawn(self) -> None:
        self.close()
        from ..sandbox import popen_target   # the sandbox door: hot loops may not bypass it
        self.proc = popen_target(
            self.argv, self.cwd, env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def run_one(self, data: bytes) -> bool:
        if self.proc is None or self.proc.poll() is not None:
            self._spawn()
            self.restarts += 1
        assert self.proc and self.proc.stdin and self.proc.stdout
        try:
            self.proc.stdin.write(struct.pack(">I", len(data)) + data)
            self.proc.stdin.flush()
            status = self.proc.stdout.read(1)
        except (BrokenPipeError, OSError):
            status = b""
        if not status:
            # The harness itself died (not just a forked child): a benign input shouldn't do this,
            # so count the input as a crash candidate, restart, and let one-shot replay adjudicate.
            self._spawn()
            self.restarts += 1
            return True
        return status == b"\x01"

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.write(struct.pack(">I", _SHUTDOWN))
                self.proc.stdin.flush()
                self.proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream and not stream.closed:
                    stream.close()
            except OSError:
                pass
        self.proc = None

    def __enter__(self) -> "ForkClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def asan_env(base: dict | None = None) -> dict:
    """Env for the fork server: hunt memory corruption, and don't let per-child leak checks or an
    ASan abort in one child be mistaken for a harness-level failure."""
    env = dict(base if base is not None else os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:exitcode=99:handle_abort=1"
    return env
