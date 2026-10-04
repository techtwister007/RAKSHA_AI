"""ThreadSanitizer oracle — data races in C/C++ (`-fsanitize=thread`) and Go (`go test -race`).

The first step toward the concurrency / temporal layer the external review asked for. It is an
oracle only: it turns a TSan report into the unified record (CWE-362, severity high) so the same
five-check gate can prove a locking fix the way it proves a bounds check. No schedule fuzzing — a
race that TSan did not observe on the runs we made is outside the claim, and the assurance boundary
says so.

Format verification status: **VERIFIED** against gcc 13's libtsan output (frames of the shape
`#0 func /path/file.c:LINE (binary+0x...)`) and the clang shape (`#0 0xADDR in func file.c:LINE:COL`);
Go's `WARNING: DATA RACE` block (`  main.f()\n      /path/x.go:12 +0x..`) is parsed from the
documented race-detector layout.

Both access stacks are read: the "Write/Read of size N ... by thread Tn" stack and the "Previous
write/read ..." stack. The abort signature is built from the top frame of each — a race is a *pair*
of sites, and two races that share one endpoint but not the other are two bugs.
"""

from __future__ import annotations

import re

from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

_C_BANNER = re.compile(r"WARNING: ThreadSanitizer: (?P<kind>data race|[\w \-]+?)(?: \(pid=\d+\))?\s*$", re.M)
_GO_BANNER = re.compile(r"WARNING: DATA RACE")
# "Write of size 4 at 0x... by thread T1:" / "Previous read of size 4 at 0x... by main thread:"
_C_ACCESS = re.compile(
    r"^\s*(?P<prev>Previous )?(?P<rw>Atomic read|Atomic write|Read|Write) of size (?P<size>\d+)"
    r" at 0x[0-9a-fA-F]+ by (?P<thread>main thread|thread T\d+)", re.M | re.I)
# clang: "#0 0x4a1b2c in worker /src/w.c:12:5"   gcc: "#0 worker /src/w.c:12 (bin+0x1234)"
_C_FRAME = re.compile(
    r"^\s*#(?P<depth>\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(?P<symbol>[^\s]+)"
    r"(?:\s+(?P<uri>[^\s:()]+):(?P<line>\d+)(?::(?P<col>\d+))?)?")
# Go: "Write at 0x00c000012345 by goroutine 7:" / "Previous read at ... by main goroutine:"
_GO_ACCESS = re.compile(
    r"^(?P<prev>Previous )?(?P<rw>Read|Write) at 0x[0-9a-fA-F]+ by (?P<thread>main goroutine|goroutine \d+)",
    re.M | re.I)
_GO_FUNC = re.compile(r"^\s+(?P<fn>[\w./\-]+(?:\.[\w.*()]+)+)\(\)\s*$")
_GO_FILE = re.compile(r"^\s+(?P<file>[^\s:]+\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-fA-F]+)?\s*$")
#: Frames that belong to the sanitizer runtime or the Go runtime, never to the target.
_NOT_TARGET = ("libsanitizer", "tsan_interceptors", "sanitizer_common", "/src/runtime/", "/src/testing/",
               "/src/sync/", "runtime.", "testing.", "raksha_fuzz_test.go")

CWE_DATA_RACE = "CWE-362"


class TsanOracle(Oracle):
    name = "tsan"
    language = "c/c++"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        if _GO_BANNER.search(raw):
            return self._parse_go(raw, target=target)
        m = _C_BANNER.search(raw)
        if m:
            return self._parse_c(raw, m, target=target)
        return []

    # ------------------------------------------------------------------ C / C++

    def _parse_c(self, raw: str, banner: re.Match[str], *, target: str) -> list[Finding]:
        kind = banner.group("kind").strip()
        # The report is the text between the banner and the next "=====" rule or SUMMARY line.
        body = raw[banner.end():]
        cut = re.search(r"^\s*(?:=+\s*$|SUMMARY:)", body, re.M)
        if cut:
            body = body[:cut.start()]
        stacks = self._c_stacks(body)
        current = stacks.get("current", [])
        previous = stacks.get("previous", [])
        frames = _dedupe([*current, *previous])
        accesses = [m.group("rw").lower() for m in _C_ACCESS.finditer(body)]
        detail = f"{kind}" + (f" ({' vs '.join(accesses[:2])})" if accesses else "")
        return [self._finding(raw, target, frames, [current, previous], detail, language="c/c++")]

    @staticmethod
    def _c_stacks(body: str) -> dict[str, list[Frame]]:
        """Frames under the current-access header and under the previous-access header."""
        out: dict[str, list[Frame]] = {}
        section: str | None = None
        for line in body.splitlines():
            acc = _C_ACCESS.match(line)
            if acc:
                section = "previous" if acc.group("prev") else "current"
                out.setdefault(section, [])
                continue
            if not line.strip():
                section = None
                continue
            if section is None:
                continue
            fm = _C_FRAME.match(line)
            if fm and fm.group("depth"):
                uri = fm.group("uri")
                if uri and any(mk in uri for mk in _NOT_TARGET):
                    continue
                out[section].append(Frame(
                    symbol=fm.group("symbol"), uri=uri,
                    line=int(fm.group("line")) if fm.group("line") else None,
                    column=int(fm.group("col")) if fm.group("col") else None))
        return out

    # ------------------------------------------------------------------------ Go

    def _parse_go(self, raw: str, *, target: str) -> list[Finding]:
        lines = raw.splitlines()
        stacks: dict[str, list[Frame]] = {}
        section: str | None = None
        pending_fn: str | None = None
        accesses: list[str] = []
        for line in lines:
            acc = _GO_ACCESS.match(line)
            if acc:
                section = "previous" if acc.group("prev") else "current"
                stacks.setdefault(section, [])
                accesses.append(acc.group("rw").lower())
                pending_fn = None
                continue
            if not line.strip():
                section = None
                pending_fn = None
                continue
            if section is None:
                continue
            fn = _GO_FUNC.match(line)
            if fn:
                pending_fn = fn.group("fn").rsplit("/", 1)[-1]
                continue
            fl = _GO_FILE.match(line)
            if fl:
                uri = fl.group("file")
                if any(mk in uri for mk in _NOT_TARGET) or any(mk in (pending_fn or "") for mk in _NOT_TARGET):
                    pending_fn = None
                    continue
                stacks[section].append(Frame(symbol=pending_fn or uri.rsplit("/", 1)[-1], uri=uri,
                                             line=int(fl.group("line"))))
                pending_fn = None
        current = stacks.get("current", [])
        previous = stacks.get("previous", [])
        frames = _dedupe([*current, *previous])
        detail = "data race" + (f" ({' vs '.join(accesses[:2])})" if accesses else "")
        return [self._finding(raw, target, frames, [current, previous], detail, language="go")]

    # -------------------------------------------------------------------- common

    def _finding(self, raw: str, target: str, frames: list[Frame], stacks: list[list[Frame]],
                 detail: str, *, language: str) -> Finding:
        # Signature from the top frame of EACH access stack: a race is a pair of sites.
        tops = [s[0] for s in stacks if s]
        sig_frames = tops if len(tops) == 2 else frames[:2]
        f = Finding(
            oracle=f"{self.name}:ThreadSanitizer",
            bug_class=CWE_DATA_RACE,
            language=language,
            target=target,
            message=f"ThreadSanitizer: {detail}",
            severity="high",
            frames=frames,
            abort_signature=abort_signature(CWE_DATA_RACE, sig_frames, depth=2),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(f, frames)
        return f


def _dedupe(frames: list[Frame]) -> list[Frame]:
    seen: set[Frame] = set()
    out: list[Frame] = []
    for fr in frames:
        if fr not in seen:
            seen.add(fr)
            out.append(fr)
    return out
