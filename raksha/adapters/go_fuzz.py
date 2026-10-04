"""Go deep lane — native `go test -fuzz`, no hand-written harness.

Go ships a fuzzer in the toolchain, so the lane uses it rather than our mutation engine: RAKSHA
discovers the entry point, synthesizes a `FuzzRaksha` test, and `go test -fuzz` finds a panicking
input. The finding then goes through the same gate as every other language — `GoFuzzTarget` builds
the module, replays the input, measures coverage (from Go's own coverage profile) and re-fuzzes, so
"fix and prove" is the shared five-check gate, not a Go-specific one.

Everything runs offline (GOFLAGS=-mod=mod, GOPROXY=off): the demo module is stdlib-only, so a sealed
node with the Go toolchain needs no network.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..finding import Finding, Frame, Reproducer, ReplayResult, utcnow
from ..gate.target import BuildResult, RunResult, TestResult
from ..harness import names
from ..sandbox import run_target
from ..harness.entrypoints import Entrypoint, discover
from ..oracles.go_panic import GoOracle

_FUZZ_TEST = '''package {pkg}

import "testing"

func {fuzz}(f *testing.F) {{
    f.Add({seed})
    f.Fuzz(func(t *testing.T, {arg} {typ}) {{
        {call}
    }})
}}
'''
_POV_SEED = names.GO_SEED
_CORPUS_V1 = "go test fuzz v1\n"


def _go_env() -> dict:
    env = dict(os.environ)
    env.setdefault("GOFLAGS", "-mod=mod")
    env.setdefault("GOPROXY", "off")
    env.setdefault("GOCACHE", tempfile.gettempdir() + "/" + names.SCRATCH + "gocache")
    env.setdefault("GOTMPDIR", tempfile.gettempdir())
    return env


def _go_quote(data: bytes) -> str:
    """A Go byte-string literal for a corpus file: []byte("\\x01\\x02...")."""
    return '[]byte("' + "".join(f"\\x{b:02x}" for b in data) + '")'


def synthesize_go_test(ep: Entrypoint, pkg: str) -> str:
    if ep.kind == "go_bytes":
        return _FUZZ_TEST.format(pkg=pkg, seed='[]byte("\\x01a")', arg="data", typ="[]byte",
                                 call=f"{ep.symbol}(data)", fuzz=names.GO_FUZZ)
    return _FUZZ_TEST.format(pkg=pkg, seed='"a"', arg="s", typ="string", call=f"{ep.symbol}(s)",
                             fuzz=names.GO_FUZZ)


_GO_CHROME = re.compile(
    r"^(ok|FAIL|PASS|---\s+(FAIL|PASS)|=== RUN|=== (?:CONT|NAME|PAUSE)|coverage:|\s*--- FAIL"
    r"|FAIL\s|ok\s|\?\s|\s*\(cached\)|testing:|exit status \d+).*$", re.MULTILINE)


def _strip_go_test_chrome(text: str) -> str:
    """Drop `go test`'s own status/timing lines, keeping the program's and the runtime's output."""
    return "\n".join(ln for ln in text.splitlines()
                     if ln.strip() and not _GO_CHROME.match(ln.strip()) and not _GO_CHROME.match(ln))


def _package_of(path: Path) -> str:
    m = re.search(r"^package\s+(\w+)", path.read_text(errors="replace"), re.MULTILINE)
    return m.group(1) if m else "main"


class GoFuzzTarget:
    """A gate Target backed by a Go module and the synthesized FuzzRaksha test."""

    def __init__(self, source_root: str | Path, fuzz_test: str, pkg_dir: str = ".",
                 timeout: float = 180.0) -> None:
        self.source_root = Path(source_root).resolve()
        self.fuzz_test = fuzz_test            # the synthesized FuzzRaksha test, written into every build
        self.pkg_dir = pkg_dir
        self.timeout = timeout
        self.env = _go_env()

    def _sh(self, cmd: str, cwd: Path, timeout: float | None = None) -> RunResult:
        try:
            p = run_target(cmd, str(cwd), shell=True, timeout=timeout or self.timeout, env=self.env)
            return RunResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired as e:
            return RunResult(-1, e.stdout or b"", e.stderr or b"", timed_out=True)

    def _pkg(self, root: Path) -> Path:
        return root / self.pkg_dir

    def build(self, patch_diff: str | None, *, flavour: str = "sanitizer") -> BuildResult:
        label = "patched" if patch_diff else "vulnerable"
        root = Path(tempfile.mkdtemp(prefix=names.SCRATCH))
        shutil.copytree(self.source_root, root, dirs_exist_ok=True)
        if patch_diff:
            (root / names.dot("patch")).write_text(patch_diff)
            applied = self._sh(f"git apply -p1 {names.dot('patch')} 2>/dev/null || patch -p1 < {names.dot('patch')}", root)
            if applied.exit_code != 0:
                return BuildResult(False, label, "patch did not apply:\n" + applied.text, root)
        # the synthesized fuzz test is part of the target as far as the gate is concerned
        (self._pkg(root) / names.GO_FILE).write_text(self.fuzz_test)
        built = self._sh("go build ./...", self._pkg(root))
        return BuildResult(built.exit_code == 0, label, built.text[-800:], root)

    def _write_pov(self, build: BuildResult, data: bytes) -> None:
        d = self._pkg(build.root) / "testdata" / "fuzz" / names.GO_FUZZ
        d.mkdir(parents=True, exist_ok=True)
        (d / _POV_SEED).write_text(_CORPUS_V1 + _go_quote(data) + "\n")

    def run(self, build: BuildResult, data: bytes) -> RunResult:
        assert build.root is not None
        self._write_pov(build, data)
        r = self._sh(f"go test -run='{names.GO_FUZZ}/{_POV_SEED}'", self._pkg(build.root), timeout=90)
        # `go test` chrome (ok/FAIL/--- lines, timings, (cached)) is not the target's behaviour and
        # varies run to run; strip it so the differential compares the program's own output, and the
        # oracle still sees any panic. The fuzz harness discards Decode's return, so behaviour here is
        # "panics or not" — the exit code carries that, which the differential also compares.
        stripped = _strip_go_test_chrome((r.stdout + b"\n" + r.stderr).decode("utf-8", "replace"))
        return RunResult(r.exit_code, stripped.encode(), b"", timed_out=r.timed_out)

    def run_tests(self, build: BuildResult) -> TestResult:
        assert build.root is not None
        r = self._sh("go test -run='^Test' ./...", self._pkg(build.root), timeout=120)
        if "no test files" in r.text or "no tests to run" in r.text:
            return TestResult(ran=0, failed=0, log="no non-fuzz tests in the module")
        return TestResult(ran=1, failed=0 if r.exit_code == 0 else 1, log=r.text[-600:])

    def run_added_test(self, build: BuildResult, test_source: str) -> TestResult:
        return TestResult(0, 0, "added-test not wired for the Go lane")

    def covered_lines(self, build: BuildResult, inputs: list[bytes]) -> set[tuple[str, int]]:
        assert build.root is not None
        d = self._pkg(build.root) / "testdata" / "fuzz" / names.GO_FUZZ
        d.mkdir(parents=True, exist_ok=True)
        for i, data in enumerate(inputs):          # each input as its own seed file
            (d / f"{_POV_SEED}_{i}").write_text(_CORPUS_V1 + _go_quote(data) + "\n")
        pkg = self._pkg(build.root)
        # run the whole fuzz function over its seed corpus under coverage (a single -run=.../seed
        # under -coverprofile records no counts; the function's seed replay does)
        self._sh(f"go test -run='{names.GO_FUZZ}' -coverprofile={names.dot('cov')}", pkg, timeout=120)
        covered: set[tuple[str, int]] = set()
        prof = pkg / names.dot("cov")
        if not prof.exists():
            return covered
        # cover profile lines: file:startline.col,endline.col numstmt count
        for line in prof.read_text(errors="replace").splitlines()[1:]:
            m = re.match(r"(?P<file>.+):(?P<s>\d+)\.\d+,(?P<e>\d+)\.\d+\s+\d+\s+(?P<n>\d+)", line)
            if not m or int(m.group("n")) == 0:
                continue
            base = m.group("file").rsplit("/", 1)[-1]
            for ln in range(int(m.group("s")), int(m.group("e")) + 1):
                covered.add((base, ln))
        return covered

    def can_refuzz(self) -> bool:
        return True

    def refuzz(self, build: BuildResult, seconds: float) -> list[str]:
        assert build.root is not None
        r = self._sh(f"go test -run='^$' -fuzz='{names.GO_FUZZ}' -fuzztime={max(1, int(seconds))}s",
                     self._pkg(build.root), timeout=seconds + 60)
        return [r.text] if r.exit_code != 0 and ("panic" in r.text or "DATA RACE" in r.text) else []

    def discard(self, build: BuildResult) -> None:
        if build.root and Path(build.root).name.startswith(names.SCRATCH):
            shutil.rmtree(build.root, ignore_errors=True)


@dataclass
class GoAutofuzzResult:
    finding: Finding | None
    entrypoint: Entrypoint | None
    crashing_input: bytes | None
    target: GoFuzzTarget | None
    note: str = ""

    @property
    def found(self) -> bool:
        return self.finding is not None


def go_autofuzz(target_root: str | Path, *, fuzztime_s: int = 10, max_entrypoints: int = 3) -> GoAutofuzzResult:
    """Synthesize a Go fuzz test for the best entry point and run native fuzzing until it panics."""
    root = Path(target_root)
    if shutil.which("go") is None:
        return GoAutofuzzResult(None, None, None, None, note="go toolchain not available")
    candidates = [e for e in discover(root, languages={"go"}) if True]
    for ep in candidates[:max_entrypoints]:
        src = root / ep.path
        pkg_dir = str(src.parent.relative_to(root)) if src.parent != root else "."
        work = Path(tempfile.mkdtemp(prefix=names.SCRATCH)) / root.name
        shutil.copytree(root, work, dirs_exist_ok=True)
        pkgpath = work / pkg_dir
        (pkgpath / names.GO_FILE).write_text(synthesize_go_test(ep, _package_of(src)))
        env = _go_env()
        if run_target("go build ./...", str(pkgpath), shell=True, env=env).returncode != 0:
            shutil.rmtree(work.parent, ignore_errors=True)
            continue
        r = run_target(f"go test -run='^$' -fuzz='{names.GO_FUZZ}' -fuzztime={fuzztime_s}s",
                       str(pkgpath), shell=True, env=env, timeout=fuzztime_s + 90)
        text = (r.stdout + b"\n" + r.stderr).decode("utf-8", "replace")
        findings = GoOracle().parse(text, target=root.name)
        crasher = _read_latest_crasher(pkgpath / "testdata" / "fuzz" / names.GO_FUZZ)
        shutil.rmtree(work.parent, ignore_errors=True)
        if not findings or crasher is None:
            continue
        f = findings[0]
        _rebase_to(f, work)                       # paths relative to the module root, so a fix applies
        target = GoFuzzTarget(root, synthesize_go_test(ep, _package_of(src)), pkg_dir=pkg_dir)
        f.attach_reproducer(Reproducer.from_bytes(crasher, ["go", "test", f"-run={names.GO_FUZZ}/{_POV_SEED}"],
                                                  detail=f"go-autofuzz: synthesized fuzz test for {ep.symbol}"))
        f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                            abort_signature=f.abort_signature, exit_code=1))
        f.confirm(reason=f"panic reproduced via a synthesized Go fuzz test for {ep.symbol}")
        return GoAutofuzzResult(f, ep, crasher, target, note=f"panic via the synthesized fuzz test for {ep.symbol}")
    return GoAutofuzzResult(None, candidates[0] if candidates else None, None, None,
                            note="no panic found within the budget")


def _rebase_to(finding: Finding, work: Path) -> None:
    """Rewrite the finding's frame / fix-site paths to be relative to the module root `work`, so a
    repair diff (a/<rel> b/<rel>) applies in the gate's fresh build copy."""
    base = str(work)
    def rel(uri: str | None) -> str | None:
        if uri and uri.startswith(base):
            return uri[len(base):].lstrip("/")
        return uri
    finding.frames = [Frame(symbol=fr.symbol, uri=rel(fr.uri), line=fr.line, column=fr.column)
                      for fr in finding.frames]
    for s in finding.fix_site_set:
        object.__setattr__(s, "uri", rel(s.uri))


def _read_latest_crasher(corpus_dir: Path) -> bytes | None:
    if not corpus_dir.is_dir():
        return None
    files = [p for p in corpus_dir.iterdir() if p.is_file() and p.name != _POV_SEED]
    if not files:
        return None
    newest = max(files, key=lambda p: p.stat().st_mtime)
    return _corpus_bytes(newest.read_text(errors="replace"))


def _corpus_bytes(text: str) -> bytes | None:
    """Decode a Go fuzz corpus file's single []byte("...") value into raw bytes."""
    m = re.search(r'\[\]byte\("(.*)"\)', text, re.S)
    if not m:
        return None
    raw, out, i = m.group(1), bytearray(), 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "x" and i + 3 < len(raw):
                out.append(int(raw[i + 2:i + 4], 16)); i += 4; continue
            esc = {"n": 10, "t": 9, "r": 13, "\\": 92, '"': 34, "0": 0}.get(nxt)
            if esc is not None:
                out.append(esc); i += 2; continue
        out.append(ord(c) & 0xFF); i += 1
    return bytes(out)
