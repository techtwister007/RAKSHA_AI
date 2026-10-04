"""Rust deep lane — stable `cargo test` as the fuzzing engine, no hand-written harness.

Rust ships no fuzzer in the stable toolchain (`cargo-fuzz`/libFuzzer needs nightly and a network
fetch), so this lane supplies the mutation itself and uses `cargo test` only as the *runner*: RAKSHA
discovers a `fn name(&[u8])` entry point, synthesizes a `tests/raksha_fuzz.rs` harness that reads an
input file and calls it, mutates seeds until the harness panics, and turns that panic into a finding.
The finding then goes through the same five-check gate as every other language — `RustFuzzTarget`
builds the crate, replays the input, measures coverage and re-fuzzes — so "fix and prove" is the
shared gate, not a Rust-specific one.

Everything runs offline and leaves no global state: `CARGO_NET_OFFLINE=true` and a crate-local
`CARGO_HOME`/`CARGO_TARGET_DIR` under a tempdir, so a sealed node with only the Rust toolchain needs
no network and never writes the user's `~/.cargo`.

Coverage, honestly
-------------------
Stable `cargo` has no built-in line coverage (`-C instrument-coverage` needs the `llvm-tools-preview`
component, an online fetch we refuse). So `covered_lines` is a cheap source-line heuristic — the body
lines of the function enclosing the fix site in the *patched* build, returned only once the harness
is confirmed to still run. It is enough for what COVERAGE_HELD guards against: a "fix" that deletes
the vulnerable function makes the fix-site line vanish from the returned set and the check fails.
Same spirit as the Go lane's note, where exact coverage was impractical we report the fix
neighbourhood the corpus provably reaches instead of fabricating a profile.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ..finding import Finding, Frame, Reproducer, ReplayResult, utcnow
from ..gate.target import BuildResult, RunResult, TestResult
from ..harness.entrypoints import Entrypoint
from ..oracles.rust_panic import RustPanicOracle
from ..repair_templates import _diff, _read_fix_site

_INPUT_FILE = "raksha_input.bin"
_CORPUS_DIR = "raksha_corpus"

_FUZZ_HARNESS = '''// RAKSHA synthesized fuzz harness — generated, not hand-written.
// Reads one input file (or a corpus directory) and feeds it to the entry point, so any panic the
// input triggers fails `cargo test`. Stable cargo, offline — no cargo-fuzz, no nightly.
use std::fs;
use std::path::PathBuf;

#[test]
fn raksha_fuzz() {{
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let single = dir.join("{input}");
    if single.is_file() {{
        let data = fs::read(&single).expect("read input");
        {crate}::{symbol}(&data);
        return;
    }}
    let corpus = dir.join("{corpus}");
    if corpus.is_dir() {{
        let mut files: Vec<PathBuf> = fs::read_dir(&corpus)
            .expect("read corpus dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        for p in files {{
            let data = fs::read(&p).expect("read corpus file");
            {crate}::{symbol}(&data);
        }}
    }}
}}
'''


# ---------------------------------------------------------------- discovery

# A free function taking a single `&[u8]` argument — the fuzzable "give me bytes" shape. Matches an
# optional `pub`, generics-free signature, on one line. entrypoints.discover() has no Rust scanner,
# so the Rust lane discovers its own entry points here rather than editing the shared module.
_RS_FUNC = re.compile(
    r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\s*"
    r"\(\s*(?P<arg>\w+)\s*:\s*&\s*\[\s*u8\s*\]\s*\)",
    re.MULTILINE)

_INPUT_NAMES = ("parse", "decode", "read", "load", "handle", "process", "deserialize", "unmarshal",
                "convert", "scan", "lex", "tokenize", "render", "ingest", "interpret", "run",
                "dispatch", "command", "query", "record")


def _name_bonus(name: str) -> float:
    low = name.lower()
    return max((2.0 for h in _INPUT_NAMES if h in low), default=0.0)


def discover_rust(root: str | Path, *, limit: int = 20) -> list[Entrypoint]:
    """Candidate `fn name(&[u8])` entry points under `root`, best first. Reads source only.

    Stands in for `entrypoints.discover` for Rust, which has no `.rs` scanner; kept here so the lane
    owns its own discovery without touching the shared harness module.
    """
    root = Path(root)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*.rs"))
        if p.is_file() and "target" not in p.parts and p.name != "raksha_fuzz.rs"]
    out: list[Entrypoint] = []
    for p in files:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(root)) if root.is_dir() else p.name
        for m in _RS_FUNC.finditer(text):
            name = m.group("name")
            line = text[: m.start()].count("\n") + 1
            is_pub = bool(re.match(r"^\s*pub\s+fn", m.group(0)))
            score = 3.0 + _name_bonus(name) + (0.5 if is_pub else 0.0)
            out.append(Entrypoint("rust", rel, name, line, "rust_bytes", score,
                                  signature=f"fn {name}({m.group('arg')}: &[u8])"))
    out.sort(key=lambda e: (-e.score, e.path, e.line))
    return out[:limit]


def _crate_name(root: Path) -> str:
    """The lib crate's import name from Cargo.toml — `[lib] name` wins, else `[package] name`,
    with hyphens normalised to underscores the way Rust imports them."""
    toml = root / "Cargo.toml"
    pkg = lib = None
    section = None
    if toml.is_file():
        for ln in toml.read_text(errors="replace").splitlines():
            s = ln.strip()
            if s.startswith("["):
                section = s.strip("[]").strip()
                continue
            m = re.match(r'name\s*=\s*"([^"]+)"', s)
            if m:
                if section == "lib":
                    lib = m.group(1)
                elif section == "package":
                    pkg = m.group(1)
    return (lib or pkg or root.name).replace("-", "_")


def synthesize_rust_harness(ep: Entrypoint, crate: str) -> str:
    return _FUZZ_HARNESS.format(crate=crate, symbol=ep.symbol, input=_INPUT_FILE, corpus=_CORPUS_DIR)


# ---------------------------------------------------------------- cargo env

def _cargo_env(home: Path, target_dir: Path) -> dict:
    env = dict(os.environ)
    env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_HOME"] = str(home)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env.setdefault("RUST_BACKTRACE", "1")
    env.pop("RUSTFLAGS", None)
    return env


# ---------------------------------------------------------------- the target

class RustFuzzTarget:
    """A gate Target backed by a cargo crate and the synthesized `raksha_fuzz` test.

    Mirrors `GoFuzzTarget`: it keeps the pristine `source_root` and the synthesized harness text, and
    rebuilds a fresh copy for every `build()` so a patch applies against clean source. `cargo build
    --tests` compiles the harness once per build; `run` then drives the compiled test binary directly
    (≈3 ms) rather than re-invoking `cargo test` (≈60 ms), which keeps the 24-variant CLEAN_REFUZZ
    neighbourhood and the fresh campaign cheap.
    """

    def __init__(self, source_root: str | Path, entrypoint: Entrypoint, harness: str,
                 timeout: float = 240.0) -> None:
        self.source_root = Path(source_root).resolve()
        self.entrypoint = entrypoint
        self.harness = harness
        self.ep_path = entrypoint.path          # the file holding the entry point, relative to root
        self.ep_symbol = entrypoint.symbol
        self.ep_line = entrypoint.line
        self.timeout = timeout
        self._home = Path(tempfile.mkdtemp(prefix="raksha-cargo-home-"))
        self._bin: dict[str, Path] = {}         # build root -> test binary path

    # -- plumbing ----------------------------------------------------------

    def _sh(self, cmd: str, cwd: Path, *, env: dict, timeout: float | None = None) -> RunResult:
        try:
            p = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True,
                               timeout=timeout or self.timeout, env=env)
            return RunResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired as e:
            return RunResult(-1, e.stdout or b"", e.stderr or b"", timed_out=True)

    def _env(self, root: Path) -> dict:
        return _cargo_env(self._home, root / "target")

    @staticmethod
    def _find_test_bin(root: Path) -> Path | None:
        deps = root / "target" / "debug" / "deps"
        if not deps.is_dir():
            return None
        cands = [p for p in deps.glob("raksha_fuzz-*")
                 if p.is_file() and p.suffix != ".d" and os.access(p, os.X_OK)]
        return max(cands, key=lambda p: p.stat().st_mtime) if cands else None

    # -- Target protocol ---------------------------------------------------

    def build(self, patch_diff: str | None, *, flavour: str = "sanitizer") -> BuildResult:
        label = "patched" if patch_diff else "vulnerable"
        root = Path(tempfile.mkdtemp(prefix=f"raksha-rust-{label}-"))
        shutil.copytree(self.source_root, root, dirs_exist_ok=True)
        if patch_diff:
            (root / ".raksha.patch").write_text(patch_diff)
            applied = self._sh("git apply -p1 .raksha.patch 2>/dev/null || patch -p1 < .raksha.patch",
                               root, env=self._env(root))
            if applied.exit_code != 0:
                return BuildResult(False, label, "patch did not apply:\n" + applied.text, root)
        (root / "tests").mkdir(exist_ok=True)
        (root / "tests" / "raksha_fuzz.rs").write_text(self.harness)
        built = self._sh("cargo build --tests", root, env=self._env(root))
        ok = built.exit_code == 0
        if ok:
            b = self._find_test_bin(root)
            if b is None:
                return BuildResult(False, label, "harness test binary not found after build", root)
            self._bin[str(root)] = b
        return BuildResult(ok, label, built.text[-800:], root)

    def _run_bin(self, build: BuildResult, data: bytes) -> RunResult:
        """Run one input through the compiled harness binary. Falls back to `cargo test` if the
        binary path was not captured (e.g. a build from another process)."""
        assert build.root is not None
        root = build.root
        (root / _INPUT_FILE).write_bytes(data)
        shutil.rmtree(root / _CORPUS_DIR, ignore_errors=True)   # ensure single-input mode
        b = self._bin.get(str(root)) or self._find_test_bin(root)
        if b is not None:
            return self._sh(f"{b} --test-threads=1", root, env=self._env(root), timeout=60)
        return self._sh("cargo test --test raksha_fuzz -q", root, env=self._env(root), timeout=90)

    def run(self, build: BuildResult, data: bytes) -> RunResult:
        return self._run_bin(build, data)

    def run_tests(self, build: BuildResult) -> TestResult:
        """The crate's own regression suite (unit + integration tests), excluding our harness."""
        assert build.root is not None
        r = self._sh("cargo test --lib --bins -q", build.root, env=self._env(build.root), timeout=120)
        if "no library targets" in r.text or "0 tests" in r.text and r.exit_code == 0:
            return TestResult(ran=0, failed=0, log="no non-harness tests in the crate")
        return TestResult(ran=1, failed=0 if r.exit_code == 0 else 1, log=r.text[-600:])

    def run_added_test(self, build: BuildResult, test_source: str) -> TestResult:
        return TestResult(0, 0, "added-test not wired for the Rust lane")

    def covered_lines(self, build: BuildResult, inputs: list[bytes]) -> set[tuple[str, int]]:
        """Fix-site-enclosing function body lines in the *patched* source, once the harness is
        confirmed to still run. Heuristic — see the module docstring: stable cargo has no line
        coverage, so this reports the neighbourhood the corpus reaches and has teeth against a fix
        that deletes the vulnerable function (its lines then vanish from the set)."""
        assert build.root is not None
        covered: set[tuple[str, int]] = set()
        src = build.root / self.ep_path
        if not src.is_file():
            return covered
        # confirm the harness still executes on this build (links against the crate); if nothing
        # runs cleanly we cannot claim the corpus reaches anything.
        ran_ok = False
        for data in inputs[:3]:
            r = self._run_bin(build, data)
            if not r.timed_out:
                ran_ok = True
                break
        if not ran_ok:
            return covered
        span = self._fn_span(src.read_text(errors="replace"), self.ep_symbol)
        if span is None:
            return covered
        base = self.ep_path.rsplit("/", 1)[-1]
        lo, hi = span
        for ln in range(lo, hi + 1):
            covered.add((base, ln))
        return covered

    @staticmethod
    def _fn_span(text: str, symbol: str) -> tuple[int, int] | None:
        """1-based [start, end] line range of `fn <symbol>`'s body, by brace matching."""
        m = re.search(rf"\bfn\s+{re.escape(symbol)}\s*\(", text)
        if not m:
            return None
        start_line = text[: m.start()].count("\n") + 1
        i = text.find("{", m.end())
        if i < 0:
            return None
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        end_line = text[: j].count("\n") + 1
        return start_line, end_line

    def can_refuzz(self) -> bool:
        return True

    def refuzz(self, build: BuildResult, seconds: float) -> list[str]:
        """A bounded fresh mutation campaign on the patched build; raw output per crash found."""
        import random
        assert build.root is not None
        rng = random.Random(0xF2B1)                 # distinct from the pov_neighbourhood seed
        seeds = [b"\x01\x01\x05", b"\x02ab", b"\x00", b"", b"\x04wxyz"]
        deadline = time.time() + max(1.0, seconds)
        from ..harness.mutator import _mutate
        oracle = RustPanicOracle()
        crashes: list[str] = []
        pool = list(seeds)
        while time.time() < deadline and len(crashes) < 5:
            base = rng.choice(pool)
            data = _mutate(rng, base)
            r = self._run_bin(build, data)
            if r.exit_code != 0 and oracle.parse(r.text, target="<refuzz>"):
                crashes.append(r.text)
        return crashes

    def discard(self, build: BuildResult) -> None:
        if build.root and Path(build.root).name.startswith("raksha-rust-"):
            self._bin.pop(str(build.root), None)
            shutil.rmtree(build.root, ignore_errors=True)


# ---------------------------------------------------------------- the template

_RS_RANGE = re.compile(
    r"(?P<arr>[A-Za-z_]\w*)\s*\[\s*(?P<lo>[^\]\[]*?)\.\.(?P<eq>=?)\s*(?P<hi>[^\]\[]+?)\s*\]")
_RS_INDEX = re.compile(r"(?P<arr>[A-Za-z_]\w*)\s*\[\s*(?P<idx>[^\].\[]+?)\s*\]")


def rust_bound_index(finding: Finding, root: Path) -> str | None:
    """Clamp an unbounded slice range / index at the fix site to the backing length.

    A slice range `data[2..2 + n]` whose high bound is unchecked becomes
    `data[2..usize::min(2 + n, data.len())]`; a bare index `v[i]` becomes
    `v[usize::min(i, v.len().saturating_sub(1))]`. Produces a real unified diff via difflib (hunk
    lines always match), and NOTHING here decides the fix is correct — the five-check gate does. A
    clamp that is wrong for the target is rejected by the gate's differential / coverage checks, so
    proposing it is safe; accepting it is the gate's call. Mirrors `go_bound_slice`.
    """
    got = _read_fix_site(finding, root)
    if got is None:
        return None
    rel, text = got
    lines = text.splitlines(keepends=True)
    idx = (finding.fix_site_set[0].start_line or 1) - 1
    after = list(lines)
    changed = False
    for i in range(max(0, idx - 2), min(len(lines), idx + 3)):   # the oracle line, give or take
        line = lines[i]
        m = _RS_RANGE.search(line)
        if m:
            arr, lo, hi, eq = (m.group("arr"), m.group("lo").strip(),
                               m.group("hi").strip(), m.group("eq"))
            if f"{arr}.len()" in hi or "min(" in hi:
                continue                                         # already bounded
            if eq:   # inclusive `..=hi` indexes element `hi`, so clamp to the last valid index
                bounded = f"{arr}[{lo}..={arr}.len().saturating_sub(1).min({hi})]"
            else:
                bounded = f"{arr}[{lo}..usize::min({hi}, {arr}.len())]"
            after[i] = line[:m.start()] + bounded + line[m.end():]
            changed = True
            break
        mi = _RS_INDEX.search(line)
        if mi:
            arr, ix = mi.group("arr"), mi.group("idx").strip()
            if ix.isdigit() or f"{arr}.len()" in ix or "min(" in ix:
                continue                                         # constant or already bounded
            bounded = f"{arr}[usize::min({ix}, {arr}.len().saturating_sub(1))]"
            after[i] = line[:mi.start()] + bounded + line[mi.end():]
            changed = True
            break
    return _diff(text, "".join(after), rel) if changed else None


# ---------------------------------------------------------------- autofuzz

@dataclass
class RustAutofuzzResult:
    finding: Finding | None
    entrypoint: Entrypoint | None
    crashing_input: bytes | None
    target: RustFuzzTarget | None
    note: str = ""
    found: bool = False


def _fuzz_until_panic(bin_path: Path, root: Path, env: dict, seeds: list[bytes],
                      fuzztime_s: int) -> bytes | None:
    """Mutate the seeds and run the harness binary until it panics or the budget is spent.

    Deterministic: a fixed RNG seed, so the same crate yields the same crashing input.
    """
    import random
    from ..harness.mutator import _mutate
    rng = random.Random(0x1234)
    oracle = RustPanicOracle()
    # try the raw seeds first (a seed may already crash), then mutate.
    deadline = time.time() + max(1, fuzztime_s)
    pool = list(seeds)
    queue = list(seeds)
    while queue or time.time() < deadline:
        if queue:
            data = queue.pop(0)
        else:
            data = _mutate(rng, rng.choice(pool))
        (root / _INPUT_FILE).write_bytes(data)
        try:
            p = subprocess.run(f"{bin_path} --test-threads=1", shell=True, cwd=str(root),
                               capture_output=True, timeout=30, env=env)
        except subprocess.TimeoutExpired:
            continue
        text = (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")
        if p.returncode != 0 and oracle.parse(text, target="<probe>"):
            return data
        if not queue and len(pool) < 64:
            pool.append(data)
    return None


def rust_autofuzz(target_root: str | Path, *, fuzztime_s: int = 10,
                  max_entrypoints: int = 3) -> RustAutofuzzResult:
    """Synthesize a `cargo test` harness for the best entry point and mutate inputs until it panics.

    Mirrors `go_autofuzz`: discover a `fn name(&[u8])` entry point, synthesize the harness, build it
    once, fuzz until a panic, then build the Finding with a replaying `Reproducer`, record the
    before-replay and `confirm()` it — so it leaves CONFIRMED exactly like every other lane.
    """
    root = Path(target_root).resolve()
    if shutil.which("cargo") is None:
        return RustAutofuzzResult(None, None, None, None, note="cargo toolchain not available")
    candidates = discover_rust(root)
    if not candidates:
        return RustAutofuzzResult(None, None, None, None, note="no Rust &[u8] entry point found")
    crate = _crate_name(root)
    home = Path(tempfile.mkdtemp(prefix="raksha-cargo-home-"))
    seeds = [b"\x01\x01\x05", b"\x02ab", b"\x00", b"", b"\x03xyz", b"\x01\x02\x03\x04"]
    for ep in candidates[:max_entrypoints]:
        harness = synthesize_rust_harness(ep, crate)
        work = Path(tempfile.mkdtemp(prefix="raksha-rust-fuzz-")) / root.name
        shutil.copytree(root, work, dirs_exist_ok=True)
        (work / "tests").mkdir(exist_ok=True)
        (work / "tests" / "raksha_fuzz.rs").write_text(harness)
        env = _cargo_env(home, work / "target")
        built = subprocess.run("cargo build --tests", shell=True, cwd=str(work),
                               capture_output=True, env=env)
        if built.returncode != 0:
            shutil.rmtree(work.parent, ignore_errors=True)
            continue
        bin_path = RustFuzzTarget._find_test_bin(work)
        if bin_path is None:
            shutil.rmtree(work.parent, ignore_errors=True)
            continue
        crasher = _fuzz_until_panic(bin_path, work, env, seeds, fuzztime_s)
        if crasher is None:
            shutil.rmtree(work.parent, ignore_errors=True)
            continue
        # replay the crasher once more to capture the panic text for the oracle
        (work / _INPUT_FILE).write_bytes(crasher)
        p = subprocess.run(f"{bin_path} --test-threads=1", shell=True, cwd=str(work),
                           capture_output=True, timeout=30, env=env)
        text = (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")
        findings = RustPanicOracle().parse(text, target=root.name)
        shutil.rmtree(work.parent, ignore_errors=True)
        if not findings:
            continue
        f = findings[0]
        # the Rust runtime prints crate-relative source paths (src/lib.rs), so the fix site already
        # applies as a/src/lib.rs in the gate's fresh copy — no rebase, unlike the Go lane.
        target = RustFuzzTarget(root, ep, harness)
        f.attach_reproducer(Reproducer.from_bytes(
            crasher, ["cargo", "test", "--test", "raksha_fuzz"],
            detail=f"rust-autofuzz: synthesized cargo-test harness for {ep.symbol}"))
        f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                            abort_signature=f.abort_signature, exit_code=101))
        f.confirm(reason=f"panic reproduced via a synthesized cargo-test harness for {ep.symbol}")
        return RustAutofuzzResult(f, ep, crasher, target,
                                  note=f"panic via raksha_fuzz for {ep.symbol}", found=True)
    return RustAutofuzzResult(None, candidates[0], None, None,
                              note="no panic found within the budget")


# keep Frame importable for callers that rebase (parity with go_fuzz); unused rebase here by design.
__all__ = ["RustFuzzTarget", "RustAutofuzzResult", "rust_autofuzz", "rust_bound_index",
           "discover_rust", "synthesize_rust_harness", "RustPanicOracle", "Frame"]
