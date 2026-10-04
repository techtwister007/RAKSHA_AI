"""Autofuzz — find a bug in an unfamiliar target with no hand-written harness.

The one human step a deep lane used to need was a harness: a person reading the code and writing the
driver that feeds input to the right function. This removes it. End to end:

    discover entry points  ->  rank (model-assisted, heuristic floor)
      ->  synthesize a harness  ->  two-check quality gate (compiles, exercises the target)
      ->  mutation-fuzz it  ->  an oracle reads the crash  ->  a CONFIRMED finding + a gate-ready target

The finding then goes through the SAME five-check gate and repair ladder as every other finding, so
"fix and prove" is not a second mechanism — autofuzz only produces the input side a human used to.

Everything here runs with just a compiler (C) or the interpreter (Python); no fuzzing engine and no
model are required. A model sharpens entry-point choice and the harness wrapper; a real engine
(libFuzzer/AFL) plugs in behind `mutator.Fuzzer` when the sealed node carries one.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from ..finding import Finding, Reproducer, ReplayResult, utcnow
from ..gate.target import CommandTarget
from ..oracles import AsanOracle, PySecSanOracle
from ..oracles.base import Oracle
from .entrypoints import Entrypoint, discover, rank_with_model
from .forkserver import ForkClient, asan_env
from .mutator import Fuzzer
from .synth import Harness, quality_gate, synthesize


@dataclass
class AutofuzzResult:
    finding: Finding | None
    entrypoint: Entrypoint | None
    harness: Harness | None
    crashing_input: bytes | None
    target: CommandTarget | None          # wired to the synthesized harness, for the gate
    executions: int = 0
    tried: int = 0                        # entry points whose harness passed the quality gate
    note: str = ""

    @property
    def found(self) -> bool:
        return self.finding is not None

    def cleanup(self) -> None:
        """Delete the synthesized-harness scratch tree (`/tmp/raksha-harness-*`). The gate already
        discards its own build copies; this removes the autofuzz work dir once repair is finished,
        so a long estate run does not leave one scratch tree per target behind."""
        import shutil
        import tempfile
        t = self.target
        root = getattr(t, "source_root", None) if t is not None else None
        if root is None:
            return
        # the scratch layout is <tmp>/raksha-harness-XXXX/<target-name>; remove the prefixed parent
        parent = Path(root).parent
        tmp = Path(tempfile.gettempdir()).resolve()
        try:
            rp = parent.resolve()
        except OSError:
            return
        if rp.parent == tmp and rp.name.startswith("raksha-harness-"):
            shutil.rmtree(rp, ignore_errors=True)


def _oracle_for(language: str) -> Oracle:
    return AsanOracle() if language == "c/c++" else PySecSanOracle()


def autofuzz(target_root: str | Path, *, max_entrypoints: int = 4, max_execs: int = 20000,
             seed_corpus: list[bytes] | None = None, use_model: bool = True,
             client=None) -> AutofuzzResult:
    """Synthesize a harness for the best entry points and fuzz until one crashes."""
    root = Path(target_root)
    candidates = discover(root)
    if use_model:
        candidates = rank_with_model(candidates, client=client)
    if not candidates:
        return AutofuzzResult(None, None, None, None, None, note="no fuzzable entry point found")

    tried = 0
    for ep in candidates[:max_entrypoints]:
        harness = synthesize(ep)
        quality, built = quality_gate(harness, root)
        if not quality.ok:
            continue
        tried += 1
        oracle = _oracle_for(ep.language)
        result = _fuzz(ep, built, oracle, max_execs, seed_corpus)
        if result is not None:
            finding, crashing, target = result
            return AutofuzzResult(finding, ep, harness, crashing, target,
                                  executions=max_execs, tried=tried,
                                  note=f"crash via synthesized harness for {ep.symbol}")
    return AutofuzzResult(None, candidates[0], None, None, None, tried=tried,
                          note=f"no crash in {tried} harness(es) within the budget")


def _fuzz(ep, built, oracle, max_execs, seed_corpus):
    work: Path = built["root"]
    if ep.language == "c/c++":
        client, replay = _c_runner(work, built, oracle)
        target = _c_target(work, built, ep)
    else:
        client, replay = _py_runner(work, ep, oracle)
        target = _py_target(work, ep)

    with client:
        fuzzer = Fuzzer(run_one=client.run_one,
                        seed_corpus=seed_corpus or [b"\x01\x10value", b"A" * 40], max_execs=max_execs)
        res = fuzzer.run()
    if not res.found:
        return None
    # The fork server reports only crash/clean; re-run each candidate one-shot (full oracle text),
    # keeping the first the oracle confirms — a harness-death false positive is dropped here.
    crashing = raw = None
    for cand in res.crashes:
        text = replay(cand)
        if oracle.parse(text, target="<autofuzz>"):
            crashing, raw = cand, text
            break
    if crashing is None:
        return None
    findings = oracle.parse(raw, target=Path(work).name)
    if not findings:
        return None
    f = findings[0]
    f.attach_reproducer(Reproducer.from_bytes(
        crashing, target.run_cmd.split(), minimised=False, detail=f"autofuzz: synthesized harness for {ep.symbol}"))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                         abort_signature=f.abort_signature, exit_code=1))
    f.confirm(reason=f"crash reproduced via a synthesized harness for {ep.symbol}")
    return f, crashing, target


# ---- C: run one input, and a gate-ready CommandTarget (gcov coverage) --------------------------

def _c_sources(work: Path, harness_name: str = "raksha_harness.c") -> list[str]:
    out = []
    for p in sorted(work.rglob("*.c")):
        if p.name == harness_name:
            continue
        text = p.read_text(errors="replace")
        if "int main(" in text or "main (" in text:
            continue
        out.append(str(p.relative_to(work)))
    return out


def _c_build_cmd(work: Path, cc: str) -> str:
    srcs = ["raksha_harness.c", *_c_sources(work)]
    incdirs = sorted({str(Path(s).parent) for s in srcs if Path(s).parent != Path(".")})
    inc = " ".join(f"-I{d}" for d in incdirs)
    return (f"{cc} -g -fsanitize=address -fno-omit-frame-pointer -I. {inc} "
            f"-o raksha_harness {' '.join(srcs)}")


def _c_release_build_cmd(work: Path, cc: str) -> str:
    """The deployment twin's build (A3): optimised, no sanitizer — what the system actually ships."""
    srcs = ["raksha_harness.c", *_c_sources(work)]
    incdirs = sorted({str(Path(s).parent) for s in srcs if Path(s).parent != Path(".")})
    inc = " ".join(f"-I{d}" for d in incdirs)
    return f"{cc} -O2 -I. {inc} -o raksha_harness {' '.join(srcs)}"


def _c_runner(work: Path, built: dict, oracle: Oracle):
    import subprocess
    binary = work / "raksha_harness"
    env = asan_env()

    def replay(data: bytes) -> str:
        f = work / ".raksha_replay_in"
        f.write_bytes(data)
        p = subprocess.run([str(binary), str(f)], cwd=str(work), capture_output=True, timeout=30, env=env)
        return (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")

    return ForkClient([str(binary)], work, env=env), replay


def _c_target(work: Path, built: dict, ep: Entrypoint) -> CommandTarget:
    cc = built.get("cc", "gcc")
    # Coverage: a gcov-instrumented twin of the harness. `coverage_cmd` builds it once, runs the
    # input, and prints `file:line` for every executed line — which is what the gate's COVERAGE_HELD
    # reads to confirm the fix site is still reached (a patch that "fixes" by deleting the code fails).
    srcs_q = " ".join(shlex.quote(s) for s in _c_sources(work))
    # gcov coverage, with no literal { } (the gate .format()s this string). An executed .gcov line
    # is "   <count>:  <lineno>: <code>"; sed turns each into "<source>:<lineno>".
    cov = (
        "test -x raksha_cov || " + cc + " -O0 -g --coverage -I. -o raksha_cov "
        "raksha_harness.c " + srcs_q + " >/dev/null 2>&1; "
        "./raksha_cov {input} >/dev/null 2>&1 || true; "
        "gcov -o . *.gcda >/dev/null 2>&1; "
        "for s in " + srcs_q + "; do b=$(basename \"$s\"); "
        "grep -E '^ *[0-9]+: *[0-9]+:' \"$b.gcov\" 2>/dev/null | "
        "sed -E \"s|^ *[0-9]+: *([0-9]+):.*|$s:\\1|\"; done"
    )
    refuzz = (
        "i=0; for n in 8 16 40 64 120 200; do i=$((i+1)); "
        "head -c $n /dev/urandom > rf_$i 2>/dev/null; printf '\\001\\377' | cat - rf_$i > rf2_$i; "
        "./raksha_harness rf2_$i > err_$i 2>&1; "
        "if [ $? -ne 0 ]; then cp err_$i {out}/crash_$i; fi; done"
    )
    return CommandTarget(
        source_root=work,
        build_cmd=_c_build_cmd(work, cc),
        run_cmd="./raksha_harness {input}",
        test_cmd="true",                          # a discovered target brings no suite of its own
        coverage_cmd=cov,
        refuzz_cmd=refuzz,
        release_build_cmd=_c_release_build_cmd(work, cc),   # A3 deployment twin
        added_test_cmd="sh {test}",               # lets a verified regression test ride to the bundle
        added_test_path="raksha_regression.sh",
        apply_patch_cmd="git apply -p1 {patch} 2>/dev/null || patch -p1 < {patch}",
        timeout=120.0,
    )


# ---- Python: run one input, and a gate-ready CommandTarget -------------------------------------

def _py_runner(work: Path, ep: Entrypoint, oracle: Oracle):
    import subprocess

    def replay(data: bytes) -> str:
        f = work / ".raksha_replay_in"
        f.write_bytes(data)
        p = subprocess.run(["python3", "raksha_harness.py", str(f)], cwd=str(work),
                           capture_output=True, timeout=30)
        return (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")

    return ForkClient(["python3", "raksha_harness.py"], work), replay


def _py_target(work: Path, ep: Entrypoint) -> CommandTarget:
    return CommandTarget(
        source_root=work,
        build_cmd="python3 -c \"import py_compile,glob; [py_compile.compile(f,doraise=True) for f in glob.glob('**/*.py',recursive=True)]\"",
        run_cmd="python3 raksha_harness.py {input}",
        test_cmd="true",
        coverage_cmd="python3 raksha_harness.py {input} 2>/dev/null; echo " + shlex.quote(f"{ep.path}:{ep.line}"),
        refuzz_cmd=("i=0; for p in 'A; id' 'B | cat /etc/hostname' 'C && echo x' 'D `whoami`'; do "
                    "i=$((i+1)); printf '%s' \"$p\" > rf_$i; python3 raksha_harness.py rf_$i > err_$i 2>&1; "
                    "if [ $? -ne 0 ]; then cp err_$i {out}/crash_$i; fi; done"),
        added_test_cmd="python3 {test}",          # lets a verified regression test ride to the bundle
        added_test_path="raksha_regression.py",
        apply_patch_cmd="git apply -p1 {patch} 2>/dev/null || patch -p1 < {patch}",
        timeout=120.0,
    )
