"""B5 — Java with no hand-written harness: discover a public static entry point, synthesize a driver.

The Java mirror of the C/Python autofuzz branch and of `js_sink.py`. With only a JDK on the box:

    discover `public static <T> name(byte[] | String)` under src/main/java
      ->  synthesize `RakshaDriver.java` that feeds a file's bytes to it and, on any uncaught
          Throwable, prints the exception in Jazzer's own `== Java Exception:` / `\tat` format
      ->  compile the target's main sources + the driver with `javac` (no Maven, no network)
      ->  mutation-fuzz in BATCHES (one JVM runs a directory of inputs; a JVM per input would cost
          ~0.3 s each), stop at the first throwable
      ->  JazzerOracle parses the output unchanged  ->  B6 agreement replay  ->  B2 minimise
      ->  B7 contract check  ->  a CONFIRMED finding + a gate-ready CommandTarget

Exceptions the entry point *declares* (`throws X`) are its contract, not a defect, and are never
reported. The gate's test check runs the project's own JUnit suite through `mvn -o` when a pom and
Maven are present (offline, so a cold `~/.m2` fails loudly rather than downloading).
"""

from __future__ import annotations

import random
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..contract import demotion_reason
from ..finding import Finding, Reproducer, ReplayResult, utcnow
from ..gate.target import CommandTarget
from ..harness.entrypoints import Entrypoint, _name_bonus
from ..harness.mutator import _mutate
from ..minimise import minimise
from ..oracles.jazzer import JazzerOracle
from ..harness import names
from ..sandbox import run_target

DRIVER = names.JAVA_DRIVER
_OUT = names.JAVA_OUT
_SKIP = {".git", "target", "build", "test", "tests", _OUT}

_PKG = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_METHOD = re.compile(
    r"public\s+static\s+(?:final\s+)?(?P<ret>[\w<>\[\],.? ]+?)\s+(?P<name>\w+)\s*\(\s*"
    r"(?:final\s+)?(?P<type>byte\s*\[\]|String)\s+\w+\s*\)\s*(?:throws\s+(?P<throws>[\w.,\s]+?))?\s*\{")
_CLASS = re.compile(r"\b(?:public\s+)?(?:final\s+)?class\s+(\w+)")

_SEEDS = [b"\x02ab", b"\x00", b"hello", b"\x01A", b"{\"a\":1}", b"A" * 16]


@dataclass
class JavaEntrypoint:
    ep: Entrypoint
    fqcn: str
    arg: str                      # "bytes" | "string"
    throws: tuple[str, ...] = ()


def discover_java(root: str | Path, *, limit: int = 20) -> list[JavaEntrypoint]:
    """Public static one-argument (byte[] / String) methods under the main sources, best first."""
    root = Path(root)
    base = root / "src" / "main" / "java"
    base = base if base.is_dir() else root
    out: list[JavaEntrypoint] = []
    for p in sorted(base.rglob("*.java")):
        if any(part in _SKIP for part in p.relative_to(root).parts) or names.is_ours(p.name):
            continue
        text = p.read_text(errors="replace")
        pkg = _PKG.search(text)
        cls = _CLASS.search(text)
        if not cls:
            continue
        fqcn = (pkg.group(1) + "." if pkg else "") + cls.group(1)
        for m in _METHOD.finditer(text):
            if m.group("name") == "main":
                continue
            line = text[: m.start()].count("\n") + 1
            arg = "bytes" if "byte" in m.group("type") else "string"
            throws = tuple(t.strip().rsplit(".", 1)[-1] for t in (m.group("throws") or "").split(",") if t.strip())
            score = 3.0 + _name_bonus(m.group("name")) + (0.5 if arg == "bytes" else 0.0)
            ep = Entrypoint("java", str(p.relative_to(root)), m.group("name"), line, arg, score,
                            signature=m.group(0).rstrip("{ ").strip())
            out.append(JavaEntrypoint(ep, fqcn, arg, throws))
    out.sort(key=lambda j: (-j.ep.score, j.ep.path, j.ep.line))
    return out[:limit]


def synthesize_driver(je: JavaEntrypoint) -> str:
    """The driver source. A directory argument runs every file in it (sorted) in one JVM and stops at
    the first throwable, naming the input; a file argument runs that one input."""
    call_arg = "d" if je.arg == "bytes" else "new String(d, java.nio.charset.StandardCharsets.UTF_8)"
    declared = ", ".join(f'"{t}"' for t in je.throws)
    return f"""import java.nio.file.*;
import java.util.*;

public final class {DRIVER} {{
    private static final Set<String> DECLARED = new HashSet<>(Arrays.asList({declared}));

    static void one(byte[] d) throws Throwable {{
        {je.fqcn}.{je.ep.symbol}({call_arg});
    }}

    static String report(Throwable t) {{
        String msg = t.getMessage() == null ? "" : ": " + t.getMessage().replace('\\n', ' ');
        StringBuilder b = new StringBuilder("== Java Exception: " + t.getClass().getName() + msg + "\\n");
        for (StackTraceElement e : t.getStackTrace()) b.append("\\tat ").append(e).append("\\n");
        return b.toString();
    }}

    // Fresh campaign for CLEAN_REFUZZ: seeded random inputs, half with a large leading byte (the
    // header shape length-prefixed formats over-claim with), for `seconds` of wall time.
    static void refuzz(int seconds, Path out) throws Exception {{
        Random r = new Random(0xC0FFEE);
        long end = System.currentTimeMillis() + seconds * 1000L;
        int k = 0;
        while (System.currentTimeMillis() < end && k < 200000) {{
            byte[] d = new byte[r.nextInt(64)];
            r.nextBytes(d);
            if (d.length > 0 && (k & 1) == 0) d[0] = (byte) (0x40 + r.nextInt(0xC0));
            k++;
            try {{
                one(d);
            }} catch (Throwable t) {{
                if (DECLARED.contains(t.getClass().getSimpleName())) continue;
                Files.write(out.resolve("crash_" + k), report(t).getBytes());
                return;
            }}
        }}
    }}

    public static void main(String[] a) throws Exception {{
        if (a.length == 3 && a[0].equals("--refuzz")) {{ refuzz(Integer.parseInt(a[1]), Paths.get(a[2])); return; }}
        List<Path> files = new ArrayList<>();
        Path p = Paths.get(a[0]);
        if (Files.isDirectory(p)) {{
            try (java.util.stream.Stream<Path> s = Files.list(p)) {{ s.sorted().forEach(files::add); }}
        }} else {{
            files.add(p);
        }}
        for (Path f : files) {{
            byte[] d = Files.readAllBytes(f);
            try {{
                one(d);
            }} catch (Throwable t) {{
                if (DECLARED.contains(t.getClass().getSimpleName())) continue;  // its declared contract
                System.err.println("RAKSHA_INPUT " + f.getFileName());
                System.err.print(report(t));
                System.exit(77);
            }}
        }}
        System.out.println("RAKSHA_OK " + files.size());
    }}
}}
"""


def _sources_cmd() -> str:
    return (f"mkdir -p {_OUT} && javac -nowarn -d {_OUT} "
            f"$(find src/main/java -name '*.java' 2>/dev/null || find . -name '*.java' -not -path './{_OUT}/*') "
            f"{DRIVER}.java")


def method_span(path: Path, decl_line: int) -> tuple[int, int]:
    """(first, last) 1-based lines of the method declared at `decl_line`, by brace matching."""
    lines = path.read_text(errors="replace").splitlines()
    depth, opened = 0, False
    for i in range(decl_line - 1, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1; opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            return decl_line, i + 1
    return decl_line, len(lines)


def java_target(work: str | Path, je: JavaEntrypoint, *, timeout: float = 420.0) -> CommandTarget:
    """A CommandTarget over the synthesized driver, for the gate."""
    work = Path(work)
    tests = "mvn -o -q -B test" if (work / "pom.xml").exists() and shutil.which("mvn") else "true"
    # Coverage is a HEURISTIC, stated as such (as for Rust): a JDK has no line coverage without an
    # agent we cannot fetch offline, so an input that runs the entry method without the driver
    # failing to start is credited with the method's whole span. It cannot tell early-return lines
    # from the rest; the differential corpus and the PoV replay carry the precise evidence.
    span = method_span(work / je.ep.path, je.ep.line)
    (work / names.dot("lines")).write_text(
        "".join(f"{je.ep.path}:{n}\n" for n in range(span[0], span[1] + 1)))
    return CommandTarget(
        source_root=work,
        build_cmd=_sources_cmd(),
        run_cmd=f"java -cp {_OUT} {DRIVER} {{input}}",
        test_cmd=tests,
        coverage_cmd=(f"java -cp {_OUT} {DRIVER} {{input}} >/dev/null 2>&1; "
                      f"[ $? -le 77 ] && cat {names.dot('lines')}"),
        refuzz_cmd=f"java -cp {_OUT} {DRIVER} --refuzz {{seconds}} {{out}}",
        apply_patch_cmd="git apply -p1 {patch} 2>/dev/null || patch -p1 < {patch}",
        timeout=timeout,
    )


@dataclass
class JavaAutofuzzResult:
    finding: Finding | None
    entrypoint: JavaEntrypoint | None
    crashing_input: bytes | None
    target: CommandTarget | None
    executions: int = 0
    note: str = ""
    benign_corpus: list = field(default_factory=list)
    demoted: list = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.finding is not None


def _run(work: Path, arg: str, timeout: float = 120.0) -> str:
    p = run_target(["java", "-cp", _OUT, DRIVER, arg], str(work), timeout=timeout)
    return (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")


def java_autofuzz(target_root: str | Path, *, max_execs: int = 4000, batch: int = 400,
                  max_entrypoints: int = 4, seed: int = 0) -> JavaAutofuzzResult:
    """Discover, synthesize, fuzz in batches, confirm — the Java branch of autofuzz."""
    if shutil.which("javac") is None or shutil.which("java") is None:
        return JavaAutofuzzResult(None, None, None, None, note="no JDK on this host — Java lane skipped")
    root = Path(target_root)
    candidates = discover_java(root)[:max_entrypoints]
    if not candidates:
        return JavaAutofuzzResult(None, None, None, None, note="no public static byte[]/String entry point")
    oracle = JazzerOracle()
    demoted: list[Finding] = []
    execs = 0
    for je in candidates:
        work = Path(tempfile.mkdtemp(prefix=names.SCRATCH)) / root.name
        shutil.copytree(root, work, symlinks=True,
                        ignore=shutil.ignore_patterns("target", ".raksha*", _OUT, f"*{names.TOKEN}*"))
        (work / f"{DRIVER}.java").write_text(synthesize_driver(je))
        built = run_target(_sources_cmd(), str(work), shell=True, timeout=600)
        if built.returncode != 0:
            continue
        rng = random.Random(seed)
        corpus = list(_SEEDS)
        benign: list[bytes] = []
        crashing = None
        inbox = work / names.dot("batch")
        while execs < max_execs and crashing is None:
            if inbox.exists():
                shutil.rmtree(inbox)
            inbox.mkdir()
            n = min(batch, max_execs - execs)
            cands = corpus[:n] if execs == 0 else [_mutate(rng, rng.choice(corpus)) for _ in range(n)]
            for i, c in enumerate(cands):
                (inbox / f"{i:06d}").write_bytes(c)
            out = _run(work, str(inbox))
            m = re.search(r"RAKSHA_INPUT (\d+)", out)
            done = int(m.group(1)) if m else len(cands)
            execs += done + (1 if m else 0)
            ok = cands[:done]
            benign.extend(ok[: max(0, 32 - len(benign))])
            corpus.extend(c for c in ok[:8] if c not in corpus)
            if m and oracle.parse(out, target="<java-autofuzz>"):
                crashing = cands[done]
        shutil.rmtree(inbox, ignore_errors=True)
        if crashing is None:
            continue
        one = work / names.dot("input")

        def replay(data: bytes) -> str:
            one.write_bytes(data)
            return _run(work, one.name)

        if not oracle.parse(replay(crashing), target="<java-autofuzz>"):   # B6 agreement
            continue
        try:
            reduced = minimise(crashing, lambda b: bool(oracle.parse(replay(b), target="<java-autofuzz>")))
            if reduced and oracle.parse(replay(reduced), target="<java-autofuzz>"):
                crashing = reduced
        except Exception:  # noqa: BLE001 — best-effort
            pass
        findings = oracle.parse(replay(crashing), target=root.name)
        if not findings:
            continue
        f = findings[0]
        _resolve_sites(f, work)
        target = java_target(work, je)
        reason = demotion_reason(work, je.ep.path, je.ep.symbol)
        if reason:
            f.contract = reason
            demoted.append(f)
            continue
        f.attach_reproducer(Reproducer.from_bytes(
            crashing, target.run_cmd.split(), minimised=True,
            detail=f"java-autofuzz: synthesized driver for {je.fqcn}.{je.ep.symbol}"))
        f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                             abort_signature=f.abort_signature, exit_code=77))
        f.confirm(reason=f"exception reproduced via a synthesized driver for {je.fqcn}.{je.ep.symbol}")
        return JavaAutofuzzResult(f, je, crashing, target, executions=execs,
                                  note=f"crash via synthesized driver for {je.ep.symbol}",
                                  benign_corpus=benign, demoted=demoted)
    note = "no crash within the budget"
    if demoted:
        note += f"; {len(demoted)} contract-violation crash(es) held at SUSPECTED"
    return JavaAutofuzzResult(None, candidates[0], None, None, executions=execs, note=note,
                              demoted=demoted)


def _resolve_sites(finding: Finding, root: Path) -> None:
    """A JVM frame names `com/x/Parser.java`; the patch needs `src/main/java/com/x/Parser.java`."""
    import dataclasses

    def real(uri: str | None) -> str | None:
        if not uri or (root / uri).exists():
            return uri
        hits = sorted(q for q in root.rglob(Path(uri).name)
                      if str(q).endswith(uri) and _OUT not in q.parts)
        return str(hits[0].relative_to(root)) if hits else uri

    finding.fix_site_set = [dataclasses.replace(s, uri=real(s.uri)) for s in finding.fix_site_set]
    finding.frames = [dataclasses.replace(fr, uri=real(fr.uri)) for fr in finding.frames]


# ---------------------------------------------------------------- repair template (zero inference)

_INDEX = re.compile(r"(?P<arr>\b[A-Za-z_]\w*)\s*\[(?P<idx>[^\[\]]+)\]")
_FOR = re.compile(r"for\s*\((?P<init>[^;]*);(?P<cond>[^;]*);(?P<step>[^)]*)\)")


def java_bound_index(finding: Finding, root: str | Path) -> str | None:
    """Bound the array read at the fix site by the array's length.

    Inside a `for` loop the loop condition gains `&& <idx> < <arr>.length` (the loop simply stops
    where the data ends); otherwise the statement is wrapped in a bounds guard. Honest inputs take
    exactly the same path, which the gate's differential corpus proves.
    """
    from ..repair_templates import _diff
    root = Path(root)
    if not finding.fix_site_set or not finding.fix_site_set[0].start_line:
        return None
    site = finding.fix_site_set[0]
    path = root / site.uri
    if not path.exists():
        return None
    text = path.read_text()
    lines = text.splitlines(keepends=True)
    i = site.start_line - 1
    if not 0 <= i < len(lines):
        return None
    m = _INDEX.search(lines[i])
    if not m or m.group("arr") in {"int", "byte", "char", "long", "String"}:
        return None
    arr, idx = m.group("arr"), m.group("idx").strip()
    guard = f"({idx}) >= 0 && ({idx}) < {arr}.length"
    after = list(lines)
    for j in range(i - 1, max(-1, i - 8), -1):
        fm = _FOR.search(lines[j])
        if fm:
            if f"{arr}.length" in fm.group("cond"):
                return None                                   # already bounded
            new = f"{fm.group('init')};{fm.group('cond').rstrip()} && {guard};{fm.group('step')}"
            after[j] = lines[j][:fm.start()] + f"for ({new.strip()})" + lines[j][fm.end():]
            return _diff(text, "".join(after), site.uri)
    indent = re.match(r"\s*", lines[i]).group(0)
    after[i] = f"{indent}if ({guard}) {{\n{lines[i].rstrip()}\n{indent}}}\n"
    return _diff(text, "".join(after), site.uri)
