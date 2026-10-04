"""JavaScript / Node adapter — the deep lane for a target that ships no fuzz harness.

The JavaScript mirror of raksha/adapters/python_sink.py + the Python branch of
raksha/harness/autofuzz.py. End to end, with only `node` (built-in modules) on the box:

    discover the entry point  ->  copy the target + the jssinkguard preload into a work dir
      ->  mutation-fuzz it (raksha.harness.mutator.Fuzzer), the guard aborting at an injected sink
      ->  the JsSinkOracle reads the banner  ->  a CONFIRMED finding + a gate-ready CommandTarget

`jssinkguard.js` is the harness: a Node preload (built-ins only) that monkeypatches the dangerous
shell / eval / code-loading sinks before requiring the target and calling the discovered entry point
with the fuzzed input as its single string argument — no hand-written driver. The richer "take-lane"
alternative is Jazzer.js with its command-injection sanitizer; it is not used here because it needs a
network install (`npm install`), and it would plug in behind the same oracle banner when bundled.

The repair template `js_shell_safe` lives here (not in repair_templates.py): it rewrites the
injectable shell sink to a non-shell `execFileSync('cmd', [args...])` form. The five-check gate
proves the fix like any other.
"""

from __future__ import annotations

import difflib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..finding import Finding, Reproducer, ReplayResult, utcnow
from ..gate.target import CommandTarget
from ..harness.entrypoints import Entrypoint, _name_bonus
from ..harness.mutator import Fuzzer
from ..oracles.js_sink import JsSinkOracle

_SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", "__pycache__", ".venv",
              "test", "tests", "__tests__"}
_JS_SUFFIXES = {".js", ".cjs", ".mjs", ".ts"}
_HARNESS = Path(__file__).resolve().parents[1] / "harness" / "jssinkguard.js"

# Injection payloads: each carries a shell metacharacter, so on the vulnerable build the guard fires
# and on the patched (non-shell) build it does not. A benign spec ("10m") must NOT fire.
_SEED_CORPUS = [b"10m", b"a; id", b"b | id", b"c && id", b"d `id`", b"e $(id)", b"f\nid", b"g > h"]
_REFUZZ_PAYLOADS = ["A; id", "B | cat /etc/hostname", "C && echo x", "D `whoami`", "E $(id)", "F\nid"]


# ---------------------------------------------------------------- discovery

# `function name(arg)`  |  `exports.name = (arg) =>` / `= function (arg)`  |  `const name = (arg) =>`
# |  Express `app.get('/x', (req, res) => ...)`. One string-ish argument is the fuzzable shape.
_JS_FUNC = re.compile(
    r"^\s*(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(\s*(?P<arg>[A-Za-z_$][\w$]*)\s*\)",
    re.MULTILINE)
_JS_EXPORT = re.compile(
    r"(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?"
    r"(?:function\s*)?\(?\s*(?P<arg>[A-Za-z_$][\w$]*)\s*\)?\s*=?>?", re.MULTILINE)
_JS_CONST = re.compile(
    r"^\s*(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?"
    r"\(?\s*(?P<arg>[A-Za-z_$][\w$]*)\s*\)?\s*=>", re.MULTILINE)
_JS_ROUTE = re.compile(
    r"\.(?:get|post|put|delete|patch|all|use)\s*\(\s*['\"](?P<name>[^'\"]+)['\"]\s*,\s*"
    r"(?:async\s+)?\(\s*(?P<arg>[A-Za-z_$][\w$]*)", re.MULTILINE)


def _js_entrypoints(text: str, path: str) -> list[Entrypoint]:
    """One-argument functions worth fuzzing in a JS/TS source. Reads source only; never executes."""
    out: list[Entrypoint] = []
    seen: set[str] = set()
    for rx, kind in ((_JS_FUNC, "one_arg"), (_JS_EXPORT, "export"),
                     (_JS_CONST, "arrow"), (_JS_ROUTE, "route")):
        for m in rx.finditer(text):
            name = m.group("name")
            if kind != "route" and name.startswith("_"):
                continue
            if name in seen:
                continue
            seen.add(name)
            line = text[: m.start()].count("\n") + 1
            score = 3.0 + _name_bonus(name) + (0.5 if kind == "route" else 0.0)
            out.append(Entrypoint("javascript", path, name, line, kind, score,
                                  signature=m.group(0).strip()))
    return out


def discover_js(root: str | Path, *, limit: int = 20) -> list[Entrypoint]:
    """Candidate JS entry points under `root`, best first. (entrypoints.discover has no JS scanner,
    so the JS lane carries its own here rather than editing that module.)"""
    root = Path(root)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and p.suffix in _JS_SUFFIXES
        and not any(part in _SKIP_DIRS for part in p.parts)]
    found: list[Entrypoint] = []
    for p in files:
        rel = str(p.relative_to(root)) if root.is_dir() else p.name
        try:
            found.extend(_js_entrypoints(p.read_text(errors="replace"), rel))
        except OSError:
            continue
    found.sort(key=lambda e: (-e.score, e.path, e.line))
    return found[:limit]


# ---------------------------------------------------------------- the gate-ready target

def _env_for(entrypoint: Entrypoint) -> dict[str, str]:
    spec = entrypoint.path if entrypoint.path.startswith((".", "/")) else "./" + entrypoint.path
    return {"RAKSHA_JS_MODULE": spec, "RAKSHA_JS_SYMBOL": entrypoint.symbol}


def js_target(work: str | Path, entrypoint: Entrypoint, *, timeout: float = 120.0) -> CommandTarget:
    """A CommandTarget that drives the target through `node jssinkguard.js <input>`.

    Mirrors `_py_target`: build is a syntax check, run invokes the guard, tests are a no-op (a
    discovered target brings no suite), coverage prints the fix-site line, and refuzz replays a small
    battery of injection payloads — the JavaScript shapes of the Python lane's refuzz loop.
    """
    work = Path(work)
    quoted_site = f"{entrypoint.path}:{entrypoint.line}"
    payloads = " ".join("'" + p.replace("'", "'\\''") + "'" for p in _REFUZZ_PAYLOADS)
    return CommandTarget(
        source_root=work,
        build_cmd=f"node --check {entrypoint.path}",            # "COMPILES" for JS: it parses
        run_cmd="node jssinkguard.js {input}",
        test_cmd="true",
        coverage_cmd="node jssinkguard.js {input} 2>/dev/null; echo " + _shq(quoted_site),
        refuzz_cmd=("i=0; for p in " + payloads + "; do i=$((i+1)); printf '%s' \"$p\" > rf_$i; "
                    "node jssinkguard.js rf_$i > err_$i 2>&1; "
                    "if [ $? -ne 0 ]; then cp err_$i {out}/crash_$i; fi; done"),
        apply_patch_cmd="git apply -p1 {patch} 2>/dev/null || patch -p1 < {patch}",
        timeout=timeout,
        env=_env_for(entrypoint),
    )


def _shq(s: str) -> str:
    import shlex
    return shlex.quote(s)


# ---------------------------------------------------------------- run one input + replay

def _js_runner(work: Path, entrypoint: Entrypoint):
    """A `run_one(data) -> bool` for the fuzzer and a `replay(data) -> str` for one-shot oracle text.

    No fork server (that is the C/Python engine's optimisation): node starts fast, and the seed
    corpus fires the guard in the first handful of executions, so a plain subprocess per input is
    enough — and it keeps the lane to Node built-ins with no engine installed.
    """
    import os
    env = {**os.environ, **_env_for(entrypoint)}
    infile = work / ".raksha_js_in"

    def run_one(data: bytes) -> bool:
        infile.write_bytes(data)
        p = subprocess.run(["node", "jssinkguard.js", str(infile)], cwd=str(work),
                           capture_output=True, timeout=30, env=env)
        return p.returncode == 99 or JsSinkOracle().detects(
            (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace"))

    def replay(data: bytes) -> str:
        infile.write_bytes(data)
        p = subprocess.run(["node", "jssinkguard.js", str(infile)], cwd=str(work),
                           capture_output=True, timeout=30, env=env)
        return (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")

    return run_one, replay


# ---------------------------------------------------------------- autofuzz

@dataclass
class JsAutofuzzResult:
    finding: Finding | None
    entrypoint: Entrypoint | None
    harness: str | None                   # the jssinkguard preload path, relative to the work dir
    crashing_input: bytes | None
    target: CommandTarget | None          # wired to the harness, for the gate
    note: str = ""

    @property
    def found(self) -> bool:
        return self.finding is not None


def _scratch(target_root: Path) -> Path:
    work = Path(tempfile.mkdtemp(prefix="raksha-js-")) / Path(target_root).name
    shutil.copytree(target_root, work, symlinks=True)
    shutil.copy2(_HARNESS, work / "jssinkguard.js")
    return work


def js_autofuzz(target_root: str | Path, *, max_execs: int = 6000) -> JsAutofuzzResult:
    """Discover a JS entry point, synthesize the jssinkguard wiring, fuzz until the sink oracle
    fires, and confirm the crash — the JavaScript branch of `raksha.harness.autofuzz.autofuzz`."""
    root = Path(target_root)
    candidates = discover_js(root)
    if not candidates:
        return JsAutofuzzResult(None, None, None, None, None, note="no fuzzable JS entry point found")
    ep = candidates[0]
    work = _scratch(root)
    oracle = JsSinkOracle()
    run_one, replay = _js_runner(work, ep)

    fuzzer = Fuzzer(run_one=run_one, seed_corpus=list(_SEED_CORPUS), max_execs=max_execs)
    res = fuzzer.run()
    if not res.found:
        return JsAutofuzzResult(None, ep, "jssinkguard.js", None, None,
                                note="no crash within the budget")

    target = js_target(work, ep)
    crashing = raw = None
    for cand in res.crashes:
        text = replay(cand)
        if oracle.parse(text, target="<autofuzz>"):
            crashing, raw = cand, text
            break
    if crashing is None:
        return JsAutofuzzResult(None, ep, "jssinkguard.js", None, target,
                                note="guard fired but no oracle-confirmed crash")

    findings = oracle.parse(raw, target=Path(work).name)
    if not findings:
        return JsAutofuzzResult(None, ep, "jssinkguard.js", None, target,
                                note="oracle did not parse the crash")
    f = findings[0]
    f.attach_reproducer(Reproducer.from_bytes(
        crashing, target.run_cmd.split(), minimised=False,
        detail=f"js-autofuzz: jssinkguard harness for {ep.symbol}"))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                         abort_signature=f.abort_signature, exit_code=99))
    f.confirm(reason=f"injection reproduced via the jssinkguard harness for {ep.symbol}")
    return JsAutofuzzResult(f, ep, "jssinkguard.js", crashing, target,
                            note=f"injection via jssinkguard harness for {ep.symbol}")


# ---------------------------------------------------------------- repair template

# `execSync('echo converting: ' + spec)` -> `execFileSync('echo', ['converting:', spec])`
_JS_SHELL = re.compile(
    r"(?P<fn>exec|execSync|spawn|spawnSync)\s*\(\s*"
    r"(?P<q>['\"])(?P<prefix>(?:\\.|(?!(?P=q)).)*)(?P=q)\s*\+\s*(?P<arg>[A-Za-z_$][\w$.]*)\s*\)")
_NON_SHELL = {"exec": "execFile", "execSync": "execFileSync", "spawn": "spawn", "spawnSync": "spawnSync"}


def js_shell_safe(finding: Finding, root: str | Path) -> str | None:
    """Rewrite the injectable shell sink at the fix site to a non-shell argument-list form.

    `execSync('echo converting: ' + spec)` becomes `execFileSync('echo', ['converting:', spec])`:
    an argument vector passed straight to the program, with no shell to interpret metacharacters.
    Any needed `child_process` binding (e.g. `execFileSync`) is added to the import. Produces a real
    unified diff (difflib, so the hunk line numbers always match); the five-check gate proves it.
    """
    root = Path(root)
    got = _read_fix_site(finding, root)
    if got is None:
        return None
    rel, text = got
    lines = text.splitlines(keepends=True)
    idx = (finding.fix_site_set[0].start_line or 1) - 1
    after = list(lines)
    needed: set[str] = set()
    changed = False
    for i in range(max(0, idx - 2), min(len(lines), idx + 3)):
        m = _JS_SHELL.search(lines[i])
        if not m:
            continue
        new_fn = _NON_SHELL[m.group("fn")]
        parts = m.group("prefix").strip().split()
        if not parts:
            continue                                  # no command word to anchor the argv
        cmd, lits = parts[0], parts[1:]
        argv = ", ".join([*(f"'{p}'" for p in lits), m.group("arg")])
        repl = f"{new_fn}('{cmd}', [{argv}])"
        after[i] = lines[i][:m.start()] + repl + lines[i][m.end():]
        needed.add(new_fn)
        changed = True
        break
    if not changed:
        return None
    after = _ensure_cp_bindings(after, needed)
    body = "".join(after)
    if body == text:
        return None
    return "".join(difflib.unified_diff(text.splitlines(keepends=True),
                                        body.splitlines(keepends=True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def _ensure_cp_bindings(lines: list[str], names: set[str]) -> list[str]:
    """Make sure each name in `names` is bound from 'child_process'. Extend an existing destructuring
    `require('child_process')` / `import { ... } from 'child_process'`, else insert a require line."""
    # A name is already bound if it appears on a line that imports from 'child_process'.
    missing = {n for n in names
               if not any("child_process" in l and re.search(rf"\b{re.escape(n)}\b", l) for l in lines)}
    if not missing:
        return lines
    destr = re.compile(r"(?P<head>(?:const|let|var)\s*\{)(?P<names>[^}]*)(?P<tail>\}\s*=\s*require\(\s*['\"]child_process['\"]\s*\))")
    imp = re.compile(r"(?P<head>import\s*\{)(?P<names>[^}]*)(?P<tail>\}\s*from\s*['\"]child_process['\"])")
    for i, ln in enumerate(lines):
        m = destr.search(ln) or imp.search(ln)
        if m:
            existing = {t.strip() for t in m.group("names").split(",") if t.strip()}
            merged = sorted(existing | missing)
            lines[i] = ln[:m.start()] + m.group("head") + " " + ", ".join(merged) + " " + m.group("tail") + ln[m.end():]
            return lines
    # no destructuring import found: insert a fresh require after the last import/require line
    insert_at = 0
    for i, ln in enumerate(lines):
        if re.match(r"^\s*(?:const|let|var)\b[^\n]*require\(", ln) or re.match(r"^\s*import\b", ln):
            insert_at = i + 1
    lines.insert(insert_at, "const { " + ", ".join(sorted(missing)) + " } = require('child_process');\n")
    return lines


def _read_fix_site(finding: Finding, root: Path) -> tuple[str, str] | None:
    """(relative path, source text) for the finding's fix site, or None if unreadable. Mirrors
    repair_templates._read_fix_site so the JS template localises the same way the others do."""
    if not finding.fix_site_set:
        return None
    rel = finding.fix_site_set[0].uri
    p = (root / rel)
    if not p.is_file():
        matches = [q for q in root.rglob(Path(rel).name) if q.is_file()]
        if not matches:
            return None
        p, rel = matches[0], str(matches[0].relative_to(root))
    try:
        return rel, p.read_text()
    except OSError:
        return None
