"""G1 — SMT reachability evidence: does the patched guard make the dangerous state unreachable?

The gate decides whether a fix is accepted, empirically. This lane adds one analytic question, asked
of the solver for a localised out-of-bounds fix: at the access `arr[idx]` the finding points at,
under the conditions that must hold for that line to execute, can `idx` fall outside
`[0, arr.length)`?

It asks twice, on the code before and after the patch:

* **before** — typically `reachable`, with the solver's witness (concrete values that reach the
  bad index). That witness is a second, independent account of the bug next to the fuzzer's input.
* **after** — `unreachable` when the guard closes every path to the bad index, `reachable` with a
  witness when it does not (a shallow fix the solver can see through), `not-modelled` when the code
  around the access is outside the small language this lane reads.

What is read, and what is assumed
---------------------------------
Guards: the conditions of the enclosing `for`/`while`/`if` blocks above the access within its
function, and the negation of every `if (C) return/continue/break` above it. A `for (int v = K; ...;
v++)` loop adds `v >= K`. Lengths (`x.length`, `len(x)`, `x.len()`) are non-negative integers.
Arithmetic is over mathematical integers: overflow is NOT modelled, and the record says so. The
result is evidence for the record; it never changes a finding's status — the gate does that.

The solver (z3) is optional. Absent, the record reads `unavailable` and nothing is claimed.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .finding import Finding

_KEYWORDS = ("for", "while", "if", "switch", "else", "catch", "do", "try")
_ACCESS = re.compile(r"(?P<arr>\b[A-Za-z_]\w*)\s*\[(?P<idx>[^\[\]]+)\]")
_HEAD = re.compile(r"^\s*(?P<kw>for|while|if)\s*\((?P<cond>.*)\)\s*\{?\s*$")
_EARLY = re.compile(r"^\s*if\s*\((?P<cond>.*)\)\s*\{?\s*(return|continue|break)\b")
_FOR = re.compile(r"^\s*for\s*\((?P<init>[^;]*);(?P<cond>[^;]*);(?P<step>[^)]*)\)")
_INIT = re.compile(r"(?:\b(?:int|long|size_t|usize|var|let)\s+)?(?P<v>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<k>-?\d+)\s*$")
_STEP_UP = re.compile(r"^\s*(?:(?P<a>[A-Za-z_]\w*)\s*(?:\+\+|\+=\s*\d+)|\+\+\s*(?P<b>[A-Za-z_]\w*))\s*$")
_FUNC = re.compile(r"^\s*(?:public|private|protected|static|final|func|fn|def|\w[\w<>\[\]\s*&]*)\s*\w+\s*\([^;]*\)\s*(?:throws[^{]*)?\{\s*$")


class NotModelled(ValueError):
    pass


def _z3():
    try:
        import z3  # noqa: F401
        return z3
    except Exception:  # noqa: BLE001 — absent or broken: honestly "unavailable"
        return None


# ---------------------------------------------------------------- reading the code

def _normalise(expr: str) -> str:
    """C-family / Go / Rust boolean expression -> Python syntax this lane can parse."""
    e = expr.strip()
    e = re.sub(r"\(\s*(?:int|long|size_t|unsigned|usize|isize)\s*\)", "", e)      # casts
    e = re.sub(r"\b([A-Za-z_]\w*)\.length\b", r"len__\1", e)
    e = re.sub(r"\blen\(\s*([A-Za-z_]\w*)\s*\)", r"len__\1", e)
    e = re.sub(r"\b([A-Za-z_]\w*)\.len\(\)", r"len__\1", e)
    e = e.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    if re.search(r"[\[\]\"'?:.]|->|<<|>>|\b(?:true|false|null|nil)\b", e):
        raise NotModelled(f"expression outside the modelled language: {expr.strip()!r}")
    return e


def _function_start(lines: list[str], i: int) -> int:
    for j in range(i, -1, -1):
        s = lines[j]
        if _FUNC.match(s) and not re.match(r"^\s*(?:" + "|".join(_KEYWORDS) + r")\b", s):
            return j
    return 0


def guards_at(lines: list[str], i: int) -> tuple[list[str], list[str]]:
    """(conditions that hold when line i runs, notes). Line indexes are 0-based."""
    start = _function_start(lines, i)
    conds: list[str] = []
    notes: list[str] = []
    depth = 0
    for j in range(i - 1, start - 1, -1):
        line = lines[j]
        opens, closes = line.count("{"), line.count("}")
        m_early = _EARLY.match(line)
        if m_early and depth == 0 and closes == 0:
            # an early exit before the access, at the same nesting: its condition is false here
            conds.append(f"not ({m_early.group('cond')})")
            continue
        prev_depth = depth
        depth += closes - opens
        if prev_depth > 0 and depth == 0 and opens:
            # a block fully above the access: `if (C) { return/continue/break ...` exits early
            hm = _HEAD.match(line)
            nxt = next((x.strip() for x in lines[j + 1:i] if x.strip()), "")
            if hm and hm.group("kw") == "if" and re.match(r"(return|continue|break)\b", nxt):
                conds.append(f"not ({hm.group('cond')})")
            continue
        if depth < 0:                       # this line opens a block that encloses line i
            depth = 0
            fm = _FOR.match(line)
            if fm:
                conds.append(fm.group("cond"))
                im, sm = _INIT.search(fm.group("init").strip()), _STEP_UP.match(fm.group("step"))
                if im and sm and (sm.group("a") or sm.group("b")) == im.group("v"):
                    conds.append(f"{im.group('v')} >= {im.group('k')}")
                    notes.append(f"loop variable {im.group('v')} starts at {im.group('k')} and only increases")
                continue
            hm = _HEAD.match(line)
            if hm and hm.group("kw") in ("if", "while"):
                conds.append(hm.group("cond"))
    return conds, notes


def access_at(lines: list[str], i: int, arr_hint: str | None = None) -> tuple[str, str] | None:
    for m in _ACCESS.finditer(lines[i]):
        if arr_hint and m.group("arr") != arr_hint:
            continue
        return m.group("arr"), m.group("idx")
    return None


# ---------------------------------------------------------------- the solver question

def _to_z3(node: ast.AST, env: dict, z3):
    if isinstance(node, ast.Expression):
        return _to_z3(node.body, env, z3)
    if isinstance(node, ast.BoolOp):
        parts = [_to_z3(v, env, z3) for v in node.values]
        return z3.And(*parts) if isinstance(node.op, ast.And) else z3.Or(*parts)
    if isinstance(node, ast.UnaryOp):
        v = _to_z3(node.operand, env, z3)
        if isinstance(node.op, ast.Not):
            return z3.Not(v)
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return v
    if isinstance(node, ast.Compare):
        left = _to_z3(node.left, env, z3)
        out = []
        for op, right_node in zip(node.ops, node.comparators):
            right = _to_z3(right_node, env, z3)
            out.append({ast.Lt: left < right, ast.LtE: left <= right, ast.Gt: left > right,
                        ast.GtE: left >= right, ast.Eq: left == right,
                        ast.NotEq: left != right}[type(op)])
            left = right
        return z3.And(*out) if len(out) > 1 else out[0]
    if isinstance(node, ast.BinOp):
        a, b = _to_z3(node.left, env, z3), _to_z3(node.right, env, z3)
        ops = {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
               ast.FloorDiv: lambda: a / b, ast.Div: lambda: a / b, ast.Mod: lambda: a % b}
        if type(node.op) in ops:
            return ops[type(node.op)]()
    if isinstance(node, ast.Name):
        if node.id not in env:
            env[node.id] = z3.Int(node.id)
        return env[node.id]
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return z3.IntVal(node.value)
    raise NotModelled(f"unsupported construct {type(node).__name__}")


def ask(conds: list[str], arr: str, idx: str, *, z3=None) -> dict:
    """Can `idx` leave [0, len(arr)) while every condition holds? -> status + witness."""
    z3 = z3 or _z3()
    if z3 is None:
        return {"status": "unavailable", "detail": "no SMT solver bundled on this node"}
    env: dict = {}
    try:
        guard = [_to_z3(ast.parse(_normalise(c), mode="eval"), env, z3) for c in conds]
        index = _to_z3(ast.parse(_normalise(idx), mode="eval"), env, z3)
    except (NotModelled, SyntaxError) as e:
        return {"status": "not-modelled", "detail": str(e)}
    length = env.setdefault(f"len__{arr}", z3.Int(f"len__{arr}"))
    s = z3.Solver()
    s.set("timeout", 5000)
    for name, var in env.items():
        if name.startswith("len__"):
            s.add(var >= 0)
    s.add(*guard)
    s.add(z3.Or(index < 0, index >= length))
    r = s.check()
    if r == z3.unsat:
        return {"status": "unreachable", "detail": f"no assignment satisfying the guard puts {idx.strip()} "
                                                    f"outside [0, {arr}.length)"}
    if r == z3.sat:
        m = s.model()
        witness = {str(d): m[d].as_long() for d in m.decls()}
        return {"status": "reachable", "witness": witness,
                "detail": f"{idx.strip()} = {m.eval(index).as_long()} with {arr}.length = "
                          f"{m.eval(length).as_long()} satisfies the guard"}
    return {"status": "unknown", "detail": "solver returned unknown within the time limit"}


# ---------------------------------------------------------------- per finding

def _apply(diff: str, root: Path) -> Path | None:
    work = Path(tempfile.mkdtemp(prefix="rp-")) / "t"
    shutil.copytree(root, work, symlinks=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    p = work.parent / "p.diff"
    p.write_text(diff)
    for cmd in (["git", "apply", "-p1", str(p)], ["patch", "-p1", "-i", str(p)]):
        try:
            # raksha-own: applying a text diff to a scratch copy executes no target code
            if subprocess.run(cmd, cwd=str(work), capture_output=True, timeout=60).returncode == 0:
                return work
        except (OSError, subprocess.SubprocessError):
            continue
    shutil.rmtree(work.parent, ignore_errors=True)
    return None


def _locate(lines: list[str], near: int, arr: str, idx: str) -> int | None:
    """The patched line that still performs `arr[idx]`, closest to the original line."""
    want = re.compile(rf"\b{re.escape(arr)}\s*\[\s*{re.escape(idx.strip())}\s*\]")
    hits = [k for k, line in enumerate(lines) if want.search(line)]
    return min(hits, key=lambda k: abs(k - near)) if hits else None


def reach_proof(finding: Finding, root: str | Path, patch_diff: str) -> dict:
    """The before/after reachability record for a localised out-of-bounds finding."""
    if _z3() is None:
        return {"status": "unavailable", "detail": "no SMT solver bundled on this node"}
    if not finding.fix_site_set or not finding.fix_site_set[0].start_line:
        return {"status": "not-modelled", "detail": "finding has no source line"}
    root = Path(root)
    site = finding.fix_site_set[0]
    src = root / site.uri
    if not src.is_file():
        return {"status": "not-modelled", "detail": f"{site.uri} not found"}
    before = src.read_text(errors="replace").splitlines()
    i = site.start_line - 1
    acc = access_at(before, i) if 0 <= i < len(before) else None
    if acc is None:
        return {"status": "not-modelled", "detail": "no array access on the fix-site line"}
    arr, idx = acc
    conds_b, notes = guards_at(before, i)
    res_b = ask(conds_b, arr, idx)
    work = _apply(patch_diff, root)
    if work is None:
        return {"status": "not-modelled", "detail": "patch did not apply to a scratch copy",
                "before": res_b}
    try:
        after = (work / site.uri).read_text(errors="replace").splitlines()
        j = _locate(after, i, arr, idx)
        if j is None:
            return {"status": "not-modelled", "detail": "the patched code no longer performs the access",
                    "before": res_b}
        conds_a, notes_a = guards_at(after, j)
        res_a = ask(conds_a, arr, idx)
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)
    return {
        "status": res_a["status"],
        "question": f"can {idx.strip()} leave [0, {arr}.length) at {site.uri}:{site.start_line}?",
        "before": {**res_b, "guard": conds_b},
        "after": {**res_a, "guard": conds_a},
        "premises": ["mathematical integers (overflow not modelled)", "lengths are non-negative",
                     *sorted(set(notes + notes_a))],
        "role": "evidence only; the five-check gate decides",
    }
