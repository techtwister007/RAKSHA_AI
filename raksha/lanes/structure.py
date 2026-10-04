"""Structure lane — a code-property-graph-lite that finds source→sink paths, build-free.

What it builds: from source, a small graph of functions, their parameters, the calls between them
and the dangerous sinks they contain. What it finds: a parameter that an outsider controls (named
or typed like input, a route handler's request, a C `(const uint8_t *data, size_t len)` pair, an
exported Go handler) that flows — by assignment, concatenation, formatting or f-string, inside one
function, through at most one local helper — into a sink that executes, deserialises, queries or
copies it. Every path is emitted as a **SUSPECTED** finding and never confirmed here: a textual path
is evidence that a bug *could* be there, not a reproducer. The gate's cross-confirmation
(`raksha/gate/crossconfirm.py`) promotes it when a dynamic lane lands a reproducer on the same fix
site with the same CWE; until then it only ranks triage ("no reproducer, no report").

What is measured and what is a heuristic
----------------------------------------
- **Python is real intra-procedural taint over the `ast`**: a worklist over `Name` assignments
  (`=`, `+=`, annotated), with f-strings, `%`, `.format`, `+` and `join` all treated as
  propagating, a short sanitiser list (`shlex.quote`, `shlex.split`, `int`, `float`, `re.escape`,
  `html.escape`) that stops it, and one level of local helper followed through its return. A
  `subprocess` call fires only with `shell=True` (or `getoutput`), and list-form argv never fires.
  Which *parameters* count as sources is a heuristic (see `_PY_SOURCE_NAMES` and
  `_python_sources`), with the confidence saying how strong the naming evidence is.
- **C and Go are regex over function bodies**: assignments `x = ... tainted ...` propagate, sinks
  are matched by name, and there is no bounds-check or sanitiser recognition beyond `sizeof` on a
  length argument and `shlex`-style list forms. Confidence is set lower for that reason.
- `confidence` is a fixed per-rule prior, not a learned probability; no learned model exists today.
  `graph_json` emits the node/edge lists with per-node features (degree, source/sink flags,
  distance-to-sink) as the training-data hook for a future graph model, and that is all it is.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..finding import Finding, FixSite, Frame

_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv"}
_MAX_FILE_BYTES = 2_000_000
_LANG = {".py": "python", ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".go": "go"}

_CWE_SEVERITY = {"CWE-78": "high", "CWE-94": "high", "CWE-502": "high", "CWE-89": "high",
                 "CWE-120": "high", "CWE-134": "high", "CWE-22": "medium", "CWE-79": "medium"}


@dataclass(frozen=True)
class StructuralPath:
    """One source→sink path. `lines` runs from the source's line through each propagating
    assignment to the sink; `confidence` is the rule prior (how strong the source evidence is)."""

    file: str
    function: str
    source: str
    sink: str
    cwe: str
    lines: list[int]
    confidence: float
    language: str = "python"

    def as_dict(self) -> dict:
        return {"file": self.file, "function": self.function, "source": self.source, "sink": self.sink,
                "cwe": self.cwe, "lines": list(self.lines), "confidence": self.confidence,
                "language": self.language, "evidence": "structural (static path) — no reproducer"}


@dataclass
class Graph:
    """Nodes keyed by id; `kind` is function / param / sink / call. Edges are (src, dst, kind)."""

    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)

    def add_node(self, nid: str, **attrs) -> str:
        self.nodes.setdefault(nid, {"id": nid, **attrs})
        return nid

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        e = (src, dst, kind)
        if e not in self.edges:
            self.edges.append(e)


@dataclass
class StructureResult:
    paths: list[StructuralPath] = field(default_factory=list)
    graph: Graph = field(default_factory=Graph)
    files_scanned: int = 0

    @property
    def graph_summary(self) -> dict:
        kinds = [n["kind"] for n in self.graph.nodes.values()]
        return {"nodes": len(self.graph.nodes), "edges": len(self.graph.edges),
                "functions": kinds.count("function"), "sinks": kinds.count("sink")}


# ================================================================ Python (ast)

#: Parameter names that name input. Prefix match (`data` matches `data_bytes`), so the list is short.
_PY_SOURCE_NAMES = ("data", "buf", "buffer", "req", "request", "payload", "argv", "args", "kwargs",
                    "input", "user_input", "body", "query", "params", "form", "raw", "msg", "message",
                    "cmd", "command", "line", "text", "untrusted")
_PY_ROUTE_DECORATOR = re.compile(r"(?:^|\.)(?:route|get|post|put|patch|delete|api_route|websocket)$")
_PY_SANITISERS = {"shlex.quote", "shlex.split", "int", "float", "bool", "re.escape", "html.escape",
                  "urllib.parse.quote", "quote", "escape", "os.path.basename", "secure_filename"}
_PY_LIST_MAKERS = {"shlex.split", "split", "list", "tuple"}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def _dotted(node: ast.AST) -> str:
    """`a.b.c` for Attribute/Name chains; "" for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_sanitised(value: ast.AST) -> bool:
    if isinstance(value, ast.Call):
        name = _dotted(value.func)
        return name in _PY_SANITISERS or name.rsplit(".", 1)[-1] in {"quote", "escape", "int"}
    return False


def _is_list_shaped(value: ast.AST) -> bool:
    """A list/tuple literal or a split() result: argv form, which no shell ever parses."""
    if isinstance(value, (ast.List, ast.Tuple)):
        return True
    if isinstance(value, ast.Call):
        name = _dotted(value.func)
        return name in _PY_LIST_MAKERS or name.rsplit(".", 1)[-1] in _PY_LIST_MAKERS
    return False


def _python_sources(fn: ast.FunctionDef | ast.AsyncFunctionDef, nested: bool) -> dict[str, float]:
    """Parameters an outsider controls, with the confidence of that claim.

    0.9  a Flask / FastAPI / Django-style route handler: every parameter is request-derived
    0.8  a parameter named like input (`data`, `req`, `payload`, `*args`, ...)
    0.5  any other parameter of a public, module-level function: whoever imports the module calls
         it with their input (the autofuzz lane makes the same assumption when it synthesises a
         harness for exactly such a function). Private helpers and methods get no such benefit.
    """
    is_route = any(_PY_ROUTE_DECORATOR.search(_dotted(d.func if isinstance(d, ast.Call) else d) or "")
                   for d in fn.decorator_list)
    out: dict[str, float] = {}
    a = fn.args
    params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    if a.vararg:
        params.append(a.vararg)
    if a.kwarg:
        params.append(a.kwarg)
    for p in params:
        if p.arg in ("self", "cls"):
            continue
        ann = _dotted(p.annotation) if p.annotation is not None else ""
        if is_route:
            out[p.arg] = 0.9
        elif any(p.arg == n or p.arg.startswith(n + "_") for n in _PY_SOURCE_NAMES) or p is a.vararg or p is a.kwarg:
            out[p.arg] = 0.8
        elif not nested and not fn.name.startswith("_") and ann in ("", "str", "bytes", "Any"):
            out[p.arg] = 0.5
    return out


#: Python sinks: dotted callee pattern -> (cwe, label, condition). Condition names a check below.
_PY_SINKS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"^(?:subprocess\.)?(?:run|call|check_output|check_call|Popen)$"), "CWE-78", "subprocess shell", "shell"),
    (re.compile(r"^(?:subprocess\.)?(?:getoutput|getstatusoutput)$"), "CWE-78", "subprocess shell", "arg0"),
    (re.compile(r"^os\.(?:system|popen|execl|execlp|execv|execvp|spawnl|spawnv)$"), "CWE-78", "os shell", "arg0"),
    (re.compile(r"^(?:builtins\.)?(?:eval|exec)$"), "CWE-94", "eval/exec", "arg0"),
    (re.compile(r"^(?:pickle|cPickle|marshal|dill)\.loads?$"), "CWE-502", "pickle.loads", "arg0"),
    (re.compile(r"^yaml\.(?:load|unsafe_load|full_load)$"), "CWE-502", "yaml.load", "yaml"),
    (re.compile(r"(?:^|\.)(?:execute|executemany|executescript|raw)$"), "CWE-89", "cursor.execute", "arg0"),
    (re.compile(r"^(?:builtins\.)?open$"), "CWE-22", "open()", "arg0"),
]


def _call_args(call: ast.Call) -> list[ast.AST]:
    return list(call.args) + [k.value for k in call.keywords if k.arg in ("args", "cmd", "command", "source")]


def _sink_fires(call: ast.Call, cond: str, tainted: set[str], list_vars: set[str]) -> bool:
    args = _call_args(call)
    if not args:
        return False
    first = args[0]
    first_names = _names_in(first) - ({first.id} if isinstance(first, ast.Name) and first.id in list_vars else set())
    first_tainted = bool(first_names & tainted) and not _is_sanitised(first) and not _is_list_shaped(first)
    if cond == "shell":
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in call.keywords)
        return shell and first_tainted
    if cond == "yaml":
        loader = next((k.value for k in call.keywords if k.arg == "Loader"), None)
        if loader is not None and _dotted(loader).rsplit(".", 1)[-1] in _SAFE_YAML_LOADERS:
            return False
        return first_tainted
    return first_tainted


class _Taint:
    """Intra-procedural taint over one Python function body with a worklist on Name assignments."""

    def __init__(self, module: ast.Module, helpers: dict[str, ast.FunctionDef]) -> None:
        self.helpers = helpers
        self._memo: dict[tuple[str, int], bool] = {}

    def helper_returns_taint(self, name: str, index: int) -> bool:
        """Does local helper `name` return something derived from its `index`-th parameter?"""
        key = (name, index)
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = False                  # recursion guard
        fn = self.helpers.get(name)
        if fn is None:
            return False
        params = [p.arg for p in fn.args.args]
        if index >= len(params):
            return False
        tainted, _ = self.propagate(fn, {params[index]: fn.lineno}, follow_helpers=False)
        result = any(bool(_names_in(r.value) & set(tainted)) and not _is_sanitised(r.value)
                     for r in ast.walk(fn) if isinstance(r, ast.Return) and r.value is not None)
        self._memo[key] = result
        return result

    def propagate(self, fn: ast.AST, seeds: dict[str, int], *, follow_helpers: bool = True):
        """Returns {name: (origin parameter, lines from the parameter to this assignment)}."""
        tainted: dict[str, tuple[str, list[int]]] = {k: (k, [v]) for k, v in seeds.items()}
        list_vars: set[str] = set()
        stmts = [s for s in ast.walk(fn) if isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign))]
        stmts.sort(key=lambda s: s.lineno)
        changed = True
        while changed:                             # worklist: iterate to a fixed point (loops)
            changed = False
            for s in stmts:
                value = s.value
                if value is None:
                    continue
                targets = s.targets if isinstance(s, ast.Assign) else [s.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if not names:
                    continue
                src = _names_in(value) & set(tainted)
                via_helper = False
                if not src and follow_helpers and isinstance(value, ast.Call):
                    callee = _dotted(value.func)
                    for i, a in enumerate(value.args):
                        if _names_in(a) & set(tainted) and self.helper_returns_taint(callee, i):
                            src = _names_in(a) & set(tainted)
                            via_helper = True
                            break
                if isinstance(s, ast.AugAssign) and s.target.id in tainted:
                    src = src or {s.target.id}
                if not src or (_is_sanitised(value) and not via_helper):
                    continue
                for n in names:
                    if _is_list_shaped(value):
                        list_vars.add(n)
                    origin, lines = tainted[sorted(src)[0]]
                    chain = (origin, lines + [s.lineno])
                    if n not in tainted or len(chain[1]) < len(tainted[n][1]):
                        tainted[n] = chain
                        changed = True
        return tainted, list_vars


def _scan_python(text: str, rel: str, graph: Graph) -> list[StructuralPath]:
    try:
        module = ast.parse(text)
    except SyntaxError:
        return []
    helpers = {n.name: n for n in module.body if isinstance(n, ast.FunctionDef)}
    taint = _Taint(module, helpers)
    paths: list[StructuralPath] = []
    top_level = {id(n) for n in module.body}
    for fn in ast.walk(module):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fid = graph.add_node(f"{rel}::{fn.name}", kind="function", file=rel, name=fn.name, line=fn.lineno)
        sources = _python_sources(fn, nested=id(fn) not in top_level)
        for p, conf in sources.items():
            pid = graph.add_node(f"{fid}::{p}", kind="param", file=rel, name=p, line=fn.lineno, confidence=conf)
            graph.add_edge(pid, fid, "param-of")
        for call in ast.walk(fn):
            if isinstance(call, ast.Call) and _dotted(call.func) in helpers:
                graph.add_edge(fid, f"{rel}::{_dotted(call.func)}", "calls")
        if not sources:
            continue
        tainted, list_vars = taint.propagate(fn, {p: fn.lineno for p in sources})
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call):
                continue
            callee = _dotted(call.func)
            for pat, cwe, label, cond in _PY_SINKS:
                if not pat.search(callee):
                    continue
                if not _sink_fires(call, cond, set(tainted), list_vars):
                    continue
                first = _call_args(call)[0]
                # the longest chain is the most informative derivation to show the operator
                hit = sorted(_names_in(first) & set(tainted), key=lambda n: (-len(tainted[n][1]), n))[0]
                src_param, chain = tainted[hit]
                sid = graph.add_node(f"{fid}::sink@{call.lineno}", kind="sink", file=rel, name=callee,
                                     line=call.lineno, cwe=cwe)
                graph.add_edge(f"{fid}::{src_param}", sid, "taints")
                graph.add_edge(fid, sid, "contains")
                lines = sorted(set(chain + [call.lineno]))
                paths.append(StructuralPath(rel, fn.name, src_param, f"{callee} ({label})", cwe, lines,
                                            sources[src_param], "python"))
                break
    return paths


# ================================================================ C and Go (regex over bodies)

_C_FUNC = re.compile(r"^[ \t]*(?:static\s+|inline\s+|extern\s+)*[\w\s\*]+?\b(\w+)\s*\(([^;{)]*)\)\s*\{", re.M)
_GO_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(([^)]*)\)[^{]*\{", re.M)
_C_BUF_PARAM = re.compile(r"(?:const\s+)?(?:uint8_t|unsigned\s+char|char|u8|void)\s*\*\s*(\w+)")
_C_LEN_PARAM = re.compile(r"\b(?:size_t|int|unsigned(?:\s+int)?|uint32_t|uint16_t|ssize_t|long)\s+(\w+)")
_GO_REQ_PARAM = re.compile(r"(\w+)\s+\*?http\.Request")
_GO_BYTES_PARAM = re.compile(r"(\w+)\s+(?:\[\]byte|string)\b")
_C_SOURCE_NAMES = ("data", "buf", "buffer", "input", "in", "src", "payload", "msg", "packet", "pkt", "req", "argv", "cmd")

#: C sinks: name -> (cwe, argument indices that carry the dangerous value, index of the length
#: argument or None). A `sizeof(...)` length argument bounds the copy and suppresses the sink —
#: the only bounds-check recognition this regex lane does.
_C_SINKS = {"memcpy": ("CWE-120", (1, 2), 2), "memmove": ("CWE-120", (1, 2), 2), "strcpy": ("CWE-120", (1,), None),
            "strncpy": ("CWE-120", (1, 2), 2), "strcat": ("CWE-120", (1,), None),
            "sprintf": ("CWE-120", (1, 2, 3), None), "vsprintf": ("CWE-120", (1,), None),
            "gets": ("CWE-120", (0,), None), "system": ("CWE-78", (0,), None), "popen": ("CWE-78", (0,), None),
            "execl": ("CWE-78", (0, 1), None), "execv": ("CWE-78", (0, 1), None), "printf": ("CWE-134", (0,), None)}
_GO_SINKS = {"exec.Command": ("CWE-78", None), "os.Open": ("CWE-22", None), "os.OpenFile": ("CWE-22", None),
             "os.ReadFile": ("CWE-22", None), "ioutil.ReadFile": ("CWE-22", None), "os.Remove": ("CWE-22", None),
             "template.HTML": ("CWE-79", None), "db.Query": ("CWE-89", "fmt"), "db.Exec": ("CWE-89", "fmt"),
             "db.QueryRow": ("CWE-89", "fmt")}


def _body(text: str, open_brace: int) -> tuple[str, int]:
    """The brace-balanced body starting at `open_brace`, and its end offset. Strings are not
    parsed; an unbalanced brace in a string literal simply truncates the body (documented limit)."""
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i + 1], i + 1
    return text[open_brace:], len(text)


def _split_args(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _call_span(body: str, start: int) -> str:
    """The argument text of the call whose "(" is at `start`."""
    depth = 0
    for i in range(start, len(body)):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                return body[start + 1:i]
    return body[start + 1:]


def _regex_taint(body: str, base_line: int, seeds: dict[str, int],
                 assign: re.Pattern) -> dict[str, tuple[str, list[int]]]:
    """Worklist over `lhs = ... rhs ...` lines: lhs becomes tainted when any tainted name is in rhs.
    Returns {name: (origin parameter, lines)} like the Python propagator."""
    tainted: dict[str, tuple[str, list[int]]] = {k: (k, [v]) for k, v in seeds.items()}
    lines = body.split("\n")
    changed = True
    while changed:
        changed = False
        for i, line in enumerate(lines):
            m = assign.search(line)
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if lhs in tainted:
                continue
            src = sorted((t for t in tainted if re.search(rf"\b{re.escape(t)}\b", rhs)),
                         key=lambda t: (-len(tainted[t][1]), t))   # longest derivation wins
            if src:
                origin, chain = tainted[src[0]]
                tainted[lhs] = (origin, chain + [base_line + i])
                changed = True
    return tainted


_C_ASSIGN = re.compile(r"(?:^|[;{]\s*|^\s*)(?:[\w\s\*]+?\b)?(\w+)\s*(?:\[[^\]]*\])?\s*=(?!=)\s*([^;]+);")
_GO_ASSIGN = re.compile(r"^\s*(?:var\s+)?(\w+)(?:\s*,\s*\w+)?\s*(?::=|=)(?!=)\s*(.+)$")


def _scan_c(text: str, rel: str, graph: Graph) -> list[StructuralPath]:
    paths: list[StructuralPath] = []
    for m in _C_FUNC.finditer(text):
        name, params = m.group(1), m.group(2)
        if name in ("if", "for", "while", "switch", "return", "sizeof"):
            continue
        body, _ = _body(text, m.end() - 1)
        fline = text[:m.start()].count("\n") + 1
        body_line = text[:m.end() - 1].count("\n") + 1
        fid = graph.add_node(f"{rel}::{name}", kind="function", file=rel, name=name, line=fline)
        bufs = _C_BUF_PARAM.findall(params)
        lens = _C_LEN_PARAM.findall(params)
        seeds: dict[str, int] = {}
        conf = 0.0
        if bufs and lens:                        # the (buf, len) shape: the fuzzing entry point
            seeds.update({b: fline for b in bufs})
            seeds.update({l: fline for l in lens})
            conf = 0.7
        for p in re.findall(r"\b(\w+)\s*(?:,|$)", params):
            if any(p == n or p.startswith(n + "_") for n in _C_SOURCE_NAMES):
                seeds.setdefault(p, fline)
                conf = max(conf, 0.6)
        for p in seeds:
            pid = graph.add_node(f"{fid}::{p}", kind="param", file=rel, name=p, line=fline, confidence=conf)
            graph.add_edge(pid, fid, "param-of")
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            if cm.group(1) in _C_SINKS or cm.group(1) == name:
                continue
            if cm.group(1) in ("if", "for", "while", "switch", "return", "sizeof"):
                continue
            if f"{rel}::{cm.group(1)}" in graph.nodes or re.search(rf"\b{cm.group(1)}\s*\([^;]*\)\s*\{{", text):
                graph.add_edge(fid, f"{rel}::{cm.group(1)}", "calls")
        if not seeds:
            continue
        tainted = _regex_taint(body, body_line, seeds, _C_ASSIGN)
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            sink = cm.group(1)
            if sink not in _C_SINKS:
                continue
            cwe, idx, len_idx = _C_SINKS[sink]
            args = _split_args(_call_span(body, cm.end() - 1))
            if len_idx is not None and len_idx < len(args) and "sizeof" in args[len_idx]:
                continue                          # bounded by the destination's size
            hits = [t for i in idx if i < len(args)
                    for t in tainted if re.search(rf"\b{re.escape(t)}\b", args[i])]
            if not hits:
                continue
            hit = sorted(hits, key=lambda t: (-len(tainted[t][1]), t))[0]
            sline = body_line + body[:cm.start()].count("\n")
            root, chain = tainted[hit]
            sid = graph.add_node(f"{fid}::sink@{sline}", kind="sink", file=rel, name=sink, line=sline, cwe=cwe)
            graph.add_edge(f"{fid}::{root}", sid, "taints")
            graph.add_edge(fid, sid, "contains")
            paths.append(StructuralPath(rel, name, root, f"{sink}()", cwe, sorted(set(chain + [sline])), conf, "c"))
    return paths


def _scan_go(text: str, rel: str, graph: Graph) -> list[StructuralPath]:
    paths: list[StructuralPath] = []
    for m in _GO_FUNC.finditer(text):
        name, params = m.group(1), m.group(2)
        body, _ = _body(text, m.end() - 1)
        fline = text[:m.start()].count("\n") + 1
        body_line = text[:m.end() - 1].count("\n") + 1
        fid = graph.add_node(f"{rel}::{name}", kind="function", file=rel, name=name, line=fline)
        seeds: dict[str, int] = {}
        conf = 0.0
        for r in _GO_REQ_PARAM.findall(params):       # http.HandlerFunc: the request is the attacker's
            seeds[r] = fline
            conf = 0.9
        for p in _GO_BYTES_PARAM.findall(params):
            if any(p == n or p.startswith(n + "_") for n in _C_SOURCE_NAMES):
                seeds[p] = fline
                conf = max(conf, 0.8)
            elif name[:1].isupper():                  # exported: callers outside the package
                seeds[p] = fline
                conf = max(conf, 0.5)
        for p in seeds:
            pid = graph.add_node(f"{fid}::{p}", kind="param", file=rel, name=p, line=fline, confidence=conf)
            graph.add_edge(pid, fid, "param-of")
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            if re.search(rf"^func\s+(?:\([^)]*\)\s*)?{cm.group(1)}\s*\(", text, re.M) and cm.group(1) != name:
                graph.add_edge(fid, f"{rel}::{cm.group(1)}", "calls")
        if not seeds:
            continue
        tainted = _regex_taint(body, body_line, seeds, _GO_ASSIGN)
        # request-derived values (r.FormValue, r.URL.Query) carry the request's taint
        for sink, (cwe, cond) in _GO_SINKS.items():
            for cm in re.finditer(re.escape(sink) + r"\s*\(", body):
                args = _call_span(body, cm.end() - 1)
                if cond == "fmt" and not re.search(r"fmt\.Sprintf|\+", args):
                    continue
                hits = [t for t in tainted if re.search(rf"\b{re.escape(t)}\b", args)]
                if not hits:
                    continue
                hit = sorted(hits, key=lambda t: (-len(tainted[t][1]), t))[0]
                sline = body_line + body[:cm.start()].count("\n")
                root, chain = tainted[hit]
                sid = graph.add_node(f"{fid}::sink@{sline}", kind="sink", file=rel, name=sink, line=sline, cwe=cwe)
                graph.add_edge(f"{fid}::{root}", sid, "taints")
                graph.add_edge(fid, sid, "contains")
                paths.append(StructuralPath(rel, name, root, f"{sink}()", cwe, sorted(set(chain + [sline])), conf, "go"))
    return paths


_SCANNERS = {"python": _scan_python, "c": _scan_c, "go": _scan_go}


# ================================================================ the lane

def scan_file(text: str, rel: str, graph: Graph | None = None) -> list[StructuralPath]:
    lang = _LANG.get("." + rel.rsplit(".", 1)[-1] if "." in rel else "")
    if lang is None:
        return []
    return _SCANNERS[lang](text, rel, graph if graph is not None else Graph())


def scan_structure(root: str | Path) -> StructureResult:
    root = Path(root)
    result = StructureResult()
    paths = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    for path in paths:
        if any(part in _SKIP_DIRS for part in path.parts) or path.suffix not in _LANG:
            continue
        if path.stat().st_size > _MAX_FILE_BYTES:
            continue
        rel = str(path.relative_to(root)) if path != root else path.name
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        result.files_scanned += 1
        result.paths.extend(scan_file(text, rel, result.graph))
    result.paths.sort(key=lambda p: (p.file, p.lines[-1], p.cwe))
    return result


def to_findings(result: StructureResult) -> list[Finding]:
    """SUSPECTED findings, one per path, with the fix site at the sink. No reproducer is attached,
    so `confirm()` would refuse them: they can only be promoted by cross-confirmation."""
    findings: list[Finding] = []
    for p in result.paths:
        sink_line = p.lines[-1]
        f = Finding(
            oracle=f"cpg:{p.language}",
            bug_class=p.cwe,
            language=p.language,
            target=p.file,
            message=(f"Structural path in {p.function}(): parameter `{p.source}` reaches {p.sink} at "
                     f"{p.file}:{sink_line} via lines {p.lines} (static, unconfirmed; confidence {p.confidence})"),
            severity=_CWE_SEVERITY.get(p.cwe, "medium"),
            frames=[Frame(symbol=p.function, uri=p.file, line=sink_line)],
        )
        f.add_fix_site(FixSite(uri=p.file, rank=0, start_line=sink_line, symbol=p.function,
                               rationale=f"sink {p.sink} receives `{p.source}` unsanitised"))
        f.structure = p.as_dict()
        findings.append(f)
    return findings


def graph_json(result: StructureResult) -> dict:
    """Node / edge lists with per-node features — the data a future graph model would train on.
    `distance_to_sink` is hop count along edges to the nearest sink; None (not 0) when none is
    reachable, and 0 only for a sink itself. No learned model consumes this today."""
    g = result.graph
    in_deg = {n: 0 for n in g.nodes}
    out_deg = {n: 0 for n in g.nodes}
    fwd: dict[str, list[str]] = {n: [] for n in g.nodes}
    for s, d, _ in g.edges:
        if s in g.nodes and d in g.nodes:
            out_deg[s] += 1
            in_deg[d] += 1
            fwd[s].append(d)
    dist: dict[str, int | None] = {n: (0 if g.nodes[n]["kind"] == "sink" else None) for n in g.nodes}
    rev: dict[str, list[str]] = {n: [] for n in g.nodes}
    for s, d, _ in g.edges:
        if s in g.nodes and d in g.nodes:
            rev[d].append(s)
    frontier = [n for n in g.nodes if dist[n] == 0]
    while frontier:
        nxt = []
        for n in frontier:
            for p in rev[n]:
                if dist[p] is None:
                    dist[p] = dist[n] + 1
                    nxt.append(p)
        frontier = nxt
    nodes = []
    for nid, attrs in g.nodes.items():
        nodes.append({**attrs, "in_degree": in_deg[nid], "out_degree": out_deg[nid],
                      "is_sink": attrs["kind"] == "sink", "is_source": attrs["kind"] == "param",
                      "distance_to_sink": dist[nid]})
    return {"nodes": nodes, "edges": [{"src": s, "dst": d, "kind": k} for s, d, k in g.edges],
            "paths": [p.as_dict() for p in result.paths], "model": None,
            "note": "features for a future graph model; no learned model exists today"}
