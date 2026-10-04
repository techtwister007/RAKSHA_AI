"""Find the functions worth fuzzing in an unfamiliar target, with no human pointing at them.

A hand-written harness encodes one human decision: which function takes the untrusted input. This
recovers that decision mechanically. It scans the target's source for functions whose signature
means "give me bytes" — a `(buffer, length)` pair or a C string in C, a single-argument top-level
function in Python — and ranks them: a name like `parse`/`decode`/`handle` on an input-shaped
signature is where attacker data enters, so it fuzzes first. When a model endpoint is configured the
ranking is refined by it (`rank_with_model`); the heuristic alone is the floor and always runs.

Nothing here executes target code; it only reads source, so it is safe to run on an unknown repo
before anything is built.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: Function-name hints that an entry point takes untrusted input. Scored, not required.
_INPUT_NAMES = ("parse", "decode", "read", "load", "handle", "process", "deserialize", "unmarshal",
                "convert", "scan", "lex", "tokenize", "render", "import", "fromstring", "frombytes",
                "ingest", "interpret", "eval", "exec", "run", "dispatch", "command", "query")
_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".venv",
              "test", "tests", "testdata"}


@dataclass(frozen=True)
class Entrypoint:
    language: str
    path: str                 # relative to the scanned root
    symbol: str
    line: int
    kind: str                 # C: "buf_len" | "cstr";  Python: "one_arg"
    score: float
    signature: str = ""

    def as_dict(self) -> dict:
        return {"language": self.language, "path": self.path, "symbol": self.symbol,
                "line": self.line, "kind": self.kind, "score": round(self.score, 2)}


def _name_bonus(name: str) -> float:
    low = name.lower()
    return max((2.0 for h in _INPUT_NAMES if h in low), default=0.0)


# ---------------------------------------------------------------- C / C++

# A function definition (not a declaration): signature then an opening brace. Tolerant of return
# type, pointers and whitespace; the body brace is what separates it from a prototype.
_C_FUNC = re.compile(
    r"(?P<ret>[A-Za-z_][\w \t\*]*?)\b(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{)]*)\)\s*\{",
    re.MULTILINE,
)
_C_BUF = re.compile(r"(?:const\s+)?(?:unsigned\s+char|uint8_t|char|void)\s*\*\s*\w*")
_C_LEN = re.compile(r"\b(?:size_t|ssize_t|int|unsigned|unsigned\s+int|long|uint32_t|uint64_t)\b\s*\w*")


def _c_entrypoints(text: str, path: str) -> list[Entrypoint]:
    out: list[Entrypoint] = []
    for m in _C_FUNC.finditer(text):
        name, args = m.group("name"), m.group("args").strip()
        if name in ("main", "if", "for", "while", "switch", "sizeof", "return") or name.startswith("_"):
            continue
        if any(k in m.group("ret") for k in ("typedef", "struct", "=", "#")):
            continue
        params = [p.strip() for p in args.split(",") if p.strip() and p.strip() != "void"]
        line = text[: m.start()].count("\n") + 1
        kind = None
        if len(params) >= 2 and _C_BUF.search(params[0]) and _C_LEN.search(params[1]):
            kind, base = "buf_len", 5.0          # the libFuzzer shape: the clearest "give me bytes"
        elif len(params) == 1 and _C_BUF.search(params[0]) and "*" in params[0]:
            kind, base = "cstr", 3.0
        if kind:
            out.append(Entrypoint("c/c++", path, name, line, kind, base + _name_bonus(name),
                                  signature=f"{m.group('ret').strip()} {name}({args})"))
    return out


# ---------------------------------------------------------------- Python

_PY_DEF = re.compile(r"^(?P<indent>[ \t]*)def\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)", re.MULTILINE)


def _py_entrypoints(text: str, path: str) -> list[Entrypoint]:
    out: list[Entrypoint] = []
    for m in _PY_DEF.finditer(text):
        if m.group("indent"):
            continue                              # top-level functions only — skip methods
        name = m.group("name")
        if name.startswith("_"):
            continue
        params = [p.strip() for p in m.group("args").split(",") if p.strip()]
        positional = [p for p in params if "=" not in p and not p.startswith(("*", "self", "cls"))]
        if len(positional) != 1:
            continue                              # one input argument is the fuzzable shape
        line = text[: m.start()].count("\n") + 1
        out.append(Entrypoint("python", path, name, line, "one_arg", 3.0 + _name_bonus(name),
                              signature=f"def {name}({m.group('args')})"))
    return out


# ---------------------------------------------------------------- Go

# A top-level func (no receiver) taking one []byte or string argument — the Go native-fuzzing shape.
_GO_FUNC = re.compile(r"^func\s+(?P<name>[A-Za-z_]\w*)\s*\(\s*\w+\s+(?P<type>\[\]byte|string)\s*\)", re.MULTILINE)
_GO_PKG = re.compile(r"^package\s+(\w+)", re.MULTILINE)


def _go_entrypoints(text: str, path: str) -> list[Entrypoint]:
    if path.endswith("_test.go"):
        return []
    out: list[Entrypoint] = []
    for m in _GO_FUNC.finditer(text):
        name = m.group("name")
        line = text[: m.start()].count("\n") + 1
        kind = "go_bytes" if m.group("type") == "[]byte" else "go_string"
        # exported functions (capitalised) are the reachable API surface — a small bonus
        score = 3.0 + _name_bonus(name) + (0.5 if name[:1].isupper() else 0.0)
        out.append(Entrypoint("go", path, name, line, kind, score,
                              signature=f"func {name}({m.group('type')})"))
    return out


_SCANNERS = {".c": _c_entrypoints, ".cc": _c_entrypoints, ".cpp": _c_entrypoints,
             ".cxx": _c_entrypoints, ".py": _py_entrypoints, ".go": _go_entrypoints}
_MAX_FILE_BYTES = 1_000_000


def discover(root: str | Path, *, languages: set[str] | None = None, limit: int = 20) -> list[Entrypoint]:
    """Candidate entry points under `root`, best first. Reads source only; never executes anything."""
    root = Path(root)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts)]
    found: list[Entrypoint] = []
    for p in files:
        scan = _SCANNERS.get(p.suffix)
        if scan is None or p.stat().st_size > _MAX_FILE_BYTES:
            continue
        rel = str(p.relative_to(root)) if root.is_dir() else p.name
        if "main(" in p.name:
            pass
        try:
            found.extend(scan(p.read_text(errors="replace"), rel))
        except OSError:
            continue
    if languages:
        found = [e for e in found if e.language in languages]
    found.sort(key=lambda e: (-e.score, e.path, e.line))
    return found[:limit]


def rank_with_model(entrypoints: list[Entrypoint], *, client=None) -> list[Entrypoint]:
    """Ask the model which candidate is the untrusted-input boundary; reorder on its answer.

    Degrades to the heuristic order when no endpoint is configured or the call fails — the model
    only reorders candidates the scan already found and verified, so it can sharpen the choice but
    never invent an entry point or bypass the harness quality gate.
    """
    from ..inference import ADVISOR, InferenceError, get_client
    client = client or get_client()
    if client is None or len(entrypoints) < 2:
        return entrypoints
    listing = "\n".join(f"{i}: {e.language} {e.symbol}  [{e.signature}]  ({e.path}:{e.line})"
                        for i, e in enumerate(entrypoints[:12]))
    prompt = [
        {"role": "system", "content": "You pick fuzzing entry points. Given candidate functions, "
         "return ONLY a comma-separated list of their indices, best first — the function most likely "
         "to receive untrusted external input (a parser/decoder/request handler). No prose."},
        {"role": "user", "content": listing},
    ]
    try:
        reply = client.complete(prompt, role=ADVISOR, max_tokens=64, temperature=0.0)[0]
    except (InferenceError, IndexError):
        return entrypoints
    order = [int(x) for x in re.findall(r"\d+", reply) if int(x) < len(entrypoints)]
    if not order:
        return entrypoints
    ranked = [entrypoints[i] for i in dict.fromkeys(order)]
    ranked += [e for i, e in enumerate(entrypoints) if i not in order]
    return ranked
