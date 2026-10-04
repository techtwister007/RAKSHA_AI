"""B8 — anti-analysis hygiene: every name RAKSHA puts in a target's scratch tree is per-run.

A target under test can look at its own working directory. If every run dropped `raksha_harness.c`,
`raksha_sinkguard.py`, a `FuzzRaksha` test or a `/tmp/raksha-harness-*` directory next to it, a
hostile target could recognise the analysis and behave differently. So the harness, guard, helper
and input file names, the Go/Java symbols and the scratch-directory prefix all derive from one
random token drawn once per process (override with RAKSHA_RUN_TOKEN to reproduce a run exactly).

`scrub_python` strips comments and docstrings from a helper module copied into the tree, so the
copy carries code and no product text. Output banners the oracles parse (e.g. PySecSan's) are a
third-party format, not a product marker, and are produced at run time, not stored in the tree.
"""

from __future__ import annotations

import ast
import os
import secrets

TOKEN: str = (os.environ.get("RAKSHA_RUN_TOKEN") or secrets.token_hex(4)).lower()

HARNESS = f"h_{TOKEN}"            # C harness stem / binary; Python harness module
GUARD = f"g_{TOKEN}"              # Python sink-guard module
COV = f"c_{TOKEN}"                # coverage helper (Python) and gcov twin binary (C)
JSGUARD = f"j_{TOKEN}.js"         # Node preload guard
JAVA_DRIVER = f"D{TOKEN}"         # Java driver class (a valid identifier)
JAVA_OUT = f".o_{TOKEN}"          # Java classes dir
GO_FUZZ = f"FuzzT{TOKEN}"         # Go fuzz test function (Fuzz + non-lowercase)
GO_FILE = f"f_{TOKEN}_test.go"
GO_SEED = f"s_{TOKEN}"
RUST_TEST = f"t_{TOKEN}"
RUST_INPUT = f"i_{TOKEN}.bin"
RUST_CORPUS = f"k_{TOKEN}"
SCRATCH = f"w{TOKEN}-"            # mkdtemp prefix for harness scratch trees
JS_MODULE_ENV = f"M_{TOKEN.upper()}"   # env var naming the target module for the JS guard
JS_SYMBOL_ENV = f"S_{TOKEN.upper()}"


def dot(name: str) -> str:
    """A hidden per-run file name for an input/benign/replay file: distinct per `name`, different
    every run, and carrying no readable word."""
    import hashlib
    return "." + hashlib.sha256(f"{TOKEN}:{name}".encode()).hexdigest()[:10]


def all_names() -> tuple[str, ...]:
    return (HARNESS, GUARD, COV, JSGUARD, JAVA_DRIVER, JAVA_OUT, GO_FUZZ, GO_FILE, GO_SEED,
            RUST_TEST, RUST_INPUT, RUST_CORPUS)


def is_ours(filename: str) -> bool:
    """True for a file name RAKSHA itself placed in the tree (used by B6 attribution)."""
    return TOKEN in os.path.basename(filename)


def scrub_python(src: str, replacements: dict[str, str] | None = None) -> str:
    """Code only: comments and docstrings removed (ast round-trip), then names substituted."""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):
            body.pop(0)
            if not body:
                body.append(ast.Pass())
    out = ast.unparse(tree) + "\n"
    for old, new in (replacements or {}).items():
        out = out.replace(old, new)
    return out


def _strip_js_comments(src: str) -> str:
    """Remove /* */ blocks and // comments from OUR guard file (which has no // inside strings
    except where a quote follows, which is kept). Only used on RAKSHA's own JS, never a target's."""
    import re
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    out = []
    for line in src.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        i = line.find("//")
        if i > 0 and line[i - 1] in " \t" and not any(q in line[i:] for q in "'\"`") \
                and line[:i].count("'") % 2 == 0 and line[:i].count('"') % 2 == 0:
            line = line[:i].rstrip()
        if line.strip():
            out.append(line)
    return "\n".join(out) + "\n"


def materialise_js_guard(src: str) -> str:
    """The Node guard as it lands in the target's tree: code only, per-run names."""
    out = _strip_js_comments(src)
    return (out.replace("RAKSHA_JS_MODULE", JS_MODULE_ENV).replace("RAKSHA_JS_SYMBOL", JS_SYMBOL_ENV)
               .replace("jssinkguard.js", JSGUARD).replace("jssinkguard:", "guard:"))
