"""Synthesize a fuzz harness for a discovered entry point — TAKE a template, WRAP the function.

This is the "harness synthesis" the dossier describes: not a headline act of genius, but a wrapper
built from a template and then made to EARN its place with a two-check quality gate —

    1. it COMPILES / imports, and
    2. it EXERCISES the target: a benign input reaches the entry point and the harness exits cleanly.

A harness that fails either is discarded (we do not trust our own generated code any more than a
generated patch). When a model endpoint is configured it can propose a richer wrapper — decode the
bytes into the structured argument the function really wants — and that candidate goes through the
exact same two checks before it is used; the template wrapper is the floor that always passes them.

The synthesized harness reads one input from a file argument (or stdin) and calls the entry point,
so the mutation fuzzer and the gate can drive it with no engine installed. It exits non-zero and
lets the sanitizer print when the input crashes — which is what the oracle reads.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import names
from .entrypoints import Entrypoint

# ---- C -----------------------------------------------------------------------------------------

_C_HARNESS = r"""#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern {signature_decl};

static void run(const unsigned char *buf, size_t len) {{
    {call}
}}

static int read_n(int fd, unsigned char *p, size_t n) {{
    size_t got = 0; ssize_t r;
    while (got < n) {{ r = read(fd, p + got, n - got); if (r <= 0) return 0; got += (size_t)r; }}
    return 1;
}}

int main(int argc, char **argv) {{
    if (argc > 1) {{                       /* one-shot mode */
        FILE *in = fopen(argv[1], "rb");
        if (!in) return 0;
        unsigned char *buf = NULL; size_t cap = 0, len = 0; int c;
        while ((c = fgetc(in)) != EOF) {{
            if (len + 1 > cap) {{ cap = cap ? cap * 2 : 1024; buf = realloc(buf, cap); }}
            buf[len++] = (unsigned char)c;
        }}
        fclose(in);
        buf = realloc(buf, len ? len : 1);  /* exact-size buffer, like a real fuzzer: a read past
                                               `len` is a real out-of-bounds read, not hidden by slack */
        run(buf, len); free(buf); return 0;
    }}
    for (;;) {{                            /* fork-server mode */
        unsigned char hdr[4];
        if (!read_n(0, hdr, 4)) break;
        uint32_t n = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                     ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
        if (n == 0xFFFFFFFFu) break;
        unsigned char *buf = malloc(n ? n : 1);
        if (n && !read_n(0, buf, n)) {{ free(buf); break; }}
        pid_t pid = fork();
        if (pid == 0) {{ run(buf, n); _exit(0); }}   /* child: crash here aborts only the child */
        int st; waitpid(pid, &st, 0);
        unsigned char s = (WIFSIGNALED(st) || (WIFEXITED(st) && WEXITSTATUS(st) != 0)) ? 1 : 0;
        if (write(1, &s, 1) != 1) {{ free(buf); break; }}
        free(buf);
    }}
    return 0;
}}
"""

_C_CALL = {
    "buf_len": "if (buf) {symbol}(buf, len);",
    "cstr": "char *s = malloc(len + 1); if (s) {{ memcpy(s, buf, len); s[len] = 0; {symbol}(s); free(s); }}",
}


def _c_signature_decl(e: Entrypoint) -> str:
    # A forward declaration so the harness links against the target's function without its header.
    if e.kind == "buf_len":
        return f"int {e.symbol}(const unsigned char *, size_t)"
    return f"int {e.symbol}(const char *)"


@dataclass
class Harness:
    language: str
    entrypoint: Entrypoint
    source: str
    filename: str
    #: shell commands the gate/fuzzer run, with {input}/{out}/{root} placeholders filled by the target
    build_cmd: str
    run_cmd: str


def synthesize(entrypoint: Entrypoint) -> Harness:
    """Produce the template harness for an entry point. Validate it with `quality_gate` before use."""
    if entrypoint.language == "c/c++":
        call = _C_CALL[entrypoint.kind].format(symbol=entrypoint.symbol)
        src = _C_HARNESS.format(symbol=entrypoint.symbol, signature_decl=_c_signature_decl(entrypoint),
                                call=call)
        return Harness("c/c++", entrypoint, src, f"{names.HARNESS}.c", build_cmd="", run_cmd="")
    if entrypoint.language == "python":
        src = _PY_HARNESS.format(module=_py_module(entrypoint.path), symbol=entrypoint.symbol,
                                 guard=names.GUARD)
        return Harness("python", entrypoint, src, f"{names.HARNESS}.py", build_cmd="", run_cmd="")
    raise ValueError(f"no harness template for {entrypoint.language}")


# ---- Python ------------------------------------------------------------------------------------

_PY_HARNESS = r'''import os, sys, struct, importlib
import {guard}
{guard}.install()

_mod = importlib.import_module("{module}")
_fn = getattr(_mod, "{symbol}")

def _run(data: bytes):
    try:
        _fn(data)
    except (TypeError, UnicodeDecodeError):
        _fn(data.decode("utf-8", "surrogateescape"))

def _read_n(n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = os.read(0, n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

if __name__ == "__main__":
    if len(sys.argv) > 1:                 # one-shot
        _run(open(sys.argv[1], "rb").read())
        sys.exit(0)
    while True:                           # fork-server
        hdr = _read_n(4)
        if len(hdr) < 4:
            break
        (n,) = struct.unpack(">I", hdr)
        if n == 0xFFFFFFFF:
            break
        data = _read_n(n)
        pid = os.fork()
        if pid == 0:                      # child: runs the target, dies alone on a crash
            try:
                _run(data)
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, st = os.waitpid(pid, 0)
        crashed = 1 if (os.WIFSIGNALED(st) or (os.WIFEXITED(st) and os.WEXITSTATUS(st) != 0)) else 0
        os.write(1, bytes([crashed]))
'''


def _py_module(path: str) -> str:
    return path[:-3].replace("/", ".") if path.endswith(".py") else path.replace("/", ".")


# ---- the two-check quality gate ----------------------------------------------------------------

@dataclass
class QualityResult:
    ok: bool
    compiles: bool
    exercises: bool
    detail: str = ""


def quality_gate(harness: Harness, target_root: Path, *, benign: bytes = b"ok", cc: str = "gcc",
                 timeout: float = 120.0) -> tuple[QualityResult, dict]:
    """Run the two checks in a scratch copy. Returns (result, built) where `built` carries the paths
    the autofuzz driver needs (the compiled binary / the python invocation) when ok."""
    if harness.language == "c/c++":
        return _c_quality(harness, target_root, benign, cc, timeout)
    return _py_quality(harness, target_root, benign, timeout)


def _scratch(target_root: Path) -> Path:
    work = Path(tempfile.mkdtemp(prefix=names.SCRATCH)) / Path(target_root).name
    shutil.copytree(target_root, work, symlinks=True)
    return work


def _sh(cmd: list[str] | str, cwd: Path, stdin: bytes | None = None, timeout: float = 120.0):
    from ..sandbox import run_target      # building/running the harness runs target code
    return run_target(cmd, str(cwd), input=stdin, timeout=timeout, shell=isinstance(cmd, str))


def _c_quality(harness, target_root, benign, cc, timeout):
    work = _scratch(target_root)
    (work / harness.filename).write_text(harness.source)
    # Compile the harness with every target .c that has no main() of its own, under ASan.
    sources = sorted(p.relative_to(work) for p in work.rglob("*.c")
                     if p.name != harness.filename and "int main(" not in p.read_text(errors="replace")
                     and "main (" not in p.read_text(errors="replace"))
    srcs = " ".join(str(s) for s in [Path(harness.filename), *sources])
    build = (f"{cc} -g -fsanitize=address -fno-omit-frame-pointer -ffile-prefix-map=\"$PWD\"=. -I. "
             + " ".join(f"-I{s.parent}" for s in sources if s.parent != Path(".")) + f" -o {names.HARNESS} {srcs}")
    r = _sh(build, work, timeout=timeout)
    if r.returncode != 0:
        return QualityResult(False, False, False, "harness did not compile:\n" + r.stderr.decode("utf-8", "replace")[-800:]), {}
    (work / names.dot("benign")).write_bytes(benign)
    run = _sh([f"./{names.HARNESS}", names.dot("benign")], work, timeout=timeout)   # one-shot
    exercises = run.returncode == 0                 # a benign input must not crash the harness
    res = QualityResult(exercises, True, exercises,
                        "compiles; benign input exits cleanly" if exercises
                        else "harness crashes on a benign input — template rejected")
    return res, {"root": work, "binary": f"./{names.HARNESS}", "cc": cc}


def _materialise_python(harness: Harness, work: Path) -> None:
    """Drop the harness and its sink-guard oracle into the work dir so both the quality gate and the
    gate target run identically."""
    (work / harness.filename).write_text(harness.source)
    guard = names.scrub_python((Path(__file__).parent / "sinkguard.py").read_text(),
                               {"raksha_sinkguard.py": f"{names.GUARD}.py",
                                "raksha_harness.py": f"{names.HARNESS}.py"})
    (work / f"{names.GUARD}.py").write_text(guard)


def _py_quality(harness, target_root, benign, timeout):
    work = _scratch(target_root)
    _materialise_python(harness, work)
    (work / names.dot("benign")).write_bytes(benign)
    run = _sh(["python3", harness.filename, names.dot("benign")], work, timeout=timeout)   # one-shot
    ok = run.returncode == 0
    return (QualityResult(ok, ok, ok,
                          "imports and runs on a benign input" if ok
                          else "harness errors on a benign input:\n" + run.stderr.decode("utf-8", "replace")[-400:]),
            {"root": work} if ok else {})
