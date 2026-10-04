"""The mutation factory — does the repair ladder GENERALISE, or did it MEMORISE the demo?

A template that only fixes the exact bytes of `tlv.c` / `converter.py` is worthless; a template that
fixes the *shape* of the bug wherever it appears is the claim. This module makes that claim
measurable. `mutate_source` rewrites a known vulnerable demo into semantically-equivalent variants
that KEEP the bug — renamed variables, swapped-but-equivalent APIs (memcpy↔memmove, strcpy↔strcat;
subprocess.run(shell=True)↔os.system↔os.popen), reordered independent context, reflowed whitespace —
deterministically per seed. `generalisation_report` then runs every variant through the real
autofuzz→repair→gate loop and reports how many the templates still find AND fix, with the losses
named. The losses are the honest part: the Python shell template knows `subprocess.run`, so an
`os.system` variant of the same bug is FOUND but NOT fixed — that is memorisation, shown, not hidden.

Nothing here weakens the gate: a variant's fix is VERIFIED by the same five checks as any other.
"""

from __future__ import annotations

import random
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Variant:
    name: str            # how the variant was produced ("rename", "memmove", "os_system", ...)
    path: str            # the source filename the variant should be written to
    text: str            # the mutated source — still carrying the bug
    bug_class: str       # the CWE the variant still exhibits


# ---- identifier renaming (shared) --------------------------------------------------------------

_ID = re.compile(r"\b([A-Za-z_]\w*)\b")


def _rename(text: str, originals: list[str], rng: random.Random) -> str:
    """Rename each identifier in `originals` to a fresh, deterministic name. Word-boundary matched,
    so types/keywords/substrings are untouched."""
    pool = [f"v{i}" for i in range(len(originals) * 3)]
    rng.shuffle(pool)
    mapping = {old: pool[i] for i, old in enumerate(originals)}
    def sub(m: re.Match) -> str:
        return mapping.get(m.group(1), m.group(1))
    return _ID.sub(sub, text)


def _reflow(text: str, rng: random.Random) -> str:
    """Whitespace-only churn that compiles/parses the same: trailing spaces and blank-line jitter."""
    out = []
    for ln in text.splitlines():
        if ln.strip() and rng.random() < 0.4:
            ln = ln + "  "                       # trailing whitespace
        out.append(ln)
        if not ln.strip() and rng.random() < 0.3:
            out.append("")                       # an extra blank line
    return "\n".join(out) + "\n"


# ---- C mutations -------------------------------------------------------------------------------

_C_LOCALS = ["parse_record", "data", "len", "tag", "length", "value", "n"]


def _c_variants(src: str, seed: int) -> list[Variant]:
    out: list[Variant] = []
    base = _rename(src, _C_LOCALS, random.Random(seed))
    out.append(Variant("rename", "src/tlv.c", base, "CWE-121"))

    # memcpy -> memmove (equivalent for non-overlapping copies; same missing bound)
    memmove = re.sub(r"\bmemcpy\b", "memmove", base)
    out.append(Variant("memmove", "src/tlv.c", memmove, "CWE-121"))

    # reorder two independent reads (tag/length declarations) — context moves, bug stays
    reordered = _c_reorder_decls(base)
    out.append(Variant("reorder", "src/tlv.c", reordered, "CWE-121"))

    # whitespace reflow of a differently-renamed copy
    reflowed = _reflow(_rename(src, _C_LOCALS, random.Random(seed + 1)), random.Random(seed + 2))
    out.append(Variant("reflow", "src/tlv.c", reflowed, "CWE-121"))
    return out


def _c_reorder_decls(src: str) -> str:
    """Swap the order of the two independent byte reads (the `tag`/`length` declarations), which is
    semantically irrelevant but moves the context a memorised fix might have keyed on."""
    lines = src.splitlines(keepends=True)
    idx = [i for i, ln in enumerate(lines) if re.search(r"=\s*\w+\s*\[\s*0\s*\]", ln)
           or re.search(r"=\s*\w+\s*\[\s*1\s*\]", ln)]
    if len(idx) >= 2 and idx[1] == idx[0] + 1:
        lines[idx[0]], lines[idx[1]] = lines[idx[1]], lines[idx[0]]
    return "".join(lines)


# ---- Python mutations --------------------------------------------------------------------------

_PY_LOCALS = ["spec", "out"]


def _py_variants(src: str, seed: int) -> list[Variant]:
    out: list[Variant] = []
    base = _rename(src, _PY_LOCALS, random.Random(seed))
    out.append(Variant("rename", "converter.py", base, "CWE-78"))

    # swap the sink API to os.system — the SAME command injection, a DIFFERENT sink the
    # subprocess-shaped template does not know. A deliberate generalisation stressor.
    sys_variant = _py_swap_sink(base, "os.system")
    out.append(Variant("os_system", "converter.py", sys_variant, "CWE-78"))

    # swap to os.popen — likewise
    popen_variant = _py_swap_sink(base, "os.popen")
    out.append(Variant("os_popen", "converter.py", popen_variant, "CWE-78"))

    # whitespace reflow of the subprocess form (still fixable)
    reflowed = _reflow(_rename(src, _PY_LOCALS, random.Random(seed + 1)), random.Random(seed + 2))
    out.append(Variant("reflow", "converter.py", reflowed, "CWE-78"))
    return out


_PY_SINK = re.compile(
    r"(?P<lhs>\w+)\s*=\s*subprocess\.run\(\s*(?P<cmd>.+?)\s*,\s*shell\s*=\s*True[^)]*\)")


def _py_swap_sink(src: str, sink: str) -> str:
    """Replace `x = subprocess.run(CMD, shell=True, ...)` with an os.system/os.popen call carrying
    the same injected command string, and ensure `import os` is present."""
    def repl(m: re.Match) -> str:
        cmd = m.group("cmd")
        if sink == "os.system":
            return f"{m.group('lhs')} = str(os.system({cmd}))"
        return f"{m.group('lhs')} = os.popen({cmd}).read()"
    swapped = _PY_SINK.sub(repl, src)
    if "os.popen" in swapped or "os.system" in swapped:
        if not re.search(r"^\s*import os\b", swapped, re.M):
            swapped = "import os\n" + swapped
        # the function returns `<renamed out>.stdout`; os.* calls return strings, drop `.stdout`
        swapped = re.sub(r"return\s+(\w+)\.stdout", r"return \1", swapped)
    return swapped


def mutate_source(src: str, language: str, seed: int = 0) -> list[Variant]:
    """Semantically-equivalent, bug-preserving variants of `src`, deterministic per `seed`."""
    if language == "c/c++":
        return _c_variants(src, seed)
    if language == "python":
        return _py_variants(src, seed)
    raise ValueError(f"no mutations for language {language!r}")


# ---- the generalisation measurement ------------------------------------------------------------

def _run_variant(variant: Variant, *, max_execs: int, use_model: bool, client) -> dict:
    """Autofuzz + repair one variant in its own scratch dir; report whether it was found and fixed."""
    from .autorepair import repair
    from .harness import autofuzz
    from .retrieval import FixMemory

    is_c = variant.bug_class == "CWE-121"
    corpus = ([b"\x01\x04abcd", b"\x02zz", b"\x01\x02ab"] if is_c
              else [b"10 m to ft", b"warm", b"5 kg to lb"])
    # Seed the campaign with a bug-triggering input so the measurement is about whether the ladder
    # REPAIRS the variant (the point), not whether the short fuzzing budget happens to rediscover it.
    seeds = ([b"\x01\xff" + b"A" * 48, b"\x01\x04abcd"] if is_c
             else [b"x; touch pwn", b"a | id", b"10 m to ft"])
    work = Path(tempfile.mkdtemp(prefix="raksha-variant-"))
    try:
        dest = work / variant.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(variant.text)
        r = autofuzz(work, max_execs=max_execs, seed_corpus=seeds, use_model=use_model, client=client)
        if not r.found:
            return {"name": variant.name, "found": False, "fixed": False, "lane": None,
                    "note": r.note}
        out = repair(r.finding, r.target, root=r.target.source_root, reproducer=r.crashing_input,
                     corpus=corpus, use_model=use_model, client=client, memory=FixMemory(),
                     refuzz_seconds=2.0)
        return {"name": variant.name, "found": True, "fixed": out.verified,
                "lane": out.lane.value if out.lane else None,
                "note": "" if out.verified else f"found but {r.finding.status.value}"}
    except Exception as e:                       # noqa: BLE001 — a variant that errors is a loss, recorded
        return {"name": variant.name, "found": False, "fixed": False, "lane": None,
                "note": f"error: {e}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def generalisation_report(variants: list[Variant], *, use_model: bool = False, client=None,
                          max_execs: int = 60000) -> dict:
    """Run each variant through autofuzz+repair and measure how many the ladder still finds AND
    fixes — the "generalise or memorise" number, with losses named. Shaped for the benchmark."""
    per = [_run_variant(v, max_execs=max_execs, use_model=use_model, client=client) for v in variants]
    found = [p for p in per if p["found"]]
    fixed = [p for p in per if p["fixed"]]
    losses = [{"name": p["name"], "why": p["note"] or "not fixed"} for p in per if not p["fixed"]]
    return {
        "total": len(variants),
        "found": len(found),
        "fixed": len(fixed),
        "fix_rate_pct": round(100.0 * len(fixed) / len(variants), 1) if variants else None,
        "losses": losses,
        "by_variant": per,
        "used_model": use_model,
    }
