"""ARVO benchmark loader — the seam that plugs real bugs into the existing harness.

ARVO (~6,100 reproduced OSS-Fuzz bugs with gold patches) and AutoPatchBench are the full external
baseline the benchmark report points at. They cannot ship in an offline, stdlib-only runtime: the
sources, the reproducers and the toolchains are large and are assembled on a *networked prep
machine*, which writes a local **manifest** — a JSON list describing each case and where its files
were materialised. This module reads that manifest and turns each entry into a case
`benchmark.run_cases` can run, driving it through the SAME find → confirm → repair → five-check gate
path as every other target. Nothing here downloads anything.

The honest offline state is explicit: with no manifest present, `arvo_cases` returns `[]` and
`manifest_status` says so. That is not a failure — it is the truthful "the full baseline runs on the
prep machine, not here" that the report already states in prose.

Expected manifest schema (``ARVO_SCHEMA``)
------------------------------------------
A JSON array of objects, each::

    {
      "name":            "arvo-12345",              # required, unique case id
      "language":        "c/c++" | "python",        # required; selects the autofuzz oracle
      "source_path":     "cases/arvo-12345/src",    # required; dir of the vulnerable target,
                                                     #   absolute or relative to the manifest / repo
      "bug_class":       "CWE-787",                 # advisory metadata (the oracle sets the real one)
      "reproducer_path": "cases/arvo-12345/crash",  # optional; the known crashing input, used as a
                                                     #   fuzzing seed so the crash is reached at once
      "seed_corpus":     ["cases/arvo-12345/seeds"], # optional; extra benign seeds (files or dirs)
      "max_execs":       60000                       # optional; fuzzing budget (default 60000)
    }

`language` is required because the autofuzz path needs it to pick the oracle and runner. A real ARVO
export carries far more (project, sanitizer, gold patch, OSS-Fuzz issue id); only the fields above
are read here, and unknown fields are ignored, so a richer manifest loads unchanged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .finding import Finding

_REPO = Path(__file__).parents[1]
_DEFAULT_MAX_EXECS = 60000


@dataclass(frozen=True)
class ArvoCase:
    """One benchmark case read from the manifest. Paths are resolved to absolute at load time."""

    name: str
    language: str
    source_path: Path
    bug_class: str = "?"
    reproducer_path: Path | None = None
    seed_corpus: list[Path] = field(default_factory=list)
    max_execs: int = _DEFAULT_MAX_EXECS


def _resolve(raw: str, base: Path) -> Path:
    """Resolve a manifest path: absolute as-is, else relative to the manifest dir, else the repo."""
    p = Path(raw)
    if p.is_absolute():
        return p
    near = (base / p)
    if near.exists():
        return near
    return (_REPO / p)


def load_manifest(path: str | Path) -> list[ArvoCase]:
    """Parse an ARVO manifest into `ArvoCase`s. Missing or empty manifest → ``[]``.

    Raises `ValueError` only when a manifest *is* present but malformed (not a JSON array, or an
    entry missing a required field) — a corrupt manifest is a real error the operator must see, as
    opposed to the ordinary, honest "no manifest here" offline state.
    """
    manifest = Path(path)
    if not manifest.is_file():
        return []
    text = manifest.read_text().strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError(f"ARVO manifest {manifest} must be a JSON array of case objects")
    base = manifest.parent
    cases: list[ArvoCase] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"ARVO manifest entry {i} is not an object")
        for required in ("name", "language", "source_path"):
            if required not in entry:
                raise ValueError(f"ARVO manifest entry {i} missing required field {required!r}")
        cases.append(ArvoCase(
            name=str(entry["name"]),
            language=str(entry["language"]),
            source_path=_resolve(str(entry["source_path"]), base),
            bug_class=str(entry.get("bug_class", "?")),
            reproducer_path=(_resolve(str(entry["reproducer_path"]), base)
                             if entry.get("reproducer_path") else None),
            seed_corpus=[_resolve(str(s), base) for s in entry.get("seed_corpus", [])],
            max_execs=int(entry.get("max_execs", _DEFAULT_MAX_EXECS)),
        ))
    return cases


def manifest_status(path: str | Path) -> str:
    """A one-line human note on the manifest's state — the honest offline signal for the report."""
    manifest = Path(path)
    if not manifest.is_file():
        return (f"no ARVO manifest at {manifest}: offline mode, 0 ARVO cases. The full ARVO / "
                "AutoPatchBench baseline is assembled on a networked prep machine, which writes this "
                "manifest; this box ships without it by design.")
    try:
        cases = load_manifest(manifest)
    except (ValueError, json.JSONDecodeError) as e:
        return f"ARVO manifest at {manifest} is present but unreadable: {e}"
    if not cases:
        return f"ARVO manifest at {manifest} is present but empty: 0 ARVO cases."
    return f"ARVO manifest at {manifest}: {len(cases)} case(s) loaded."


def _seed_bytes(case: ArvoCase) -> list[bytes]:
    """Seed corpus for the fuzzer: the known reproducer first (so the crash is reached at once),
    then any benign seeds, read from files or every file in a seed directory."""
    seeds: list[bytes] = []
    if case.reproducer_path and case.reproducer_path.is_file():
        seeds.append(case.reproducer_path.read_bytes())
    for s in case.seed_corpus:
        if s.is_file():
            seeds.append(s.read_bytes())
        elif s.is_dir():
            for f in sorted(s.iterdir()):
                if f.is_file():
                    seeds.append(f.read_bytes())
    return seeds


def _runner(case: ArvoCase) -> Callable[[], Finding]:
    """Build a `run_cases`-compatible runner that drives one ARVO case end-to-end.

    It reuses the SAME autofuzz → confirm → repair → five-check gate path as `autofuzz_cases`: no
    bespoke mechanism, which is the whole point of a seam — ARVO changes the inputs, not the code.
    """
    def run() -> Finding:
        from .autorepair import repair
        from .harness import autofuzz
        if not case.source_path.exists():
            raise RuntimeError(f"{case.name}: source_path {case.source_path} does not exist "
                               "(prep machine did not materialise it)")
        seeds = _seed_bytes(case) or None
        result = autofuzz(case.source_path, max_execs=case.max_execs, seed_corpus=seeds)
        if not result.found:
            raise RuntimeError(f"{case.name}: {result.note}")
        repair(result.finding, result.target, root=result.target.source_root,
               reproducer=result.crashing_input, corpus=seeds or [])
        return result.finding
    return run


def arvo_cases(manifest_path: str | Path) -> list[tuple[str, Callable[[], Finding]]]:
    """Cases for `benchmark.run_cases`, read from a local ARVO manifest.

    With no manifest present this returns ``[]`` (see `manifest_status` for the note). Otherwise one
    `(name, runner)` per manifest entry, each runner producing a Finding driven through the normal
    gate. A case whose source is missing or that does not crash raises inside its runner, which
    `run_cases` records as an ERROR row rather than aborting the suite.
    """
    return [(case.name, _runner(case)) for case in load_manifest(manifest_path)]


__all__ = ["ArvoCase", "load_manifest", "manifest_status", "arvo_cases"]
