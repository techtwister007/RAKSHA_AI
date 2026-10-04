"""J7 — self-contained verifier media: a judge replays a finding on their own laptop in under a minute.

``build_media(out, entries, ...)`` writes a directory that can be copied to a USB stick:

    verify.py           the standalone verifier (stdlib only; see raksha/data/verify_standalone.py)
    verify.sh / .bat    launchers that prefer the portable runtime under runtime/, else python3
    bundles/<id>/       the sealed evidence bundles
    advisories/<id>/    signed internal-CERT advisories (J8), when given
    targets/<name>/     the targets the replays run against (only those the caller ships — RAKSHA's
                        own demo targets on the demo media; on a deployment, the operator decides)
    lib/raksha/         RAKSHA's own (stdlib-only) code, so deterministic-match replays
                        (`raksha secret-match` and kin) run with no install
    runtime/            optional portable Python (e.g. a python-build-standalone tree) copied as-is
    MEDIA.json(+.sig)   every file and its sha256, signed — a changed byte anywhere fails

``python -m raksha.verifiermedia demo OUT`` builds the demo media: the Python command-injection
finding proven end to end (it replays — fires, then dies on the patched copy — with nothing but a
Python interpreter), a build-free secret finding replayed through the vendored detector, and the
advisory for the verified fix.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

PKG = Path(__file__).parent
STANDALONE = PKG / "data" / "verify_standalone.py"
_SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".git", ".raksha*", "*.o", "harness")


@dataclass
class Entry:
    """One finding on the media: its bundle, and (optionally) the target its replay runs against."""
    finding_id: str
    bundle_dir: Path
    target_root: Path | None = None
    target_name: str | None = None
    needs: str | None = None          # a tool the replay requires (e.g. "gcc"); absent → not replayed
    patch_replay: bool = True
    marker: str | None = None         # the oracle's output marker; None → derived from the oracle


#: The text each oracle family prints when it fires — what the standalone verifier looks for.
_MARKERS = {"asan": "AddressSanitizer", "ubsan": "runtime error:", "lsan": "LeakSanitizer",
            "tsan": "ThreadSanitizer", "pysecsan": "PySecSan", "jazzer": "== Java Exception",
            "go": "panic:", "rust": "panicked at", "secrets": "REPRODUCED:", "osv": "REPRODUCED:",
            "crypto": "REPRODUCED:", "iac": "REPRODUCED:", "service": "REPRODUCED:", "binary": "REPRODUCED:"}


def marker_for(oracle: str) -> str:
    head = oracle.split(":", 1)[0].lower()
    for k, v in _MARKERS.items():
        if head.startswith(k):
            return v
    return "REPRODUCED:"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_media(out: str | Path, entries: list[Entry], *, advisories: list[Path] = (),
                runtime: Path | None = None, key: bytes | None = None,
                documents: list[dict] = ()) -> Path:
    """`documents`: Wave 5 signed documents, each {src, dest, stem, chain?, first_prev?}; documents
    sharing a `chain` are verified in order, each against the previous one's hash."""
    from .bundle import signing_key
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy(STANDALONE, out / "verify.py")
    (out / "verify.sh").write_text(
        '#!/bin/sh\n# no external tools assumed: only the shell itself\n'
        'case "$0" in */*) HERE="${0%/*}" ;; *) HERE=. ;; esac\n'
        'for PY in "$HERE/runtime/bin/python3" python3 python; do\n'
        '  if [ -x "$PY" ] || command -v "$PY" >/dev/null 2>&1; then exec "$PY" -I "$HERE/verify.py" "$@"; fi\n'
        'done\necho "no Python runtime found" >&2; exit 2\n')
    (out / "verify.sh").chmod(0o755)
    (out / "verify.bat").write_text(
        '@echo off\r\nset HERE=%~dp0\r\nif exist "%HERE%runtime\\python.exe" (\r\n'
        '  "%HERE%runtime\\python.exe" -I "%HERE%verify.py" %*\r\n) else (\r\n  python -I "%HERE%verify.py" %*\r\n)\r\n')
    (out / "README.txt").write_text(
        "RAKSHA verifier media\n\nRun:  sh verify.sh     (Linux/macOS)\n      verify.bat       (Windows)\n"
        "  or: python3 verify.py\n\nIt checks every file's seal, re-verifies each evidence bundle and advisory,\n"
        "and replays each finding against the shipped target: the reproducer must fire on the\n"
        "vulnerable copy and be dead on the patched copy. Nothing is installed; nothing leaves\n"
        "this machine. Exit 0 = all checks that ran passed.\n")
    shutil.copytree(PKG, out / "lib" / "raksha", ignore=_SKIP)
    findings: dict[str, dict] = {}
    for e in entries:
        bdst = out / "bundles" / e.finding_id
        shutil.copytree(e.bundle_dir, bdst)
        proof = json.loads((e.bundle_dir / "proof.json").read_text())
        row = {"bundle": f"bundles/{e.finding_id}", "patch_replay": e.patch_replay,
               "marker": e.marker or marker_for(proof.get("oracle") or "")}
        if e.target_root is not None:
            name = e.target_name or e.target_root.name
            tdst = out / "targets" / name
            if not tdst.exists():
                shutil.copytree(e.target_root, tdst, ignore=_SKIP)
            row["target"] = f"targets/{name}"
        if e.needs:
            row["needs"] = e.needs
        findings[e.finding_id] = row
    adv_rel = []
    for a in advisories:
        shutil.copytree(a, out / "advisories" / a.name)
        adv_rel.append(f"advisories/{a.name}")
    doc_rows = []
    for d in documents:
        shutil.copytree(d["src"], out / d["dest"])
        row = {"path": d["dest"], "stem": d["stem"]}
        if d.get("chain"):
            row["chain"] = d["chain"]
            row["first_prev"] = d.get("first_prev")
        doc_rows.append(row)
    if runtime is not None:
        shutil.copytree(runtime, out / "runtime", symlinks=True)
    files = {}
    for p in sorted(out.rglob("*")):
        rel = p.relative_to(out).as_posix()
        if p.is_file() and not rel.startswith("runtime/"):
            files[rel] = _sha(p)
    media = {"tool": "RAKSHA AI verifier media", "schema": 1, "findings": findings,
             "advisories": adv_rel, "documents": doc_rows, "runtime": runtime is not None,
             "files": files}
    raw = json.dumps(media, indent=2, sort_keys=True).encode()
    (out / "MEDIA.json").write_bytes(raw)
    k, key_id = (key, "caller") if key is not None else signing_key()
    (out / "MEDIA.sig.json").write_text(json.dumps({
        "alg": "HMAC-SHA256", "key_id": key_id, "media_sha256": hashlib.sha256(raw).hexdigest(),
        "signature": hmac.new(k, raw, hashlib.sha256).hexdigest()}, indent=2))
    return out


_STDLIB_DROP = {"test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "site-packages",
                "dist-packages", "__pycache__", "venv", "pydoc_data", "config-3.11-x86_64-linux-gnu"}


def portable_runtime(dest: str | Path) -> Path:
    """Relocate THIS interpreter and its standard library into `dest` (bin/python3 + lib/pythonX.Y),
    so the media carries its own runtime. CPython finds its stdlib relative to the binary (the
    `lib/pythonX.Y/os.py` landmark), so the tree runs from any path. Only the system C library and
    the few shared libraries the binary links (libm, libz, libexpat on Linux) are assumed — the same
    ones any Linux laptop carries. Third-party site-packages are deliberately not copied."""
    import os
    import sys
    import sysconfig
    dest = Path(dest)
    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    (dest / "bin").mkdir(parents=True, exist_ok=True)
    exe = Path(os.path.realpath(sys.executable))
    shutil.copy2(exe, dest / "bin" / "python3")
    shutil.copytree(stdlib, dest / "lib" / ver, symlinks=False,
                    ignore=lambda d, names: [n for n in names if n in _STDLIB_DROP or n.endswith(".pyc")])
    dyn = stdlib / "lib-dynload"
    if dyn.is_dir() and not (dest / "lib" / ver / "lib-dynload").exists():
        shutil.copytree(dyn, dest / "lib" / ver / "lib-dynload")
    return dest


def demo_media(out: str | Path, *, with_runtime: bool = False) -> Path:
    """The demo media: a verified Python fix (replays fire→dead), a secret finding, and an advisory."""
    import tempfile
    from .advisory import issue
    from .orchestrator import Session
    from .slice_three import run_python
    repo = PKG.parent
    s = Session()
    s.evidence_root = Path(tempfile.mkdtemp(prefix="raksha-media-ev-"))
    f = run_python()
    if f.status.value != "VERIFIED":
        raise RuntimeError(f"the Python demo finding did not verify ({f.status.value})")
    s.attach_target("py-cmdinject", [f])
    estate = repo / "demo-targets" / "mixed-estate"
    s.ingest_build_free(estate, name="mixed-estate")
    secret = next((x for x in s.findings.values()
                   if x.oracle.startswith("secrets:") and x.is_reportable and x.reproducer), None)
    entries = [Entry(f.id, s.bundle_dir(f.id), repo / "demo-targets" / "py-cmdinject", "py-cmdinject")]
    if secret is not None:
        entries.append(Entry(secret.id, s.bundle_dir(secret.id), estate, "mixed-estate", patch_replay=False))
    adv = issue(f, s.evidence_root / "advisories", others=list(s.findings.values()), registry=s.registry,
                bundle_dir=s.bundle_dir(f.id))
    rt = None
    if with_runtime:
        rt = Path(tempfile.mkdtemp(prefix="raksha-rt-")) / "runtime"
        portable_runtime(rt)
    return build_media(out, entries, advisories=[adv], runtime=rt)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m raksha.verifiermedia")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("out")
    d.add_argument("--runtime", action="store_true", help="carry a relocated Python runtime on the media")
    a = ap.parse_args(argv)
    p = demo_media(a.out, with_runtime=a.runtime)
    print(f"verifier media written to {p}; run: python3 {p / 'verify.py'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
