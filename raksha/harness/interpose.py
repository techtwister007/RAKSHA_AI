"""B11 — sink interposition for compiled targets with no source (the native mirror of sinkguard).

`raksha/harness/sinkguard.py` installs an in-process oracle for the synthesized *Python* harness:
it wraps the dangerous sinks so a non-crashing injection aborts at the sink instead of running. A
compiled binary we cannot recompile has no in-process hook to install — so we interpose at the libc
boundary with an `LD_PRELOAD` shim (`raksha/harness/raksha_interpose.c`). The shim resolves the
target's calls to `system` / `execve` / `execl` / `execlp` / `execv` / `execvp` / `popen` (and,
optionally, `connect`) to wrappers that write a detectable banner and exit non-zero **before the
real call runs**. It BLOCKS the operation; it never performs it. We feed adversarial input to the
target and will not actually spawn a shell to prove a sink was reachable — reaching the sink during
an untrusted-input run is itself the detection.

This module is the Python side:

* ``build_shim(cc="gcc")`` compiles the ``.c`` to a ``.so`` (returns ``None`` when gcc is absent or
  the compile fails — the lane then simply does not run, the degrade-don't-die rule).
* ``run_with_shim(argv, input_path, shim, *, timeout)`` runs the target binary with the shim
  preloaded, feeds the input bytes on stdin, and returns the combined stdout+stderr.
* ``InterposeOracle`` parses the banner into exactly one SUSPECTED ``Finding`` (CWE-78 for the
  exec/system/popen sinks, CWE-918 for the network ``connect`` sink), and is silent on a clean run.

Everything here is stdlib-only, offline and deterministic. The shim is C compiled through a gcc
subprocess; nothing in this module reaches the network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import names
from ..oracles.interpose import InterposeOracle, _SINK_CWE

__all__ = ["InterposeOracle", "_SINK_CWE", "build_shim", "run_with_shim"]

#: The C source compiled into the preload shim, shipped beside this module.
SHIM_SOURCE = Path(__file__).with_name("raksha_interpose.c")

def build_shim(cc: str = "gcc", *, out_dir: str | os.PathLike[str] | None = None) -> Path | None:
    """Compile ``raksha_interpose.c`` into a preloadable ``.so``.

    Returns the path to the shared object, or ``None`` when the compiler is absent or the build
    fails — the interposition lane then does not run (degrade, don't die). ``out_dir`` fixes the
    output location (and so the path, for determinism); without it a fresh temp dir is used.
    """
    if shutil.which(cc) is None:
        return None
    base = Path(out_dir) if out_dir is not None else Path(tempfile.mkdtemp(prefix=names.SCRATCH))
    base.mkdir(parents=True, exist_ok=True)
    so = base / "raksha_interpose.so"
    cmd = [cc, "-shared", "-fPIC", "-O2", "-o", str(so), str(SHIM_SOURCE), "-ldl"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)  # raksha-own: compiles OUR shim
    except OSError:
        return None
    if proc.returncode != 0 or not so.exists():
        return None
    return so


def run_with_shim(
    argv: list[str] | list[os.PathLike[str]],
    input_path: str | os.PathLike[str] | None,
    shim: str | os.PathLike[str],
    *,
    timeout: float,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Run the target binary with the interposition shim preloaded; return combined output.

    ``argv`` is the target command (binary + any args). The bytes at ``input_path`` are fed to the
    target on stdin (nothing is fed when it is ``None``). The shim is prepended to any existing
    ``LD_PRELOAD`` so an exec/system/popen sink aborts with the banner (exit 99) and the sink's
    operation never runs. On timeout, whatever output was produced is still returned. ``cwd`` and
    ``env`` let a caller (and the test) place the run and point the demo's sentinel path.
    """
    from ..sandbox import run_target
    data = Path(input_path).read_bytes() if input_path is not None else b""
    # The shim must sit under the run's directory so the sandbox (which mounts only that
    # directory) sees it too.
    workdir = Path(cwd) if cwd is not None else Path(str(argv[0])).resolve().parent
    local = workdir / ".raksha_interpose.so"
    if Path(shim).resolve() != local.resolve():
        shutil.copy2(shim, local)
    run_env = dict(os.environ if env is None else env)
    existing = run_env.get("LD_PRELOAD", "").strip()
    run_env["LD_PRELOAD"] = f"{local}:{existing}" if existing else str(local)
    try:
        proc = run_target([str(a) for a in argv], str(workdir), input=data, timeout=timeout,
                          env=run_env)
        out = (proc.stdout or b"") + (proc.stderr or b"")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") + (e.stderr or b"")
    except OSError as e:  # binary missing / not executable — a harness failure, not a finding
        return f"RAKSHA INTERPOSE: could not run target: {e}\n"
    return out.decode("utf-8", "replace")
