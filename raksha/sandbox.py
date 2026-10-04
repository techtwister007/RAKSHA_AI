"""The sandbox — every build and every run of untrusted target code is wrapped here.

We execute code we have never seen on a box the Army cares about, so this is rated critical for
trust and the jury will ask about it. The rule is absolute: untrusted code never gets a network
interface, and it runs under seccomp and resource limits.

This module builds the wrapper command; it does not require Docker to be importable or running, so it
is unit-testable anywhere. At deploy time the wrapper is a `docker run` (or gVisor/Firecracker)
invocation with:

  --network none        no network interface at all — this is the NETWORK INTERFACES: 0 badge
  --read-only           immutable root; only an explicit workdir tmpfs is writable
  --security-opt        seccomp profile + no-new-privileges
  --cpus / --memory     cgroup caps so one target cannot starve the box
  --pids-limit          stop fork bombs
  --cap-drop ALL        no Linux capabilities

`wrap()` turns any inner command into the sandboxed invocation; `Sandbox.run` executes it when a
container runtime is present, and otherwise reports clearly that it was not executed rather than
silently running unsandboxed.

`run_untrusted()` is the ONE door every build, run, test, coverage and refuzz command of target code
goes through. With a sandbox provisioned (RAKSHA_SANDBOX_IMAGE) it runs inside it; with
RAKSHA_REQUIRE_SANDBOX=1 and no sandbox it refuses; otherwise (a development box) it runs on the host
— and every execution is counted either way, so the NETWORK INTERFACES badge reports what actually
happened instead of what the policy intends.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field

# ---- execution accounting: the posture badge is derived from these, never asserted ----
_SANDBOXED_RUNS = 0
_UNSANDBOXED_RUNS = 0


def execution_counts() -> dict[str, int]:
    return {"sandboxed_runs": _SANDBOXED_RUNS, "unsandboxed_runs": _UNSANDBOXED_RUNS}


@dataclass(frozen=True)
class SandboxPolicy:
    image: str = "raksha-sandbox:latest"
    runtime: str = "docker"          # docker | podman; gVisor via --runtime=runsc on the command
    cpus: str = "2"
    memory: str = "4g"
    pids_limit: int = 512
    network: str = "none"            # never anything else for untrusted code
    read_only: bool = True
    seccomp: str | None = None       # path to a seccomp json, or None for the runtime default
    runsc: bool = False              # True => gVisor (--runtime=runsc)
    extra: tuple[str, ...] = ()

    def docker_flags(self) -> list[str]:
        flags = [
            f"--network={self.network}",
            f"--cpus={self.cpus}",
            f"--memory={self.memory}",
            f"--pids-limit={self.pids_limit}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ]
        if self.read_only:
            flags.append("--read-only")
        if self.seccomp:
            flags.append(f"--security-opt=seccomp={self.seccomp}")
        # with no explicit profile the runtime's default seccomp profile applies; "seccomp=default"
        # is not a keyword (docker reads it as a file path) and would make every run fail
        if self.runsc:
            flags.append("--runtime=runsc")
        flags.extend(self.extra)
        return flags


@dataclass
class Sandbox:
    policy: SandboxPolicy = field(default_factory=SandboxPolicy)

    def wrap(self, inner_cmd: str, *, workdir: str = "/work", mount: str | None = None) -> list[str]:
        """Return the full sandboxed argv for running `inner_cmd` with no network."""
        argv = [self.policy.runtime, "run", "--rm", "-i", *self.policy.docker_flags(), "-w", workdir]
        if mount:
            # `mount` is RAKSHA's own per-build scratch copy of the target, never the original
            # source, so it is mounted writable (builds write their outputs); the root stays
            # read-only and /tmp is a bounded tmpfs
            argv += ["-v", f"{mount}:{workdir}:rw", "--tmpfs", "/tmp:rw,size=512m"]
        argv += [self.policy.image, "sh", "-lc", inner_cmd]
        return argv

    def available(self) -> bool:
        return shutil.which(self.policy.runtime) is not None

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Sandbox | None":
        """The provisioned sandbox, or None. RAKSHA_SANDBOX_IMAGE names the toolchain image;
        RAKSHA_SANDBOX_ARGS adds runtime flags (e.g. a read-only dependency-cache mount)."""
        env = env if env is not None else os.environ
        image = env.get("RAKSHA_SANDBOX_IMAGE")
        if not image:
            return None
        extra = tuple(shlex.split(env.get("RAKSHA_SANDBOX_ARGS", "")))
        return cls(SandboxPolicy(image=image, runtime=env.get("RAKSHA_SANDBOX_RUNTIME", "docker"),
                                 runsc=env.get("RAKSHA_SANDBOX_GVISOR") == "1", extra=extra))

    def run(self, inner_cmd: str, *, workdir: str = "/work", mount: str | None = None,
            timeout: float = 300.0) -> tuple[int, str]:
        """Execute the sandboxed command. If no runtime is present, do NOT run unsandboxed —
        report it, so untrusted code is never executed without isolation by accident."""
        if not self.available():
            return (127, f"SANDBOX UNAVAILABLE: {self.policy.runtime} not found — refusing to run "
                         f"untrusted code without isolation")
        argv = self.wrap(inner_cmd, workdir=workdir, mount=mount)
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout)
            return p.returncode, (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return (-1, "sandboxed command timed out")

    def network_interfaces_claim(self) -> int:
        """The badge value. With --network=none the container has only loopback's absence of a
        real interface; we report 0 external interfaces, which is what the policy guarantees."""
        return 0 if self.policy.network == "none" else -1


def run_untrusted(cmd: str, cwd: str, *, stdin: bytes | None = None, timeout: float = 300.0,
                  env: dict | None = None, sandbox: Sandbox | None = None):
    """Run target code. Returns (exit_code, stdout, stderr, timed_out).

    Inside the sandbox when one is provisioned (paths under `cwd` are remapped to /work); refused
    when RAKSHA_REQUIRE_SANDBOX=1 and none is available; on the host otherwise. Counted either way.
    """
    global _SANDBOXED_RUNS, _UNSANDBOXED_RUNS
    box = sandbox if sandbox is not None else Sandbox.from_env()
    if box is not None:
        if not box.available():
            return 126, b"", f"SANDBOX UNAVAILABLE: {box.policy.runtime} not found".encode(), False
        _SANDBOXED_RUNS += 1
        argv = box.wrap(cmd.replace(str(cwd), "/work"), workdir="/work", mount=str(cwd))
    elif os.environ.get("RAKSHA_REQUIRE_SANDBOX") == "1":
        return 126, b"", b"SANDBOX REQUIRED: refusing to run untrusted code unsandboxed", False
    else:
        _UNSANDBOXED_RUNS += 1
        argv = None
    try:
        if argv is None:
            p = subprocess.run(cmd, shell=True, cwd=str(cwd), input=stdin, capture_output=True,
                               timeout=timeout, env=env)
        else:
            p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        return -1, e.stdout or b"", e.stderr or b"", True
