"""The target abstraction the gate runs against.

The gate is language-agnostic. Everything language-specific — how to build, how to run one
input, how to run the project's own tests, how to measure coverage, how to fuzz for a while —
is behind this interface, provided by the language adapter. The gate itself never shells out
to a compiler or a fuzzer directly, which is what lets one gate serve every language.

Two implementations ship: `CommandTarget`, which drives any target through shell commands
the adapter supplies, and (in the tests) a fake target that simulates a program with known
bugs and known good and bad patches, so the gate's judgement can be tested without a toolchain.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class BuildResult:
    ok: bool
    label: str
    log: str = ""
    root: Path | None = None


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False

    @property
    def text(self) -> str:
        return (self.stdout + b"\n" + self.stderr).decode("utf-8", "replace")


@dataclass(frozen=True)
class TestResult:
    ran: int
    failed: int
    log: str = ""

    @property
    def passed(self) -> bool:
        return self.failed == 0


class Target(Protocol):
    """What the gate needs from a language adapter."""

    def build(self, patch_diff: str | None) -> BuildResult:
        """Build the target, with the patch applied if given. Never raises; reports ok=False."""

    def run(self, build: BuildResult, data: bytes) -> RunResult:
        """Run one input against a build (the harness / entry point)."""

    def run_tests(self, build: BuildResult) -> TestResult:
        """The project's own regression suite."""

    def run_added_test(self, build: BuildResult, test_source: str) -> TestResult:
        """One extra test, as source, against a build. Used to verify the model's test."""

    def covered_lines(self, build: BuildResult, inputs: list[bytes]) -> set[tuple[str, int]]:
        """(file, line) pairs executed when running `inputs` against the build."""

    def refuzz(self, build: BuildResult, seconds: float) -> list[str]:
        """A bounded fresh fuzz campaign; returns raw tool output for each crash found."""


@dataclass
class CommandTarget:
    """Drive a target through adapter-supplied shell commands.

    Placeholders: `{root}` (the build directory), `{input}` (path of the input file),
    `{test}` (path of the added test source), `{seconds}` (refuzz budget), `{out}` (a
    directory for crash artifacts). Coverage commands must print one `file:line` per line.
    Refuzz commands must write one file per crash into `{out}`, each holding the raw tool
    output.

    The sandbox (no network, seccomp, cgroups) wraps these commands in Phase 4; this class
    only knows how to run them.
    """

    source_root: Path
    build_cmd: str
    run_cmd: str
    test_cmd: str
    added_test_cmd: str | None = None
    added_test_path: str = "raksha_added_test"
    coverage_cmd: str | None = None
    refuzz_cmd: str | None = None
    apply_patch_cmd: str = "git apply --whitespace=nowarn {patch}"
    timeout: float = 120.0
    env: dict[str, str] = field(default_factory=dict)

    def _sh(self, cmd: str, cwd: Path, *, stdin: bytes | None = None, timeout: float | None = None) -> RunResult:
        try:
            proc = subprocess.run(
                cmd, shell=True, cwd=str(cwd), input=stdin, capture_output=True,
                timeout=timeout or self.timeout, env={**os.environ, **self.env},
            )
            return RunResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as e:
            return RunResult(-1, e.stdout or b"", e.stderr or b"", timed_out=True)

    def build(self, patch_diff: str | None) -> BuildResult:
        label = "patched" if patch_diff else "vulnerable"
        root = Path(tempfile.mkdtemp(prefix=f"raksha-{label}-"))
        copy = self._sh(f"cp -a {shlex.quote(str(self.source_root))}/. {shlex.quote(str(root))}/", root)
        if copy.exit_code != 0:
            return BuildResult(False, label, copy.text)
        if patch_diff:
            patch = root / ".raksha.patch"
            patch.write_text(patch_diff)
            applied = self._sh(self.apply_patch_cmd.format(patch=shlex.quote(str(patch))), root)
            if applied.exit_code != 0:
                return BuildResult(False, label, "patch did not apply:\n" + applied.text)
        built = self._sh(self.build_cmd.format(root=shlex.quote(str(root))), root)
        return BuildResult(built.exit_code == 0, label, built.text, root)

    def run(self, build: BuildResult, data: bytes) -> RunResult:
        assert build.root is not None
        with tempfile.NamedTemporaryFile(dir=build.root, delete=False) as f:
            f.write(data)
            path = f.name
        try:
            return self._sh(self.run_cmd.format(root=shlex.quote(str(build.root)), input=shlex.quote(path)),
                            build.root, stdin=data)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def run_tests(self, build: BuildResult) -> TestResult:
        assert build.root is not None
        r = self._sh(self.test_cmd.format(root=shlex.quote(str(build.root))), build.root)
        # Adapters that can report counts override this; the generic contract is exit status.
        return TestResult(ran=1, failed=0 if r.exit_code == 0 else 1, log=r.text)

    def run_added_test(self, build: BuildResult, test_source: str) -> TestResult:
        assert build.root is not None
        if not self.added_test_cmd:
            return TestResult(0, 0, "adapter does not support added tests")
        path = build.root / self.added_test_path
        path.write_text(test_source)
        r = self._sh(self.added_test_cmd.format(root=shlex.quote(str(build.root)), test=shlex.quote(str(path))),
                     build.root)
        return TestResult(ran=1, failed=0 if r.exit_code == 0 else 1, log=r.text)

    def covered_lines(self, build: BuildResult, inputs: list[bytes]) -> set[tuple[str, int]]:
        assert build.root is not None
        if not self.coverage_cmd:
            return set()
        covered: set[tuple[str, int]] = set()
        for data in inputs:
            with tempfile.NamedTemporaryFile(dir=build.root, delete=False) as f:
                f.write(data)
                path = f.name
            r = self._sh(self.coverage_cmd.format(root=shlex.quote(str(build.root)), input=shlex.quote(path)),
                         build.root, stdin=data)
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                if ":" in line:
                    file, _, num = line.rpartition(":")
                    if num.strip().isdigit():
                        covered.add((file.strip(), int(num)))
        return covered

    def refuzz(self, build: BuildResult, seconds: float) -> list[str]:
        assert build.root is not None
        if not self.refuzz_cmd:
            return []
        out = Path(tempfile.mkdtemp(prefix="raksha-refuzz-", dir=build.root))
        self._sh(self.refuzz_cmd.format(root=shlex.quote(str(build.root)), seconds=int(seconds),
                                        out=shlex.quote(str(out))),
                 build.root, timeout=seconds + 60)
        return [p.read_text(errors="replace") for p in sorted(out.iterdir()) if p.is_file()]
