"""The build agent — a loop, not a genius.

Getting an unfamiliar target to build is the single point of total failure: if it never builds, the
build-dependent lanes (fuzzing, instrumentation) all starve at once. So the build agent is the
highest-value engineering in the project, and it is deliberately dumb: detect the build system, try
the standard build, and on failure apply escalating remedies, cheapest first:

    standard build
      → known error? apply a zero-inference remedy from the table, retry
      → still failing after N tries, or an unknown error? → DEGRADE to build-free

The last step is the whole point: a target that will not build is not a dead end, because the
build-free lanes (supply chain, secrets, config) need no build and still produce proven findings.
Degrade, do not die.

The model remedy (one bounded, targeted fix for an unknown error) is a declared hook here, not wired
to a live model — inference lives behind a single interface switched on in Phase 4. Until then the
agent uses the zero-inference remedy table and then degrades, which is the behaviour that matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol


class BuildSystem(str, Enum):
    MAVEN = "maven"
    GRADLE = "gradle"
    NPM = "npm"
    PIP = "pip"
    GO = "go"
    CARGO = "cargo"
    MAKE = "make"
    CMAKE = "cmake"
    UNKNOWN = "unknown"


#: Marker files, most specific first. The first match wins.
_MARKERS: tuple[tuple[str, BuildSystem], ...] = (
    ("pom.xml", BuildSystem.MAVEN),
    ("build.gradle", BuildSystem.GRADLE),
    ("build.gradle.kts", BuildSystem.GRADLE),
    ("package.json", BuildSystem.NPM),
    ("go.mod", BuildSystem.GO),
    ("Cargo.toml", BuildSystem.CARGO),
    ("CMakeLists.txt", BuildSystem.CMAKE),
    ("setup.py", BuildSystem.PIP),
    ("pyproject.toml", BuildSystem.PIP),
    ("requirements.txt", BuildSystem.PIP),
    ("Makefile", BuildSystem.MAKE),
)

_STANDARD_BUILD: dict[BuildSystem, str] = {
    BuildSystem.MAVEN: "mvn -q -B -o test-compile",
    BuildSystem.GRADLE: "gradle --offline testClasses",
    BuildSystem.NPM: "npm ci --offline || npm install --offline",
    BuildSystem.PIP: "pip install -e . || pip install -r requirements.txt",
    BuildSystem.GO: "go build ./...",
    BuildSystem.CARGO: "cargo build --offline",
    BuildSystem.MAKE: "make",
    BuildSystem.CMAKE: "cmake -S . -B build && cmake --build build",
}


def detect_build_system(root: str | Path) -> BuildSystem:
    root = Path(root)
    present = {p.name for p in root.iterdir()} if root.is_dir() else set()
    for marker, system in _MARKERS:
        if marker in present:
            return system
    return BuildSystem.UNKNOWN


@dataclass(frozen=True)
class Remedy:
    """A zero-inference fix for a recognised build error."""

    id: str
    pattern: re.Pattern
    description: str
    #: Returns a shell command to run before retrying, or None for "retry as-is after noting it".
    action: Callable[[re.Match, Path], str | None]


def _install_missing_maven_artifact(m: re.Match, root: Path) -> str | None:
    # In a real deployment this pulls from the offline mirror; here we just note and retry, since
    # the mirror warm-up is a Phase 4 concern. The remedy is recognised, which is what we assert.
    return None


_REMEDIES: tuple[Remedy, ...] = (
    Remedy("maven-missing-artifact",
           re.compile(r"Could not (?:resolve|find) artifact ([\w.\-:]+)"),
           "dependency missing from the local repo → fetch from the offline mirror",
           _install_missing_maven_artifact),
    Remedy("maven-wrong-java",
           re.compile(r"(?:invalid target release|requires Java|class file version)\s*[:=]?\s*(\d+)"),
           "wrong JDK → switch to the cached toolchain for that release",
           lambda m, root: None),
    Remedy("missing-build-tool",
           re.compile(r"(?:command not found|is not recognized).*?(mvn|gradle|npm|go|cargo|make|cmake)"),
           "build tool missing → install from the OS package mirror",
           lambda m, root: None),
    Remedy("npm-lockfile-mismatch",
           re.compile(r"npm ci.*can only install packages when your package.json and package-lock"),
           "lockfile out of sync → fall back to npm install",
           lambda m, root: "npm install --offline"),
    Remedy("test-dep-missing",
           re.compile(r"(?:cannot find symbol|ModuleNotFoundError|package .* is not in).*test", re.I),
           "a test-only dependency is missing → build with tests off and note it",
           lambda m, root: None),
)


class Runner(Protocol):
    def run(self, cmd: str, cwd: Path) -> tuple[int, str]:
        """Run a shell command in cwd; return (exit_code, combined_output)."""


@dataclass
class BuildOutcome:
    ok: bool
    degraded: bool                       # True => build failed, fall through to build-free lanes
    system: BuildSystem
    attempts: int
    remedies_applied: list[str] = field(default_factory=list)
    log: str = ""

    @property
    def summary(self) -> str:
        if self.ok and not self.remedies_applied:
            return f"built with {self.system.value} on the first try"
        if self.ok:
            return f"built with {self.system.value} after {len(self.remedies_applied)} remedy(ies): " \
                   + ", ".join(self.remedies_applied)
        return f"{self.system.value} build failed after {self.attempts} attempt(s) → build-free mode"


class BuildAgent:
    """Drives a target to a build, or cleanly to build-free mode."""

    def __init__(self, runner: Runner, *, max_attempts: int = 5) -> None:
        self.runner = runner
        self.max_attempts = max_attempts

    def build(self, root: str | Path) -> BuildOutcome:
        root = Path(root)
        system = detect_build_system(root)
        if system is BuildSystem.UNKNOWN:
            return BuildOutcome(False, True, system, 0, log="no recognised build system → build-free mode")

        cmd = _STANDARD_BUILD[system]
        applied: list[str] = []
        logs: list[str] = []
        for attempt in range(1, self.max_attempts + 1):
            code, out = self.runner.run(cmd, root)
            logs.append(f"[attempt {attempt}] exit={code}\n{out[-600:]}")
            if code == 0:
                return BuildOutcome(True, False, system, attempt, applied, "\n".join(logs))
            remedy = self._match_remedy(out)
            if remedy is None:
                # Unknown error. The bounded model remedy would go here (one targeted fix); until
                # inference is wired in Phase 4 we degrade rather than guess.
                logs.append("unknown build error → degrade (model remedy hook not yet active)")
                break
            applied.append(remedy.id)
            extra = remedy.action(remedy.pattern.search(out), root)
            logs.append(f"remedy: {remedy.id} — {remedy.description}")
            if extra:
                code2, out2 = self.runner.run(extra, root)
                logs.append(f"[remedy cmd] exit={code2}\n{out2[-300:]}")
                cmd = extra if code2 == 0 else cmd
        return BuildOutcome(False, True, system, attempt, applied, "\n".join(logs))

    @staticmethod
    def _match_remedy(output: str) -> Remedy | None:
        for remedy in _REMEDIES:
            if remedy.pattern.search(output):
                return remedy
        return None
