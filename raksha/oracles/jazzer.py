"""Jazzer oracle — JVM targets. The deepest adapter, and the demo's workhorse.

Java is the *easiest* target, not the hardest: Jazzer's autofuzz writes the harness,
its built-in sanitizers catch security bugs (SQLi, LDAP, JNDI/log4j, command injection,
deserialization, SSRF, path traversal, XPath, ReDoS) with no work from us, and JUnit
gives a native regression suite for the gate's differential check.

Format verification status: **VERIFIED** for the `== Java Exception: <class>: <title>`
banner, the tab-indented `at fqn(File.java:NN)` frames, and the
`Test unit written to <path>` artifact line. These are Jazzer/libFuzzer output and are
stable.
"""

from __future__ import annotations

import re

from ..cwe import cwe_for_jazzer
from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

_EXCEPTION = re.compile(
    r"==\s*Java Exception:\s*(?P<exc>[\w.$]+)(?::\s*(?P<title>.*))?"
)
# Java 9+ prefixes frames with a module and/or class loader ("java.base/", "app//").
_FRAME = re.compile(
    r"^\s+at\s+(?:[\w.\-$@]*/{1,2})?(?P<fqn>[\w.$<>]+)\((?P<file>[^:)]+)(?::(?P<line>\d+))?\)"
)
_CAUSED_BY = re.compile(r"^\s*Caused by:\s*(?P<exc>[\w.$]+)", re.MULTILINE)
_ARTIFACT = re.compile(r"Test unit written to\s+(?P<path>\S+)")

#: Jazzer encodes severity in the exception class name.
_SEVERITY = {
    "FuzzerSecurityIssueCritical": "critical",
    "FuzzerSecurityIssueHigh": "high",
    "FuzzerSecurityIssueMedium": "medium",
    "FuzzerSecurityIssueLow": "low",
}


class JazzerOracle(Oracle):
    name = "jazzer"
    language = "java"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        """One finding per `== Java Exception` banner (a --keep_going run can report several)."""
        banners = list(_EXCEPTION.finditer(raw))
        findings = []
        for i, match in enumerate(banners):
            end = banners[i + 1].start() if i + 1 < len(banners) else len(raw)
            findings.append(self._one(raw, raw[match.start():end], match, target=target))
        return findings

    def _one(self, raw: str, section: str, match: re.Match[str], *, target: str) -> Finding:
        exc = match.group("exc")
        # A Jazzer title can run over several lines: "Remote Code Execution" then the line that
        # says WHAT executed ("Deserialization of arbitrary classes..."). Read up to the stack.
        title_lines = [(match.group("title") or "").strip()]
        for line in section.splitlines()[1:4]:
            if _FRAME.match(line) or not line.strip() or line.lstrip().startswith("=="):
                break
            title_lines.append(line.strip())
        title = " ".join(t for t in title_lines if t)
        # Only the stack that FOLLOWS the exception banner is this finding's trace. Output can
        # contain earlier stacks (e.g. a logged warning with its own `at ...` lines); taking
        # frames from the whole text would localise to the wrong place.
        frames = self._frames(section)
        is_security_issue = "FuzzerSecurityIssue" in exc

        if is_security_issue:
            severity = _SEVERITY.get(exc.rsplit(".", 1)[-1], "high")
            bug_class = cwe_for_jazzer(title or exc)
            message = f"Jazzer {exc.rsplit('.', 1)[-1]}: {title or exc}"
        else:
            # An uncaught ordinary exception. Real, reportable once it replays, but not a security
            # issue by itself -- do not inflate its severity. A wrapper's root cause ("Caused by:")
            # is what actually went wrong, so it decides the class when it is recognisable.
            causes = [m.group("exc") for m in _CAUSED_BY.finditer(section)]
            root = next((c for c in reversed(causes) if _cwe_for_jvm_exception(c) != "CWE-noinfo"), exc)
            severity = "low"
            bug_class = _cwe_for_jvm_exception(root) if root != exc else _cwe_for_jvm_exception(exc)
            message = f"Uncaught {exc}" + (f": {title}" if title else "") + \
                (f" (caused by {root.rsplit('.', 1)[-1]})" if root != exc else "")

        finding = Finding(
            oracle=f"{self.name}:{exc.rsplit('.', 1)[-1]}",
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=message,
            severity=severity,
            frames=frames,
            abort_signature=abort_signature(bug_class, frames),
            raw_excerpt=excerpt(section),
        )

        artifact = _ARTIFACT.search(raw)
        if artifact:
            finding.artifact_hint = artifact.group("path")

        seed_fix_site(finding, frames)
        return finding

    @staticmethod
    def _frames(raw: str) -> list[Frame]:
        frames: list[Frame] = []
        for line in raw.splitlines():
            m = _FRAME.match(line)
            if not m:
                continue
            fqn = m.group("fqn")
            frames.append(
                Frame(
                    symbol=fqn,
                    uri=_java_uri(fqn, m.group("file")),
                    line=int(m.group("line")) if m.group("line") else None,
                )
            )
        return frames


def _java_uri(fqn: str, file_name: str) -> str:
    """Reconstruct a source path from the fully-qualified name.

    A JVM stack frame reports only the bare file name (`AuditLogger.java`), but SARIF
    wants a path. The package in the FQN gives it: `com.example.svc.AuditLogger.write`
    plus `AuditLogger.java` -> `com/example/svc/AuditLogger.java`. Inner classes
    (`Outer$Inner`) report the outer file, so the `$` suffix is stripped first.

    Falls back to the bare file name when the two do not agree, rather than inventing a
    path that does not exist.
    """
    parts = fqn.split(".")
    if len(parts) < 2:
        return file_name
    class_name = parts[-2].split("$", 1)[0]
    package = parts[:-2]
    candidate = "/".join([*package, f"{class_name}.java"])
    return candidate if candidate.endswith(file_name) else file_name


_JVM_EXCEPTION_CWE = {
    "ArrayIndexOutOfBoundsException": "CWE-125",
    "IndexOutOfBoundsException": "CWE-125",
    "NullPointerException": "CWE-476",
    "ArithmeticException": "CWE-369",
    "NegativeArraySizeException": "CWE-1284",
    "OutOfMemoryError": "CWE-789",
    "StackOverflowError": "CWE-674",
    "ClassCastException": "CWE-704",
    "StringIndexOutOfBoundsException": "CWE-125",
    "NumberFormatException": "CWE-20",
}


def _cwe_for_jvm_exception(exc: str) -> str:
    return _JVM_EXCEPTION_CWE.get(exc.rsplit(".", 1)[-1], "CWE-noinfo")
