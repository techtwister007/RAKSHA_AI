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
_FRAME = re.compile(
    r"^\s+at\s+(?P<fqn>[\w.$<>]+)\((?P<file>[^:)]+)(?::(?P<line>\d+))?\)"
)
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
        match = _EXCEPTION.search(raw)
        if not match:
            return []

        exc = match.group("exc")
        title = (match.group("title") or "").strip()
        frames = self._frames(raw)
        is_security_issue = "FuzzerSecurityIssue" in exc

        if is_security_issue:
            severity = _SEVERITY.get(exc.rsplit(".", 1)[-1], "high")
            bug_class = cwe_for_jazzer(title or exc)
            message = f"Jazzer {exc.rsplit('.', 1)[-1]}: {title or exc}"
        else:
            # An uncaught ordinary exception. Real, reportable once it replays, but not
            # a security issue by itself -- do not inflate its severity.
            severity = "low"
            bug_class = _cwe_for_jvm_exception(exc)
            message = f"Uncaught {exc}" + (f": {title}" if title else "")

        finding = Finding(
            oracle=f"{self.name}:{exc.rsplit('.', 1)[-1]}",
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=message,
            severity=severity,
            frames=frames,
            abort_signature=abort_signature(bug_class, frames),
            raw_excerpt=excerpt(raw),
        )

        artifact = _ARTIFACT.search(raw)
        if artifact:
            finding.artifact_hint = artifact.group("path")

        seed_fix_site(finding, frames)
        return [finding]

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
    "NumberFormatException": "CWE-20",
}


def _cwe_for_jvm_exception(exc: str) -> str:
    return _JVM_EXCEPTION_CWE.get(exc.rsplit(".", 1)[-1], "CWE-noinfo")
