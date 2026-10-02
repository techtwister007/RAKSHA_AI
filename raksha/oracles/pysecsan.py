"""PySecSan / Atheris oracle — Python targets.

Python has no sanitizer in the C sense, so this is the lane where the "install an
oracle, don't hope for a crash" idea does the most work: PySecSan hooks the dangerous
sinks (shell exec, eval/exec, SQL drivers, pickle/yaml, path joins, SSRF) and aborts at
the sink, so a non-crashing injection bug arrives at the pipeline looking exactly like
a memory bug. Same record, same gate.

Format verification status, stated honestly because it matters:

- **VERIFIED** — the Atheris uncaught-exception banner (`=== Uncaught Python
  exception: ===`) followed by a standard CPython traceback. This path always works,
  and it is the guaranteed fallback.
- **UNPROVEN** — PySecSan's own detector message. The matcher below is deliberately
  tolerant (it accepts several plausible shapes) because the exact string has not been
  validated against the installed tool. **Validate it in Phase 0 and tighten this
  regex.** Until then a detector message that does not match degrades to the verified
  traceback path, which costs us the CWE precision but never the finding itself.
  Degrade, don't die -- including in a parser.
"""

from __future__ import annotations

import re

from ..cwe import cwe_for_pysecsan
from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

_ATHERIS_BANNER = re.compile(r"===\s*Uncaught Python exception:\s*===")

# Tolerant PySecSan matcher -- see the UNPROVEN note in the module docstring.
# Accepts e.g. "PySecSan: command injection detected in subprocess.Popen",
# "=== PySecSan: SQL injection ===", "PySecSanSinkException: path traversal ...".
_PYSECSAN = re.compile(
    r"(?:^|\W)PySecSan\w*(?:Exception)?\s*[:=\-]*\s*"
    r"(?P<detector>[A-Za-z][A-Za-z /_-]{2,60}?)"
    r"(?:\s+detected|\s*===|\s*--|\s*:|\s*$)",
    re.MULTILINE,
)
_SINK = re.compile(r"(?:in|sink)\s+(?P<sink>[\w.]+\(?\)?)", re.IGNORECASE)

# "  File "/src/app/runner.py", line 57, in run_user_command"
_TB_FRAME = re.compile(
    r'^\s*File\s+"(?P<uri>[^"]+)",\s+line\s+(?P<line>\d+),\s+in\s+(?P<symbol>\S+)'
)
# The exception line that follows the Atheris banner, e.g. "ValueError: bad input".
_EXC_LINE = re.compile(r"^(?P<exc>[A-Za-z_][\w.]*(?:Error|Exception|Exit|Warning))(?::\s*(?P<detail>.*))?$")


class PySecSanOracle(Oracle):
    name = "pysecsan"
    language = "python"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        detector_match = _PYSECSAN.search(raw)
        has_banner = bool(_ATHERIS_BANNER.search(raw))
        if not detector_match and not has_banner:
            return []

        frames = self._frames(raw)

        if detector_match:
            detector = detector_match.group("detector").strip().rstrip(":-= ")
            bug_class = cwe_for_pysecsan(detector)
            sink = _SINK.search(raw)
            message = f"PySecSan: {detector}"
            if sink:
                message += f" reaching sink {sink.group('sink')}"
            # A sink abort is a deliberate security detection, not an incidental crash.
            severity = "high" if bug_class != "CWE-noinfo" else "medium"
            oracle = f"{self.name}:detector"
        else:
            exc, detail = self._exception(raw)
            bug_class = _PY_EXCEPTION_CWE.get(exc or "", "CWE-noinfo")
            message = f"Uncaught {exc or 'exception'}" + (f": {detail}" if detail else "")
            severity = "low"
            oracle = f"{self.name}:atheris"

        finding = Finding(
            oracle=oracle,
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=message,
            severity=severity,
            frames=frames,
            abort_signature=abort_signature(bug_class, frames),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(finding, frames)
        return [finding]

    @staticmethod
    def _frames(raw: str) -> list[Frame]:
        """Traceback frames, innermost first.

        CPython prints tracebacks outermost-first, the opposite of a sanitizer trace.
        We reverse them so frame 0 is always the abort site, which is what the dedup
        key and the fix-site seeder both assume.
        """
        frames = [
            Frame(
                symbol=m.group("symbol"),
                uri=m.group("uri"),
                line=int(m.group("line")),
            )
            for line in raw.splitlines()
            if (m := _TB_FRAME.match(line))
        ]
        frames.reverse()
        return frames

    @staticmethod
    def _exception(raw: str) -> tuple[str | None, str | None]:
        """The exception type and detail following the Atheris banner."""
        lines = raw.splitlines()
        for i, line in enumerate(lines):
            if not _ATHERIS_BANNER.search(line):
                continue
            for candidate in lines[i + 1 : i + 5]:
                m = _EXC_LINE.match(candidate.strip())
                if m:
                    return m.group("exc"), (m.group("detail") or "").strip() or None
            break
        return None, None


_PY_EXCEPTION_CWE = {
    "IndexError": "CWE-125",
    "KeyError": "CWE-noinfo",
    "ZeroDivisionError": "CWE-369",
    "RecursionError": "CWE-674",
    "MemoryError": "CWE-789",
    "AssertionError": "CWE-617",
    "UnicodeDecodeError": "CWE-20",
    "ValueError": "CWE-20",
    "TypeError": "CWE-704",
    "OverflowError": "CWE-190",
}
