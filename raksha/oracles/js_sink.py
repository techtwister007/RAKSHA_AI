"""JsSec oracle — JavaScript / TypeScript (Node) targets.

The JavaScript mirror of the PySecSan oracle. A command injection in Node does not crash; the
`jssinkguard.js` preload (raksha/harness/jssinkguard.js) hooks the dangerous shell / eval / code-
loading sinks and aborts at the sink with a detectable banner, so a non-crashing injection bug
arrives at the pipeline looking exactly like a memory bug. Same record, same gate.

The banner this parses, emitted to stderr by jssinkguard before it exits 99:

    === BUG DETECTED: JsSec: command injection ===
    JsSec: command injection detected in child_process.execSync
      at convert (converter.js:11)

Only a line that REPORTS a detection counts — the banner or a "<detector> detected" line — so a
status line could never be mistaken for a finding (the gate calls this parser to ask "did the
attack still fire?", and an info line answering yes would fail every correct patch). Like PySecSan,
this returns exactly one finding per abort (the one-claim rule), in SUSPECTED; the pipeline attaches
the reproducer and confirms.
"""

from __future__ import annotations

import re

from ..cwe import cwe_for_pysecsan
from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

# The JsSec detection banner, and the "<detector> detected in <sink>" line jssinkguard prints.
_JSSEC = re.compile(
    r"===\s*(?:BUG DETECTED:\s*)?JsSec\w*\s*:\s*(?P<detector>[A-Za-z][A-Za-z /_-]{2,60}?)\s*==="
    r"|JsSec\w*\s*[:=\-]+\s*(?P<detector2>[A-Za-z][A-Za-z /_-]{2,60}?)\s+detected\b",
    re.MULTILINE,
)
_SINK = re.compile(r"detected in\s+(?P<sink>[\w.]+)", re.IGNORECASE)

# A V8 / Node stack frame: "  at convert (converter.js:11)" or "  at converter.js:11".
_JS_FRAME = re.compile(
    r"^\s*at\s+(?:(?P<symbol>[^\s(]+)\s+\()?(?P<uri>[^\s():]+):(?P<line>\d+)\)?\s*$"
)


class JsSinkOracle(Oracle):
    name = "js-sink"
    language = "javascript"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        detector_match = _JSSEC.search(raw)
        if not detector_match:
            return []
        detector = next(g for g in detector_match.group("detector", "detector2") if g)
        detector = detector.strip().rstrip(":-= ")

        frames = self._frames(raw)
        bug_class = cwe_for_pysecsan(detector)        # "command injection" -> CWE-78
        sink = _SINK.search(raw)
        message = f"JsSec: {detector}"
        if sink:
            message += f" reaching sink {sink.group('sink')}"
        # A sink abort is a deliberate security detection, not an incidental crash.
        severity = "high" if bug_class != "CWE-noinfo" else "medium"

        finding = Finding(
            oracle=f"jssec:{detector.replace(' ', '-')}",
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=message,
            severity=severity,
            frames=frames,
            abort_signature=abort_signature(f"{bug_class}:{message.split(':', 1)[0]}", frames),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(finding, frames)
        return [finding]

    @staticmethod
    def _frames(raw: str) -> list[Frame]:
        """Stack frames, innermost first.

        V8 prints the innermost frame first (the opposite of a CPython traceback), which is already
        the order the dedup key and the fix-site seeder assume — frame 0 is the abort site — so no
        reversal is needed here. jssinkguard emits only the one target-owned call-site frame.
        """
        return [
            Frame(symbol=m.group("symbol") or "<anonymous>", uri=m.group("uri"), line=int(m.group("line")))
            for line in raw.splitlines()
            if (m := _JS_FRAME.match(line))
        ]
