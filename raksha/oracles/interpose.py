"""B11 — the parser half of sink interposition: the LD_PRELOAD shim's banner becomes one finding.

The shim (`raksha/harness/raksha_interpose.c`) and the runner live in `raksha.harness.interpose`;
this oracle sits with the others so `ALL_ORACLES` can route a shim run's output without importing
the harness package. Silent on a clean run; never CONFIRMED by itself (the replay does that).
"""

from __future__ import annotations

import re

from ..finding import Finding, Frame
from .base import Oracle, abort_signature, excerpt, seed_fix_site

#: Sink name (as the shim prints it in the banner) -> CWE. exec/system/popen is OS command
#: injection; the optional network sink is SSRF.
_SINK_CWE: dict[str, str] = {
    "system": "CWE-78",
    "popen": "CWE-78",
    "execve": "CWE-78",
    "execv": "CWE-78",
    "execvp": "CWE-78",
    "execl": "CWE-78",
    "execlp": "CWE-78",
    "connect": "CWE-918",
}


# "=== RAKSHA INTERPOSE: system ===" — the only line that counts as a detection. A plain log line
# mentioning the shim could never be mistaken for a finding, which matters because the gate replays
# the reproducer against the patched build and asks this parser "did the sink still fire?".
_BANNER = re.compile(r"^===\s*RAKSHA INTERPOSE:\s*(?P<sink>[A-Za-z_][A-Za-z0-9_]*)\s*===\s*$", re.MULTILINE)
#: the optional detail line carrying the sanitised argument excerpt
_DETAIL = re.compile(r"^RAKSHA INTERPOSE: blocked sink '(?P<sink>[^']+)'(?P<rest>.*)$", re.MULTILINE)


class InterposeOracle(Oracle):
    """Turns the LD_PRELOAD shim's abort banner into one unified finding (SUSPECTED, one claim).

    Silent on a clean run (``parse`` returns ``[]`` when no banner is present), exactly like the
    other sink oracles. The pipeline attaches the reproducer and replays it; only then is the
    finding confirmed — this oracle never returns CONFIRMED, per the base-class contract.
    """

    name = "interpose"
    language = "c/c++"

    def parse(self, raw: str, *, target: str) -> list[Finding]:
        m = _BANNER.search(raw)
        if not m:
            return []
        sink = m.group("sink")
        bug_class = _SINK_CWE.get(sink, "CWE-noinfo")

        detail = _DETAIL.search(raw)
        message = f"RAKSHA interpose: blocked native sink {sink}() before it executed"
        if detail and detail.group("rest").strip():
            message += f" ({detail.group('rest').strip()})"

        # A compiled target carries no source line; the frame names the sink in the binary so the
        # record is always localised to *something* the operator can act on (the call site in the
        # binary), and fix_site_set is never empty for the downstream lanes.
        frames = [Frame(symbol=f"{sink}@{target}", uri=target, line=None)]

        finding = Finding(
            oracle=f"{self.name}:{sink}",
            bug_class=bug_class,
            language=self.language,
            target=target,
            message=message,
            # A sink abort is a deliberate security detection, not an incidental crash.
            severity="high" if bug_class != "CWE-noinfo" else "medium",
            frames=frames,
            abort_signature=abort_signature(f"{bug_class}:interpose:{sink}", frames),
            raw_excerpt=excerpt(raw),
        )
        seed_fix_site(finding, frames)
        return [finding]
