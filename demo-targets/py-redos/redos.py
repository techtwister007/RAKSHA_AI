"""A catastrophic-backtracking regular expression — the ReDoS demo for the hang oracle.

``scan`` matches its argument against ``^(a+)+$``. On a string of many 'a's followed by a
character that cannot match (so the overall match must fail), Python's backtracking engine
explores exponentially many ways to partition the 'a's before giving up, so the call does
not return within any reasonable budget. The top Python frame while it is stuck sits inside
the ``re`` module, which is how the hang oracle tells ReDoS (CWE-1333) from a plain
resource-exhaustion hang (CWE-400).

Benign path: a short string, or one that matches, returns effectively instantly.
"""

from __future__ import annotations

import re
import sys

#: The vulnerable pattern. Nested unbounded quantifiers (``(a+)+``) give the backtracking engine
#: exponentially many ways to partition a run of 'a's. ``scan`` calls the module-level
#: ``re.match`` so that while the engine is stuck the top Python frame is inside the ``re`` module
#: — which is how the hang oracle classifies this as ReDoS (CWE-1333) rather than a plain hang.
PATTERN = r"^(a+)+$"


def scan(text: str) -> bool:
    """Return whether ``text`` matches the pattern (benign) — or hang on a crafted string."""
    return re.match(PATTERN, text) is not None


def redos_input(n: int = 32) -> str:
    """The crafted string: ``n`` 'a's plus a non-matching tail, forcing exponential backtracking."""
    return "a" * n + "!"


if __name__ == "__main__":
    # Replay entry point for the hang oracle: run under a budget and let faulthandler dump the
    # stack and exit if `scan` has not returned in time. The dump names the `re` frame the hang
    # oracle keys ReDoS on; a benign input returns first and cancels the watchdog.
    import faulthandler

    arg = sys.argv[1] if len(sys.argv) > 1 else redos_input()
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
    faulthandler.dump_traceback_later(budget, exit=True)
    result = scan(arg)
    faulthandler.cancel_dump_traceback_later()
    print("match" if result else "no-match")
