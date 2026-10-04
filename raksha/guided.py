"""G2 — grammar-constrained model output for the repair lane.

A free-text completion has to be fished for a diff: prose around it, code fences, a truncated hunk.
When the endpoint supports guided decoding, the model is constrained to emit exactly one JSON
object of a fixed shape, so there is nothing to fish for:

    {"diff": "<unified diff>", "regression_test": "<test source>" | null}

Two request styles are supported, selected by RAKSHA_GUIDED_DECODING:

* ``json_schema`` — the OpenAI-standard ``response_format: {type: json_schema, ...}`` (served by
  vLLM's structured-output backends and most OpenAI-compatible servers);
* ``vllm``        — vLLM's ``guided_json`` request field, for older vLLM builds;
* ``off``         — (default) no constraint; the tolerant parser in ``repair.py`` runs as before.

Whatever the style, the reply is still checked here: a JSON object that parses but carries a
malformed diff is a parse failure, counted, never passed on. The gate still decides correctness —
guidance only removes the formatting failure mode, and the counters say how often it bit.
"""

from __future__ import annotations

import json
import os
import re

STYLES = ("json_schema", "vllm", "off")

REPAIR_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "diff": {"type": "string", "minLength": 1},
        "regression_test": {"type": ["string", "null"]},
    },
    "required": ["diff", "regression_test"],
    "additionalProperties": False,
}

_COUNTS = {"guided_ok": 0, "guided_failed": 0, "tolerant_ok": 0, "tolerant_failed": 0}


def style(env: dict | None = None) -> str:
    v = (env if env is not None else os.environ).get("RAKSHA_GUIDED_DECODING", "off").strip().lower()
    return v if v in STYLES else "off"


def request_fields(style_name: str) -> dict:
    """Extra chat-completion payload fields that impose the schema, for this style."""
    if style_name == "json_schema":
        return {"response_format": {"type": "json_schema",
                                    "json_schema": {"name": "raksha_repair", "strict": True,
                                                    "schema": REPAIR_SCHEMA}}}
    if style_name == "vllm":
        return {"guided_json": REPAIR_SCHEMA}
    return {}


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def wellformed_diff(diff: str) -> bool:
    """A unified diff whose headers are present and whose hunk bodies match their declared counts."""
    lines = diff.splitlines()
    if not any(l.startswith("--- ") for l in lines) or not any(l.startswith("+++ ") for l in lines):
        return False
    i, hunks = 0, 0
    while i < len(lines):
        m = _HUNK.match(lines[i])
        if not m:
            i += 1
            continue
        hunks += 1
        old = int(m.group(2)) if m.group(2) is not None else 1
        new = int(m.group(4)) if m.group(4) is not None else 1
        i += 1
        while i < len(lines) and (old > 0 or new > 0):
            l = lines[i]
            if l.startswith("\\"):
                i += 1
                continue
            if l.startswith(" ") or l == "":
                old -= 1; new -= 1
            elif l.startswith("-"):
                old -= 1
            elif l.startswith("+"):
                new -= 1
            else:
                return False
            i += 1
        if old != 0 or new != 0:
            return False
    return hunks > 0


def parse(text: str, style_name: str) -> tuple[str | None, str | None]:
    """(diff, regression_test) from one completion. Guided replies are parsed strictly; unguided
    ones go through the tolerant parser. Every outcome is counted."""
    if style_name != "off":
        try:
            obj = json.loads(text)
            diff = obj.get("diff") if isinstance(obj, dict) else None
            test = obj.get("regression_test") if isinstance(obj, dict) else None
            if isinstance(diff, str) and wellformed_diff(diff):
                _COUNTS["guided_ok"] += 1
                return (diff if diff.endswith("\n") else diff + "\n"), (test or None)
        except (ValueError, AttributeError):
            pass
        _COUNTS["guided_failed"] += 1
        return None, None
    from .repair import split_diff_and_test
    diff, test = split_diff_and_test(text)
    _COUNTS["tolerant_ok" if diff else "tolerant_failed"] += 1
    return diff, test


def counters() -> dict[str, int]:
    return dict(_COUNTS)


def reset_counters() -> None:
    for k in _COUNTS:
        _COUNTS[k] = 0
