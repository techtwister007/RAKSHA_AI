"""Automatic harness generation — find bugs with no hand-written fuzz harness.

The deep lane used to need a human to write the driver that feeds input to the right function. This
package removes that step: it discovers the entry point, synthesizes the harness, and fuzzes it, then
hands a CONFIRMED finding and a gate-ready target to the same fix-and-prove pipeline as everything
else.
"""

from .autofuzz import AutofuzzResult, autofuzz
from .entrypoints import Entrypoint, discover
from .mutator import Fuzzer
from .synth import Harness, quality_gate, synthesize

__all__ = ["autofuzz", "AutofuzzResult", "discover", "Entrypoint", "Fuzzer", "Harness",
           "synthesize", "quality_gate"]
