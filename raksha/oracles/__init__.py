"""Oracle adapters — one per language, each a thin shim onto the unified record."""

from .asan import AsanOracle
from .base import Oracle
from .go_panic import GoOracle
from .jazzer import JazzerOracle
from .pysecsan import PySecSanOracle

#: The three oracles the Phase 0 keystone must prove. If a C trace, a Java reproducer
#: and a Python abort can all become valid records that one gate consumes, the
#: "one pipeline, every language" claim holds.
KEYSTONE_ORACLES: tuple[Oracle, ...] = (
    AsanOracle(),
    JazzerOracle(),
    PySecSanOracle(),
)

__all__ = [
    "Oracle",
    "AsanOracle",
    "JazzerOracle",
    "PySecSanOracle",
    "GoOracle",
    "KEYSTONE_ORACLES",
]
