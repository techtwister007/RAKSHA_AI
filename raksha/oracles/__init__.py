"""Oracle adapters — one per language, each a thin shim onto the unified record."""

from .asan import AsanOracle
from .base import Oracle
from .go_panic import GoOracle
from .jazzer import JazzerOracle
from .js_sink import JsSinkOracle
from .pysecsan import PySecSanOracle
from .rust_panic import RustPanicOracle
from .tsan import TsanOracle

#: The three oracles the Phase 0 keystone must prove. If a C trace, a Java reproducer
#: and a Python abort can all become valid records that one gate consumes, the
#: "one pipeline, every language" claim holds.
KEYSTONE_ORACLES: tuple[Oracle, ...] = (
    AsanOracle(),
    JazzerOracle(),
    PySecSanOracle(),
)

#: Every oracle the pipeline ships, for ingest that routes raw output to whichever one claims it.
#: KEYSTONE_ORACLES is left as the three-oracle keystone the Phase 0 tests count; the gate's
#: default oracle set stays the keystone too, and a concurrency gate run passes TsanOracle explicitly.
ALL_ORACLES: tuple[Oracle, ...] = (*KEYSTONE_ORACLES, GoOracle(), TsanOracle(),
                                   RustPanicOracle(), JsSinkOracle())

__all__ = [
    "Oracle",
    "AsanOracle",
    "JazzerOracle",
    "PySecSanOracle",
    "GoOracle",
    "TsanOracle",
    "RustPanicOracle",
    "JsSinkOracle",
    "ALL_ORACLES",
    "KEYSTONE_ORACLES",
]
