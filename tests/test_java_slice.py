"""The Java slice as an opt-in test. Skipped by default: it needs Maven, a warm local repo, and
~40s. Run it with RAKSHA_RUN_JAVA_SLICE=1 (e.g. in a nightly/rehearsal lane), not in the fast
unit suite."""

from __future__ import annotations

import os
import shutil

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RAKSHA_RUN_JAVA_SLICE") != "1" or shutil.which("mvn") is None,
    reason="set RAKSHA_RUN_JAVA_SLICE=1 and have Maven installed to run the Java slice",
)


def test_java_slice_finds_fixes_and_proves_log4shell():
    from raksha.slice_java import run
    assert run() == 0
