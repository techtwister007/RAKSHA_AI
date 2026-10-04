"""The C and Python deep slices as opt-in tests (need gcc / python toolchains and a few seconds).

Set RAKSHA_RUN_DEEP_SLICES=1 to run. These prove the deep lane — find a real abort, fix it, and pass
all five gate checks — for C (gcc+ASan) and Python (shell-injection sink), using the same gate the
Java slice uses. Kept out of the fast unit suite.
"""
from __future__ import annotations

import os
import shutil

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("RAKSHA_RUN_DEEP_SLICES") != "1",
    reason="set RAKSHA_RUN_DEEP_SLICES=1 (and have gcc/python) to run the deep slices",
)


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc required")
def test_c_slice_verifies():
    from raksha.finding import Status
    from raksha.slice_three import run_c
    assert run_c().status is Status.VERIFIED


def test_python_slice_verifies():
    from raksha.finding import Status
    from raksha.slice_three import run_python
    assert run_python().status is Status.VERIFIED
