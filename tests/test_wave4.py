"""Wave 4: says-no beat (J1), intake (J2), egress counter (J6), verifier media (J7), CERT advisory
(J8), time-lapse (J9), the console routes that drive them, and the fork-server hang cut."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from raksha import hygiene
from raksha.orchestrator import Session

REPO = Path(__file__).parents[1]
ESTATE = REPO / "demo-targets" / "mixed-estate"
needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc + ASan")


# ---------------------------------------------------------------- J1
def test_saysno_patches_apply_shape_and_unsafe_is_refused_by_hygiene():
    from raksha import saysno
    from raksha.finding import FixSite, Finding
    ps = saysno.patches((saysno.ROOT / "src" / "parser.c").read_text())
    assert set(ps) == {"shallow", "unsafe", "weak", "proper"}
    for d in ps.values():
        assert d.startswith("--- a/src/parser.c")
    f = Finding.__new__(Finding)
    f.fix_site_set = [FixSite(uri="src/parser.c", rank=0, start_line=11)]
    assert "system" in (hygiene.check(ps["unsafe"], f) or "")
    assert hygiene.check(