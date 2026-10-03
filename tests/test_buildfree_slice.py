"""The build-free slice end to end, plus a SARIF-schema check on its output."""
from __future__ import annotations

import json
import pathlib

import pytest

from raksha.lanes import scan_target
from raksha.finding import to_sarif_log

FIX = pathlib.Path(__file__).parents[1] / "demo-targets" / "mixed-estate"
SCHEMA = pathlib.Path(__file__).parents[1] / "schemas" / "sarif-2.1.0.json"


def test_slice_runs_and_reports_proven_findings():
    from raksha.slice_buildfree import run
    assert run(FIX) == 0


def test_buildfree_output_is_valid_sarif():
    jsonschema = pytest.importorskip("jsonschema")
    if not SCHEMA.exists():
        pytest.skip("schema not vendored")
    res = scan_target(FIX)
    jsonschema.validate(to_sarif_log(res.findings), json.loads(SCHEMA.read_text()))
