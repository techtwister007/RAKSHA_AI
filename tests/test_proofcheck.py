"""A10 — machine-checked bound proofs.

The proved/refuted cases need an SMT solver, so they are skipped when ``z3`` is not importable
(the solver ships as an optional wheel in the sealed bundle). The honesty property -- that the
absence of a solver yields ``unavailable`` and never a proof -- is tested unconditionally by
forcing the no-solver path, so it runs on every box.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest

from raksha import proofcheck
from raksha.proofcheck import BoundClaim, ProofResult, bound_obligation, prove_bound, z3_available

HAVE_Z3 = z3_available()
needs_z3 = pytest.mark.skipif(not HAVE_Z3, reason="z3-solver not importable on this node")

# 0 .. 2**64-1 models an unsigned size_t: a correct clamp is provably in range over it.
SIZE_T = (0, 2 ** 64 - 1)
# -2**31 .. 2**31-1 models a signed int: a clamp that ignores a negative length is refuted over it.
INT32 = (-(2 ** 31), 2 ** 31 - 1)


# ---------------------------------------------------------------- always runs

def test_no_solver_is_unavailable_never_proved(monkeypatch):
    """With z3 absent the result is 'unavailable' and never claims a proof -- even for a clamp
    that WOULD prove if a solver were present."""
    monkeypatch.setattr(proofcheck, "_load_z3", lambda: None)
    claim = BoundClaim("cap", "min(n, cap)", {"n": SIZE_T, "cap": (64, 64)})
    res = prove_bound(claim)
    assert res.status == "unavailable"
    assert res.proved is False
    assert res.counterexample is None
    assert "not proved" in res.detail.lower() or "not installed" in res.detail.lower()


def test_z3_available_matches_import_attempt(monkeypatch):
    monkeypatch.setattr(proofcheck, "_load_z3", lambda: None)
    assert proofcheck.z3_available() is False


def test_obligation_text_is_human_readable():
    claim = BoundClaim("cap", "min(n, cap)", {"n": SIZE_T, "cap": (64, 64)})
    text = bound_obligation(claim)
    assert "min(n, cap)" in text and "cap" in text and "<=" in text and "forall" in text


def test_proof_result_dataclass_shape():
    r = ProofResult("proved", "ok")
    assert r.status == "proved" and r.detail == "ok" and r.counterexample is None and r.proved


# ---------------------------------------------------------------- need a solver

@needs_z3
def test_correct_clamp_proves():
    # min(n, cap) into a buffer of size cap, n an unsigned size_t: provably in [0, cap].
    claim = BoundClaim("cap", "min(n, cap)", {"n": SIZE_T, "cap": (64, 64)})
    res = prove_bound(claim)
    assert res.status == "proved", res.detail
    assert res.proved is True
    assert res.counterexample is None


@needs_z3
def test_correct_clamp_proves_with_symbolic_cap():
    # cap left symbolic over a plausible buffer range; still provable for min(n, cap).
    claim = BoundClaim("cap", "min(n, cap)", {"n": SIZE_T, "cap": (1, 4096)})
    res = prove_bound(claim)
    assert res.status == "proved", res.detail


@needs_z3
def test_wrong_clamp_forgetting_cap_is_refuted_with_counterexample():
    # The deliberately wrong "clamp" that forgot the cap: it writes n unbounded into a 64-byte buf.
    claim = BoundClaim("cap", "n", {"n": (0, 2 ** 31 - 1), "cap": (64, 64)})
    res = prove_bound(claim)
    assert res.status == "refuted", res.detail
    assert res.proved is False
    cex = res.counterexample
    assert cex is not None
    # the witness really violates the bound it claimed to enforce
    assert not (0 <= cex["_clamped_len"] <= cex["_dst_size"])
    assert cex["_clamped_len"] == cex["n"]
    assert cex["_dst_size"] == 64


@needs_z3
def test_negative_length_clamp_is_refuted():
    # min(n, cap) with a SIGNED n can go negative -- a real under-write bug the proof catches.
    claim = BoundClaim("cap", "min(n, cap)", {"n": INT32, "cap": (64, 64)})
    res = prove_bound(claim)
    assert res.status == "refuted", res.detail
    assert res.counterexample is not None
    assert res.counterexample["_clamped_len"] < 0


@needs_z3
def test_unparseable_claim_is_unknown_not_a_crash():
    claim = BoundClaim("cap", "frobnicate(n)", {"n": SIZE_T, "cap": (64, 64)})
    res = prove_bound(claim)
    assert res.status == "unknown"
    assert res.proved is False


def test_claim_is_read_from_the_patch_not_assumed():
    from raksha.proofcheck import claim_from_diff
    c = claim_from_diff("+  memcpy(buf, src, (len) < sizeof(buf) ? (len) : sizeof(buf));\n")
    assert c and c[0].clamped_len_expr == "min(n, cap)" and "sizeof(buf)" in c[1]
    # mismatched operands are NOT a clamp: never read as one
    assert claim_from_diff("+  memcpy(buf, src, (len) < sizeof(buf) ? (other) : sizeof(buf));\n") is None
    assert claim_from_diff("+  if (i < n) x = 1;\n") is None
    go = claim_from_diff("+\tout := data[2:min(n, len(data))]\n")
    assert go and go[0].var_ranges["hi"][0] < 0          # a signed int high bound is modelled as signed
