"""B2 — deterministic input minimisation (ddmin)."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from raksha.minimise import minimise


def _contains_bug(data: bytes) -> bool:
    return b"BUG" in data


def test_minimises_to_exactly_the_required_bytes():
    data = b"xxxxxBUGxxxxx"
    out = minimise(data, _contains_bug)
    assert out == b"BUG"
    assert _contains_bug(out)
    assert len(out) < len(data)


def test_long_input_still_minimises_to_the_required_bytes():
    data = b"\x00" * 500 + b"BUG" + b"\xff" * 500
    out = minimise(data, _contains_bug)
    assert out == b"BUG"


def test_result_is_deterministic_across_runs():
    data = b"noise-noise-BUG-noise-noise"
    first = minimise(data, _contains_bug)
    second = minimise(data, _contains_bug)
    assert first == second == b"BUG"


def test_predicate_holds_on_output():
    data = bytes(range(256)) + b"BUG" + bytes(range(256))
    out = minimise(data, _contains_bug)
    assert _contains_bug(out)


def test_already_minimal_input_is_returned_unchanged():
    data = b"BUG"
    out = minimise(data, _contains_bug)
    assert out == b"BUG"


def test_single_byte_crash_is_returned_unchanged():
    out = minimise(b"\x00\x01Z\x02", lambda d: b"Z" in d)
    assert out == b"Z"


def test_non_crashing_input_is_returned_untouched():
    # The predicate is false for the whole input; we never fabricate a crashing reduction.
    data = b"nothing here"
    out = minimise(data, _contains_bug)
    assert out == data
    assert not _contains_bug(out)


def test_never_returns_a_non_crashing_input_when_original_crashes():
    data = b"abcBUGdef" * 10
    out = minimise(data, _contains_bug)
    assert _contains_bug(out)


def test_two_required_subsequences_both_survive():
    # Predicate needs BOTH markers present; ddmin cannot drop either.
    def needs_both(d: bytes) -> bool:
        return b"AA" in d and b"ZZ" in d

    data = b"....AA....ZZ...."
    out = minimise(data, needs_both)
    assert needs_both(out)
    assert b"AA" in out and b"ZZ" in out
    assert len(out) < len(data)


def test_is_locally_minimal():
    # Removing any single byte of the result must break the predicate (1-minimality).
    data = b"prefixBUGsuffix"
    out = minimise(data, _contains_bug)
    for i in range(len(out)):
        reduced = out[:i] + out[i + 1:]
        assert not _contains_bug(reduced), f"byte {i} was removable -- not locally minimal"
