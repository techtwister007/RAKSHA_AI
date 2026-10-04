"""B7: a direct-call crash on a stated precondition no input-facing caller can break stays SUSPECTED."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from raksha.contract import demotion_reason, input_facing, stated_precondition

C_GUARDED = """#include <stdint.h>
#include <stddef.h>

static const int TABLE[128] = {1};

/* Precondition: data[0] must be < 128. The caller must validate the tag first. */
int read_header(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    return TABLE[data[0]];
}

int checked(const uint8_t *data, size_t len) {
    if (len == 0 || data[0] >= 128) return 0;
    return read_header(data, len);
}
"""


def _tree(tmp_path: Path, text: str, name="lib.c") -> Path:
    (tmp_path / name).write_text(text)
    return tmp_path


def test_precondition_detected_from_comment():
    assert "must be < 128" in stated_precondition(C_GUARDED, "read_header")
    assert stated_precondition(C_GUARDED, "checked") is None


def test_python_docstring_and_assert():
    py = 'def f(buf):\n    """Decode. buf must be non-empty."""\n    return buf[0]\n\n' \
         'def g(x):\n    assert x > 0\n    return 1 // x\n'
    assert "must be non-empty" in stated_precondition(py, "f")
    assert stated_precondition(py, "g").startswith("assert")


def test_demoted_when_only_guarded_callers(tmp_path):
    root = _tree(tmp_path, C_GUARDED)
    reason = demotion_reason(root, "lib.c", "read_header")
    assert reason and "SUSPECTED" in reason


def test_not_demoted_when_input_facing_caller(tmp_path):
    text = C_GUARDED + "\n#include <unistd.h>\nint main(void) {\n  uint8_t b[64];\n" \
                       "  ssize_t n = read(0, b, 64);\n  return read_header(b, (size_t)n);\n}\n"
    root = _tree(tmp_path, text)
    assert input_facing(root, "read_header")
    assert demotion_reason(root, "lib.c", "read_header") is None


def test_public_api_with_no_callers_is_input_facing(tmp_path):
    text = "/* Precondition: len >= 8. */\nint api(const char *d, int len) {\n  return d[7];\n}\n"
    root = _tree(tmp_path, text)
    assert demotion_reason(root, "lib.c", "api") is None   # exported, attack surface: report


def test_no_precondition_means_no_demotion(tmp_path):
    text = "int inner(const char *d) {\n  return d[100];\n}\nint outer(const char *d) {\n  return inner(d);\n}\n"
    root = _tree(tmp_path, text)
    assert demotion_reason(root, "lib.c", "inner") is None


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc absent")
def test_autofuzz_holds_contract_crash_at_suspected(tmp_path):
    from raksha.harness.autofuzz import autofuzz
    root = _tree(tmp_path, C_GUARDED)
    r = autofuzz(root, use_model=False, max_execs=3000)
    assert not r.found
    assert r.demoted and r.demoted[0].contract
    assert not r.demoted[0].is_reportable
