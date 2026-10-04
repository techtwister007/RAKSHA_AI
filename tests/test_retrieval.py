"""The retrieval lane: one verified fix, remembered, re-used at ZERO inference on the next
occurrence of the same bug class at a different site.

The first C overflow is fixed by the template lane and remembered. A second target with the SAME bug
shape but different variable names, file and line is then fixed from retrieval alone (no client, no
template) — proving the memory generalises the learned fix rather than pasting the old file's bytes.
"""

from __future__ import annotations

import shutil
import tempfile
import textwrap
from pathlib import Path

import pytest

from raksha import autorepair
from raksha.autorepair import repair
from raksha.finding import Finding, FixSite, RepairLane, Status
from raksha.harness import autofuzz
from raksha.retrieval import FixMemory

HAVE_GCC = shutil.which("gcc") is not None
REPO = Path(__file__).parents[1]
C_TARGET = REPO / "demo-targets" / "c-nolibfuzzer"

# A second C target: the SAME length-field overflow shape as tlv.c, but different names, file and
# comment — "the same mistake in another system".
_RECORD_C = textwrap.dedent("""\
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>

    int parse_rec(const uint8_t *buf, size_t n) {
        if (n < 2) return -1;
        uint8_t kind = buf[0];
        size_t amount = buf[1];
        char out[32];
        if (kind == 0x01) {
            size_t cnt = (amount <= n - 2) ? amount : (n - 2);
            memcpy(out, buf + 2, cnt);   // different comment, different names: same bug
            return out[0];
        }
        return 0;
    }
""")


def _make_second_target() -> Path:
    d = Path(tempfile.mkdtemp(prefix="raksha-retrieval-"))
    (d / "src").mkdir()
    (d / "src" / "record.c").write_text(_RECORD_C)
    return d


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_second_occurrence_is_fixed_from_retrieval_at_zero_inference(monkeypatch):
    mem = FixMemory()

    # 1) first occurrence: template fixes it, the memory remembers it
    r1 = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    out1 = repair(r1.finding, r1.target, root=r1.target.source_root, reproducer=r1.crashing_input,
                  corpus=[b"\x01\x04abcd", b"\x02zz"], use_model=False, memory=mem)
    assert out1.verified and out1.lane is RepairLane.TEMPLATE
    assert len(mem) == 1 and mem.records[0].bug_class == "CWE-121"

    # 2) second occurrence at a DIFFERENT site: no template, no client — retrieval must carry it
    d = _make_second_target()
    try:
        r2 = autofuzz(d, max_execs=60000, use_model=False)
        assert r2.found and r2.finding.bug_class == "CWE-121"
        monkeypatch.setattr(autorepair, "generic_templates", lambda finding, root: [])
        out2 = repair(r2.finding, r2.target, root=r2.target.source_root, reproducer=r2.crashing_input,
                      corpus=[b"\x01\x04abcd", b"\x02zz"], use_model=False, client=None, memory=mem)
        assert out2.verified and out2.lane is RepairLane.RETRIEVAL
        assert r2.finding.status is Status.VERIFIED
        assert r2.finding.zero_inference          # retrieval costs no model tokens
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc")
def test_retrieval_retargets_to_the_new_file_never_the_old(monkeypatch):
    mem = FixMemory()
    r1 = autofuzz(C_TARGET, max_execs=60000, use_model=False)
    repair(r1.finding, r1.target, root=r1.target.source_root, reproducer=r1.crashing_input,
           corpus=[b"\x01\x04abcd", b"\x02zz"], use_model=False, memory=mem)
    assert len(mem) == 1

    d = _make_second_target()
    try:
        r2 = autofuzz(d, max_execs=60000, use_model=False)
        cands = mem.candidates(r2.finding, root=r2.target.source_root)
        assert len(cands) == 1
        diff = cands[0]
        # the diff names ONLY the new file, never the file it was learned from
        assert "a/src/record.c" in diff and "b/src/record.c" in diff
        assert "tlv.c" not in diff
        assert "sizeof(out)" in diff          # re-targeted to the new buffer, not `value`
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_non_matching_bug_class_yields_no_retrieval_candidate():
    mem = FixMemory()
    # a hand-built record standing in for a remembered CWE-121 C fix
    verified = _fake_verified_c_overflow()
    assert mem.remember(verified) is not None and len(mem) == 1

    d = _make_second_target()
    try:
        # a finding of a DIFFERENT bug class, same language, at the record.c shape — must not match
        other = Finding(oracle="asan", bug_class="CWE-476", language="c/c++", target="t",
                        message="null deref")
        other.add_fix_site(FixSite(uri="src/record.c", rank=0, start_line=12))
        assert mem.candidates(other, root=d) == []

        # the MATCHING class at the same different-enough site DOES match (sanity on the memory)
        same = Finding(oracle="asan", bug_class="CWE-121", language="c/c++", target="t",
                       message="overflow")
        same.add_fix_site(FixSite(uri="src/record.c", rank=0, start_line=12))
        assert mem.candidates(same, root=d) != []
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _fake_verified_c_overflow() -> Finding:
    """A VERIFIED CWE-121 finding carrying the tlv.c bound-copy diff, built directly so the memory
    test needs no compiler."""
    from raksha.finding import Reproducer, ReplayResult, GateCheck, utcnow
    from raksha.repair_templates import c_bound_copy
    f = Finding(oracle="asan:AddressSanitizer", bug_class="CWE-121", language="c/c++",
                target="c-nolibfuzzer", message="stack-buffer-overflow in parse_record")
    f.add_fix_site(FixSite(uri="src/tlv.c", rank=0, start_line=15, symbol="parse_record"))
    f.attach_reproducer(Reproducer.from_bytes(b"\x01\x04abcd", ["./replay"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), exit_code=1))
    f.confirm()
    diff = c_bound_copy(f, C_TARGET)
    assert diff
    f.mark_patched(diff, RepairLane.TEMPLATE)
    for c in GateCheck:
        f.record_gate(c, True, detail="ok")
    f.record_replay_after(ReplayResult(oracle_fired=False, at=utcnow(), exit_code=0))
    f.verify()
    return f
