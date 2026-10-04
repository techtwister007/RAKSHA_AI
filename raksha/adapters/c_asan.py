"""C / gcc+ASan adapter — configures the generic CommandTarget for a C project.

The deep lane for C: build with AddressSanitizer, run inputs through a hand-written harness, and let
the real AsanOracle parse genuine sanitizer output. The fix lane for the demo target is a bounds
check (template); the gate proves it the same way it proves every other language's fix.

`c_target(root)` returns a CommandTarget wired for the bundled c-overflow demo (harness.c +
src/parser.c + run_tests.sh). The compiler, harness name and test command are the only knobs, so the
same adapter drives any single-harness C project.
"""

from __future__ import annotations

from pathlib import Path

from ..gate.target import CommandTarget

#: Build flags per sanitizer. "thread" is the concurrency lane: gcc's libtsan reports a data race
#: as `WARNING: ThreadSanitizer: data race`, which `oracles.tsan.TsanOracle` turns into a CWE-362
#: record; -O1 is what TSan documents as its minimum, and the frame pointer keeps the stacks readable.
_SANITIZER_FLAGS = {
    "address": "-g -fsanitize=address -fno-omit-frame-pointer",
    "thread": "-g -O1 -fsanitize=thread -fno-omit-frame-pointer",
}
_SANITIZER_LIBS = {"address": "", "thread": " -lpthread"}
_BUILD = "{cc} {flags} -o harness {sources}{libs}"
DEFAULT_SOURCES = "harness.c src/parser.c"


def c_target(root: str | Path, *, cc: str = "gcc", timeout: float = 120.0,
             sanitizer: str = "address", sources: str = DEFAULT_SOURCES) -> CommandTarget:
    """A gate-ready CommandTarget for a single-harness C project.

    `sanitizer` is "address" (the default: ASan, memory-safety bugs) or "thread" (TSan, data races —
    pair it with `oracles=(TsanOracle(),)` on the gate). `sources` lists what the harness links.
    """
    if sanitizer not in _SANITIZER_FLAGS:
        raise ValueError(f"unknown sanitizer {sanitizer!r}; one of {sorted(_SANITIZER_FLAGS)}")
    return CommandTarget(
        source_root=Path(root).resolve(),
        build_cmd=_BUILD.format(cc=cc, flags=_SANITIZER_FLAGS[sanitizer], sources=sources,
                                libs=_SANITIZER_LIBS[sanitizer]),
        run_cmd="./harness {input}",
        test_cmd="sh run_tests.sh",
        # Coverage mode: the harness prints the fix-site line only if it actually reached parse.
        coverage_cmd="RAKSHA_COV=1 ./harness {input}",
        # Fresh campaign: random long inputs that overflow the vulnerable build and nothing the fixed
        # one; each crash's ASan output is written to {out} for the oracle to read.
        refuzz_cmd=(
            "for i in $(seq 1 24); do "
            "head -c $(( (RANDOM % 64) + 20 )) /dev/urandom > in_$i 2>/dev/null || "
            "dd if=/dev/urandom of=in_$i bs=1 count=48 2>/dev/null; "
            "./harness in_$i > /dev/null 2> err_$i; "
            "if [ $? -ne 0 ]; then cp err_$i {out}/crash_$i; fi; done"
        ),
        apply_patch_cmd="git apply -p1 {patch}",
        timeout=timeout,
    )


def bounds_check_patch(parser_src: str) -> str:
    """Template-lane fix for the demo target: bound the copy to the buffer size.

    Generated with difflib from the real source so the hunk line numbers always match, rather than
    hand-maintained. The checksum loop already caps at 16, so benign inputs are unchanged.
    """
    import difflib

    before = parser_src
    vuln = "    memcpy(buf, data, len);              /* BUG: unbounded copy into a 16-byte buffer */\n"
    fix = ("    int n = len < (int) sizeof(buf) ? len : (int) sizeof(buf);\n"
           "    memcpy(buf, data, n);                /* FIX: bound the copy to the buffer size */\n")
    if vuln not in before:
        raise ValueError("vulnerable memcpy line not found in parser.c")
    after = before.replace(vuln, fix)
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/src/parser.c", tofile="b/src/parser.c"))
