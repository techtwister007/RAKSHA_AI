# c-race — a data race for the concurrency lane

`process(const uint8_t*, size_t)` folds its input into a one-byte digest. When the first byte is
`> 0x40` it splits the work across two pthreads that both add into one shared accumulator with no
lock — a data race that `gcc -fsanitize=thread` reports and `raksha.oracles.tsan.TsanOracle` turns
into a CWE-362 record. Small inputs with a first byte `<= 0x40` take the sequential path and are
race-free, so a corpus of them is a clean differential set and a fuzzer has to find the branch.

`fix.diff` guards the shared update with the mutex the file already declares; the gate proves it:
compiles, the reproducer no longer fires TSan, every corpus input and the target's own tests
produce identical output, the fix site is still reached, and the reproducer's neighbourhood plus a
fresh campaign find nothing. `tests/test_tsan.py` runs exactly that.
