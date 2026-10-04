# c-binsink — a compiled target with a shell sink, for B11 interposition

A single `main` that shells out via `system()` when the first input byte is the magic `0x42` ('B'),
and is benign otherwise. There is **no** source available in the defender's scenario (only the
compiled binary) and **no** fuzz harness — it exists to exercise `raksha/harness/raksha_interpose.c`
through `raksha/harness/interpose.py`.

Run under the shim:

```
gcc -O2 -o binsink src/binsink.c
SHIM=$(python3 -c "from raksha.harness.interpose import build_shim; print(build_shim())")
printf 'Battacker' | LD_PRELOAD=$SHIM ./binsink
# => === RAKSHA INTERPOSE: system ===   (exit 99; the `touch` never runs)
```

A benign first byte produces `benign` with no banner. Under the shim the triggering input never
creates the sentinel file (`$RAKSHA_BINSINK_SENTINEL`, default `raksha_binsink_sentinel`): the sink
is **blocked**, not merely detected. See `tests/test_interpose.py`.
