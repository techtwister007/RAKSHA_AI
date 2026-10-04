# RAKSHA AI — model-lane benchmark

Model: `qwen2.5-coder-7b` served locally (llama.cpp, 4 CPU threads, Q4 quantisation). Set: 8 bug-preserving variants of RAKSHA's own demo defects (mutation factory). The five-check gate decides in both runs; the model can only add repair candidates.

| | model-free | with model |
|---|---|---|
| variants found | 8/8 | 8/8 |
| fixed through the gate | 6/8 (75.0%) | 6/8 (75.0%) |
| model calls | 0 | 10 |
| completion tokens | 0 | 2348 |
| cloud (egress) calls | 0 | 0 |
| wall time (s) | 36.6 | 587.4 |

## Per variant

| variant | model-free | with model |
|---|---|---|
| rename | fixed (TEMPLATE) | fixed (TEMPLATE) |
| memmove | fixed (TEMPLATE) | fixed (TEMPLATE) |
| reorder | fixed (TEMPLATE) | fixed (TEMPLATE) |
| reflow | fixed (TEMPLATE) | fixed (TEMPLATE) |
| rename | fixed (TEMPLATE) | fixed (TEMPLATE) |
| os_system | found, not fixed | found, not fixed |
| os_popen | found, not fixed | found, not fixed |
| reflow | fixed (TEMPLATE) | fixed (TEMPLATE) |

Hardware note: a CPU-only 7B model is the floor, not the finale configuration (a ~32B model on the GPU). Re-run this script on the finale box to replace these numbers.
