# RAKSHA AI — model-lane benchmark (local model)

**Model:** Qwen2.5-Coder-7B-Instruct, Q4_K_M, served locally by llama.cpp on 4 CPU threads (no GPU).
**Set:** 8 bug-preserving variants of RAKSHA's own demo defects (the mutation factory: renamed
identifiers, equivalent APIs, reordered and reflowed code). **Rule unchanged throughout:** the
five-check gate decides; the model can only add repair candidates. Cloud (egress) calls: 0 in every run.
Reproduce: `RAKSHA_INFERENCE_BASE_URL=http://127.0.0.1:8701/v1 RAKSHA_REPAIR_MODEL=… python3 scripts/model_benchmark.py`.

## Results, run by run

| Run | What changed before it | Fixed model-free | Fixed with model | Model calls | Tokens | Time with model |
|-----|------------------------|------------------|------------------|-------------|--------|-----------------|
| 1 | — | 6/8 | 6/8 | 10 | 2,348 | 587 s |
| 2 | patch hygiene compares primitive classes | 6/8 | 6/8 | 10 | 2,348 | 582 s |
| 3 | edit blocks + diff re-anchoring; prompt aligned | 6/8 | 6/8 | 10 | 2,094 | 547 s |
| 4 | candidate top-up; no-op patches dropped | 6/8 | 6/8 | 24 | 5,784 | 1,235 s |
| final | new `os.system`/`os.popen` template | **8/8** | — (model not needed) | 0 | 0 | ≈ 30 s |

## What the benchmark exposed in the pipeline (and what was fixed)

Each run was followed by a diagnosis of the one variant still unfixed (`os.system` command injection),
reading the refusal reasons, the gate records and the model's raw replies.

1. **Patch hygiene refused the correct fix.** In run 1 the model proposed the standard fix
   (`subprocess.run([...])` instead of `os.system(...)`); hygiene rejected it as a "new execution
   primitive". *Fixed:* hygiene now compares primitive classes. A plain argument-list process call may
   replace a shell call; any new shell, network, code-loading or deserialising primitive is still refused.
2. **Malformed diffs.** The 7B model's unified diffs had wrong hunk counts and invented context, so the
   patch never applied (COMPILES failed). *Fixed:* the model may answer with SEARCH/REPLACE edit blocks,
   any unified diff is re-anchored on the real file, and RAKSHA writes the exact diff itself.
3. **The prompt contradicted the fix.** It told the model never to add a command call, yet the fix is a
   command call without a shell. *Fixed:* the prompt now forbids network, code loading and shells.
4. **Only one candidate per round.** llama.cpp ignores `n>1`, so the model lane got a third of its
   attempts. *Fixed:* further calls at rising temperature fill the round.
5. **Empty patches reached the gate.** The model sometimes returned a "diff" that changes nothing.
   *Fixed:* such candidates are dropped before the gate.
6. **Template gap (the root cause).** The shell template knew only `subprocess.run(shell=True)`, so the
   `os.system` and `os.popen` forms of the same injection were found but never fixed. *Fixed:* the
   `py_os_shell_safe` template. Result: 8/8 fixed through the gate with zero model calls.

## What this says about the model on this hardware

- A 7B model on CPU is too slow and too weak to add fixes here: about one minute per call, and after the
  pipeline fixes it still returned changes that did not address the defect. The finale design uses a
  ~32B model on the GPU; re-run this script there to measure it.
- The fixes above help any model: correct hygiene, exact diffs from edit blocks, full candidate rounds,
  no wasted gate runs. They are tested with fake model replies (`tests/test_autorepair.py`).
- RAKSHA's design holds: templates and fix memory fix what they know at zero inference cost; the model
  is the fallback, and nothing it proposes is accepted without the gate.
