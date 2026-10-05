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

## Is the pipeline sound? A check with a capable "model" (5 October 2026)

The runs above could not separate *the model is weak* from *the pipeline loses good answers*. So
the model lane was tested on its own:
- the fix templates are switched off, so every fix must come from the model;
- a stand-in model returns answers written in advance for the eight variants: correct fixes
  written the way a capable model writes them, and, separately, plausible but wrong ones.

`python3 scripts/model_lane_check.py` reproduces it in about a minute, with no model server.

| Answers given | Found | Fixed through the gate | Lane |
|---|---|---|---|
| none (control) | 8/8 | 0/8 | — |
| correct, before the fix below | 8/8 | 4/8 (all four C fixes lost) | LLM |
| correct, after the fix | 8/8 | **8/8** | LLM |
| wrong (bound too loose, `;` blocklist, shell quoting, `eval`) | 8/8 | **0/8** | — |

**Flaw found and fixed.** A model copies a code line but drops its trailing comment
(`/* ...but not to sizeof: BUG */`). The edit-block matcher allowed for differences in whitespace
but not in comments, so every correct C fix was discarded before it reached the gate. `_locate` in
`raksha/repair.py` now has a third matching tier, *code without its trailing comment*. It still
refuses an edit that matches more than one place. The test is
`test_model_edit_matches_a_line_copied_without_its_trailing_comment`.

The wrong answers were stopped at the right places:
- `eval` by patch hygiene, before the gate ran at all;
- the other seven (four too-loose C bounds, the `;` blocklist, two shell-quoting attempts) passed
  hygiene and were rejected by the five-check gate itself.

So the pipeline accepts a correct model fix end to end and rejects wrong ones. What remains is
model quality.

**The real 7B model, on its own.** The same setup (templates off, everything from the model), with
Qwen2.5-Coder-7B on 4 CPU threads and the matching fix in place:

| | Found | Fixed through the gate | Model calls | Tokens | Time |
|---|---|---|---|---|---|
| Qwen2.5-Coder-7B, model only | 8/8 | **3/8** (two C variants, one Python) | 25 | 5,614 | 1,609 s |

It fixed the C `reorder` and `reflow` variants and the Python `reflow` variant. It failed the C
`rename` and `memmove` variants, the Python `rename` variant, and both `os.system` / `os.popen`
variants. In the one failure inspected in detail (`os.system`), its replies restated the vulnerable
line and proposed a test instead of a change. Every fix it made was proven by the same gate.

Conclusion: the pipeline is not the bottleneck. A small CPU model fixes some bugs on its own, the
templates fix all eight, and a stronger model (the finale GPU model, or an Ollama cloud model on
demo code) should be measured with `scripts/model_benchmark.py`.
