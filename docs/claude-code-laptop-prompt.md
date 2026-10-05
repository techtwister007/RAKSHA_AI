# Prompts for a Claude Code session on the laptop

Open `RAKSHA Shell.bat`, run `claude` inside `/root/RAKSHA_AI` (or open that folder in Claude
Code), and paste one of these.

## First session: check the install

```
Read HANDOFF.md and CLAUDE.md. Then run, in order, and report each result in one line:
1. git pull origin claude/magical-mayer-gs2xno
2. RAKSHA_PROVIDER=off python -m raksha.airgap
3. RAKSHA_PROVIDER=off python scripts/model_lane_check.py
4. RAKSHA_PROVIDER=off python -m raksha.slice_autofuzz
5. python -m pytest -q
6. python -m raksha.provider show
If anything fails, find the cause and fix it with a test, run the touched tests, commit and push
to claude/magical-mayer-gs2xno. Do not skip or weaken tests.
```

## Switch the model provider and measure it

```
Set RAKSHA's model provider to <PROVIDER> with model <MODEL> using
`python -m raksha.provider set <PROVIDER> --model <MODEL>` (add --url / --key if needed; never
commit a key). Run `python -m raksha.provider test`, then `python scripts/model_benchmark.py
--out docs/model-benchmark-<PROVIDER>.md` and summarise: fixed model-free vs with the model,
model calls, tokens, wall time, cloud calls. If the provider is hosted, say so in the summary.
Commit only the results file.
```

Examples for `<PROVIDER> <MODEL>`:
- `ollama qwen2.5-coder:7b`
- `ollama gpt-oss:120b-cloud`
- `lmstudio qwen2.5-coder-7b-instruct`
- `vllm Qwen/Qwen2.5-Coder-32B-Instruct`
- `openai gpt-4.1`
- `deepseek deepseek-chat`
- `custom` with `--url http://HOST:PORT/v1`

## Continue the remaining work

```
Read HANDOFF.md §6 and docs/missing-pieces.md. Take the next item, build it with tests in the
style of tests/test_wave5.py, run the touched tests and the full suite, update the docs that
mention it (HANDOFF.md, docs/claim-audit.md), commit and push to claude/magical-mayer-gs2xno.
Keep the rules in CLAUDE.md.
```
