# What is not built, and how your team can build it

Six items in the plans are not built in this repository. For each one, this page says what it is
for, what already exists that it plugs into, what it must take in and give out, and how you know
it is done. The specifications are in `PLAN_V2.md`. Build the items yourselves, or hand one section
of this page plus the named source files to any coding assistant.

The rule is the same for every item: **the five-check gate decides; nothing new may report a
finding without a reproducer, call a target "secure", send code off the machine, or skip a test.**

| Item | What it adds | Plugs into | Effort | Needed for the finale? |
|---|---|---|---|---|
| J3 real-ARVO numbers | fix rate on real, published bugs | `raksha/benchmark_arvo.py` (runner exists) | 1–2 days, networked machine | useful, not required |
| Plain-model baseline arm | the "model alone" column in the baseline table | `raksha/baseline.py` | — | **no — leave as "not run"** |
| K21 why-is-this-risky text | plain-language explanation per finding | `raksha/reports.py` rows, `raksha/views.py` | ½ day | nice to have |
| K24 ask-about-my-project | answers only from signed reports, cited | `raksha/views.py::kb_search`, `reports.history` | 1 day | nice to have |
| K30 drill mode | checks the team's process, not the code | project store, `raksha/intake.py` | ½ day | optional |
| Toolchain Docker image | deep lanes inside the sealed container | `deploy/Dockerfile` | 1 day | only for the sealed node |

---

## J3 — real ARVO numbers

**What exists.** `raksha/benchmark_arvo.py` already reads a manifest and runs every case through
the same find → confirm → repair → gate path. `python -m raksha.benchmark` picks it up when
`RAKSHA_ARVO_MANIFEST=/path/to/manifest.json` is set. Without a manifest it truthfully reports
"0 ARVO cases".

**What is missing.** Only the data: real cases, assembled once on a machine with internet.

**How to build it (no new code):**
1. From the public ARVO dataset, pick 20–50 **C/C++ or Python** cases. Those are the languages the
   autofuzz path handles.
2. For each case, put the vulnerable source in `cases/<id>/src` and the known crashing input from
   the dataset in `cases/<id>/crash`.
3. Write `manifest.json` following the schema in the docstring at the top of
   `raksha/benchmark_arvo.py`: `name`, `language`, `source_path`, and optionally `bug_class`,
   `reproducer_path`, `seed_corpus` and `max_execs`.
4. Run `RAKSHA_ARVO_MANIFEST=cases/manifest.json python -m raksha.benchmark`.
5. Publish the table it writes in `docs/benchmark-report.md` **with the losses**. Never quote a
   number the run did not produce.

**Done when** the report lists every case with fixed / not fixed and the reason, and
`docs/claim-audit.md` J3 is updated from "reworded" to the measured number.

## Plain-model baseline arm — recommendation: do not build

The baseline table already compares a static scanner with RAKSHA on the measure that matters,
"reports carrying a reproducer that replays". The model-alone arm is recorded as **not run**, with
the reason. That is honest, and judges accept it. Leave it.

## K21 — why-is-this-risky, in plain language

**Purpose.** For each finding, give an owner three short sentences: *where it is*, *what it
exposes*, *what the proven fix changes*. In English and Hindi. Built **only from fields already in
the signed report**. It does not need a model; fixed sentence templates per bug family are enough
and are safer.

**Inputs.** One report row from `raksha/reports.py::_row`. Fields: `family`, `bug_class`,
`severity`, `file`, `line`, `symbol`, `state`, `lane`, `evidence`, `patch_diff`, `needs_human`.
Optionally the finding's attack-graph chain: `capability` and `service` from
`raksha/attackgraph.py`, which the console already shows.

**Output.** Add a function `explain(row: dict, lang: str = "en") -> dict` in `raksha/views.py`:
```json
{"where": "src/tlv.c line 15, function parse_record",
 "exposes": "memory safety: a long record overruns a 32-byte buffer (CWE-121)",
 "fix": "the copy is now bounded to the buffer; proven by the five-check gate",
 "source_fields": ["file", "line", "symbol", "bug_class", "state"]}
```
`source_fields` lists the row fields each sentence came from. Any field that is missing reads
"not in the record". The function never guesses.

**Done when:**
- a test checks that every sentence is traceable to `source_fields`;
- a finding with no fix says "no proven fix yet";
- the Hindi output comes from the same template table;
- the console's Projects screen shows it under each finding.

## K24 — ask about my project (offline)

**Purpose.** An owner types a question ("which secrets are still open?", "what changed since
v2?"). The answer comes **only** from that project's signed reports, with the report version cited.
If the answer is not in the reports, it says "not in the record".

**Inputs.** `projects.Store`, `reports.history(store, pid)`, `reports.diff(...)` and
`views.kb_search(...)`. These already return every row of every version.

**Output.** Add `ask(store, pid, question: str) -> dict` in `raksha/views.py`:
```json
{"answer": "2 secrets are open: config/app.properties lines 2 and 3.",
 "cites": [{"version": 3, "keys": ["<finding key>", "<finding key>"]}],
 "matched": "open secrets"}
```
Build it as keyword intents over the report rows: *open*, *fixed*, *secrets*, *critical*,
*changed since vN*, *by family*, *by file*. Anything outside those intents returns "not in the
record". An optional model may only **rephrase** an answer the intents already produced. It never
adds facts.

**Done when:**
- every answer cites a version and finding keys that exist;
- a question about something absent returns "not in the record";
- the reports' signature chain is verified (`reports.verify_chain`) before answering.

## K30 — drill mode (checks the process, not the code)

**Purpose.** A training exercise. Give the team a **copy** of a project containing a weakness that
is already known, and check that review, CI and response catch it.

**Build it without writing anything risky.** The repository already ships known-weakness targets
in `demo-targets/`. A drill is:
1. Copy one of them into a scratch area.
2. Submit it through the existing intake (`raksha/intake.py`, the console's "Bring your own target").
3. Record who noticed it and when.
4. Delete the copy.

The only new code is a small record in the project store: `drill_id`, `started`, `detected_by`,
`detected_at`, `closed`. Plus a console button. Never modify a real project; drills use copies only.

**Done when** a drill's record shows time-to-detect, and no file outside the scratch copy changed.

## Toolchain image for the sealed node

**What exists.** `deploy/Dockerfile` builds the sandbox. `deploy/install.sh` and the two compose
files run the sealed stack. On a laptop the deep lanes run directly under WSL, and the console
truthfully shows `NET IF: unenforced`.

**What is missing.** One image that holds gcc, the JDK with a warmed Maven cache, Go, cargo and
Node, so every deep lane runs inside the network-less sandbox.

**How.** Start from the package list in `deploy/laptop-bootstrap.sh`, section 1. Install the same
packages in the Dockerfile and run `deploy/warm-maven.sh` at build time. Set
`RAKSHA_SANDBOX_IMAGE` to the new tag.

**Done when:**
- `RAKSHA_REQUIRE_SANDBOX=1 python -m raksha.slice_three` passes;
- the console shows `NET IF: 0`.

---

## Handing a section to a coding assistant

Give it:
1. this page's section;
2. the source files named under "Plugs into" or "Inputs";
3. `tests/test_wave5.py` as the style example.

Then ask for one function plus its tests. Run `python -m pytest -q` before committing. If the
assistant suggests calling a target "secure", reporting without a reproducer, or adding a network
call, reject that part.
