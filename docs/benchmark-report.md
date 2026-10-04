# RAKSHA AI — Benchmark Report

## Methodology

Every number below is measured by running the actual pipeline over the target set named in the Results table and reading the finding records — none is borrowed from a published general-coding score. The pipeline is identical to the one demonstrated: ingest → oracle → confirm (reproducer replays) → repair ladder → five-check gate → signed bundle.

**Scope, stated plainly.** This bundled set is small and curated (our demo targets across C, Java, Python and the build-free lanes). The aggregates are a *reproducible baseline*, not a statistical security fix-rate — a fix-rate claim requires the full ARVO / AutoPatchBench run, which plugs into this same harness as additional cases on a networked prep machine. We quote the set size with every number.

## Results

**Timing columns.** *End-to-end* is wall-clock for the whole case: build, hunt, repair and the five-check gate (deep cases), or the whole estate scan (build-free). *Confirm* and *patch* are measured from the finding record's creation; in these deep cases the reproducer is seeded rather than discovered by a fuzzing campaign, so *confirm* is record latency, not time-to-discovery — the end-to-end column is the honest speed number.

| Target | Lang | Bug | Status | Fixed | Evidence | Lane | end-to-end (s) | confirm (s) | patch (s) |
|--------|------|-----|--------|-------|----------|------|----------------|-------------|-----------|
| c-overflow | c/c++ | CWE-121 | VERIFIED | yes | exploit-replay | TEMPLATE | 1.15 | 0.00108 | 0.942845 |
| py-cmdinject | python | CWE-78 | VERIFIED | yes | exploit-replay | TEMPLATE | 2.16 | 0.001023 | 2.10093 |
| java-log4shell | java | CWE-917 | VERIFIED | yes | exploit-replay | TEMPLATE | 64.83 | 0.006065 | 58.210545 |
| autofuzz:c-nolibfuzzer | c/c++ | CWE-121 | VERIFIED | yes | exploit-replay | TEMPLATE | 2.05 | 3.6e-05 | 0.898843 |
| autofuzz:py-noharness | python | CWE-78 | VERIFIED | yes | exploit-replay | TEMPLATE | 2.01 | 4e-05 | 1.721959 |
| estate:generic-password-assign@config/app.properties:2 | any | CWE-798 | CONFIRMED | — | deterministic-match | — | 0.009 | 6.1e-05 | — |
| estate:aws-secret-access-key@config/app.properties:3 | any | CWE-798 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.4e-05 | — |
| estate:weak-hash-security-context@crypto-svc/signer.py:19 | python | CWE-328 | CONFIRMED | — | deterministic-match | — | 0.009 | 2.7e-05 | — |
| estate:static-iv@crypto-svc/signer.py:24 | python | CWE-329 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.3e-05 | — |
| estate:weak-rsa-keysize@crypto-svc/signer.py:30 | python | CWE-326 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.2e-05 | — |
| estate:legacy-tls-protocol@crypto-svc/signer.py:34 | python | CWE-757 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.3e-05 | — |
| estate:no-cert-verification@crypto-svc/signer.py:35 | python | CWE-295 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.2e-05 | — |
| estate:no-cert-verification@crypto-svc/signer.py:36 | python | CWE-295 | CONFIRMED | — | deterministic-match | — | 0.009 | 1e-05 | — |
| estate:missing-authz@gateway-go/openapi.json:DELETE /users/{id} | api | CWE-862 | CONFIRMED | — | deterministic-match | — | 0.009 | 3.1e-05 | — |
| estate:missing-authz@gateway-go/openapi.json:POST /admin/flush | api | CWE-862 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.1e-05 | — |
| estate:debug-endpoint@gateway-go/openapi.json:POST /admin/flush | api | CWE-489 | CONFIRMED | — | deterministic-match | — | 0.009 | 9e-06 | — |
| estate:version-match@audit-java/pom.xml:9 | java | CWE-917 | CONFIRMED | — | deterministic-match | — | 0.009 | 3.6e-05 | — |
| estate:version-match@audit-java/pom.xml:9 | java | CWE-917 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.6e-05 | — |
| estate:version-match@audit-java/pom.xml:9 | java | CWE-74 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.5e-05 | — |
| estate:version-match@gateway-go/go.mod:6 | go | CWE-444 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.2e-05 | — |
| estate:version-match@service-js/package-lock.json:lodash | javascript | CWE-94 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.2e-05 | — |
| estate:version-match@service-js/package-lock.json:minimist | javascript | CWE-1321 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.3e-05 | — |
| estate:version-match@tool-py/requirements.txt:2 | python | CWE-20 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.3e-05 | — |
| estate:version-match@tool-py/requirements.txt:3 | python | CWE-200 | CONFIRMED | — | deterministic-match | — | 0.009 | 1.4e-05 | — |

## Aggregates (on this set)

- Targets run: **24** of 24 (0 errors)
- Proven findings reported: **24**
- Verified fixes: **5**  ·  report-only: **0**
- Fix rate on this set: **20.8%** (of reported findings; small-set baseline, not a security fix-rate)
- Zero-inference fixes: **100.0%**
- Languages covered: **5** (c/c++, go, java, javascript, python)
- Evidence: 5 exploit-proven, 19 match-proven
- Deep cases, median end-to-end (build → hunt → fix → five-check gate): **2.05s**
- Build-free estate scan, all 19 match-proven findings: **0.009s**

## Losses, shown beside the wins

- **estate:generic-password-assign@config/app.properties:2** (any): proven by re-match; the fix is rotating the credential — an operator action, not a code patch
- **estate:aws-secret-access-key@config/app.properties:3** (any): proven by re-match; the fix is rotating the credential — an operator action, not a code patch
- **estate:weak-hash-security-context@crypto-svc/signer.py:19** (python): status CONFIRMED
- **estate:static-iv@crypto-svc/signer.py:24** (python): status CONFIRMED
- **estate:weak-rsa-keysize@crypto-svc/signer.py:30** (python): status CONFIRMED
- **estate:legacy-tls-protocol@crypto-svc/signer.py:34** (python): status CONFIRMED
- **estate:no-cert-verification@crypto-svc/signer.py:35** (python): status CONFIRMED
- **estate:no-cert-verification@crypto-svc/signer.py:36** (python): status CONFIRMED
- **estate:missing-authz@gateway-go/openapi.json:DELETE /users/{id}** (api): proven from the API spec; the fix is an authorization policy change, reviewed by a human
- **estate:missing-authz@gateway-go/openapi.json:POST /admin/flush** (api): proven from the API spec; the fix is an authorization policy change, reviewed by a human
- **estate:debug-endpoint@gateway-go/openapi.json:POST /admin/flush** (api): proven from the API spec; the fix is an authorization policy change, reviewed by a human
- **estate:version-match@audit-java/pom.xml:9** (java): proven by version match; zero-inference patch prepared (bump org.apache.logging.log4j:log4j-core to 2.15.0) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@audit-java/pom.xml:9** (java): proven by version match; zero-inference patch prepared (bump org.apache.logging.log4j:log4j-core to 2.16.0) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@audit-java/pom.xml:9** (java): proven by version match; zero-inference patch prepared (bump org.apache.logging.log4j:log4j-core to 2.17.1) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@gateway-go/go.mod:6** (go): proven by version match; zero-inference patch prepared (bump github.com/gin-gonic/gin to 1.7.7) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@service-js/package-lock.json:lodash** (javascript): proven by version match; zero-inference patch prepared (bump lodash to 4.17.21) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@service-js/package-lock.json:minimist** (javascript): proven by version match; zero-inference patch prepared (bump minimist to 1.2.6) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@tool-py/requirements.txt:2** (python): proven by version match; zero-inference patch prepared (bump pyyaml to 5.4) but not gate-verified — the gate needs a build, and this case ran build-free
- **estate:version-match@tool-py/requirements.txt:3** (python): proven by version match; zero-inference patch prepared (bump requests to 2.31.0) but not gate-verified — the gate needs a build, and this case ran build-free

## Precision

100% of reported findings carry a replaying reproducer, by construction — the data model forbids reporting one that does not. That is a structural property; it says every report is *evidenced*, not that no evidence is ever wrong. So false positives are measured separately, against negative controls: a clean estate built from the same shapes as the vulnerable one — fixed dependency versions on every patched release line, secrets read from the environment, references in config, AWS documentation keys, ranges in manifests, an authenticated API.

- Negative controls scanned: **11** clean artifacts
- False positives on them: **0**

## Baseline comparison (J4)

The same demo targets through a static scanner alone and through RAKSHA, on the one measure that
matters — **reports carrying a reproducer that replays** (`python -m raksha.baseline --report`):

| arm | reports | with reproducer | defect files hit | FPs on clean | time (s) |
|-----|---------|-----------------|------------------|--------------|----------|
| static scanner (flawfinder / bandit, defaults) | 8 | 0 | 5 | 0 | ~1 |
| RAKSHA (synthesized-harness lane, model-free) | 7 | 7 | 7 | 0 | ~5 |
| plain model alone | — | — | — | — | not run |

A static scanner emits no input, so by construction none of its reports carry a reproducer — that is
the structural difference, not a dig. The plain-model arm is recorded as not-run: RAKSHA's model use
(ranking, the repair ladder) is measured instead by the zero-inference share on the Scorecard and by
the mutation factory below. Small curated set — a reproducible comparison, not a statistical claim.

## Recall (J5)

Recall where the denominator is knowable (`python -m raksha.recall --report`). On an open corpus
recall is undefined — there is no catalogue of all real bugs to divide by — which is why a
population recall is still declined. Two sets have an exact denominator:

- **Mutation factory:** **100%** (8/8). Every bug-preserving variant is a real instance of a known
  defect, so the denominator is exact; recall is the find half, the fix rate (75% of variants) the
  repair half.
- **Demo ground truth, fuzzable families:** **54.5%** (6/11), misses named
  (c-binsink, js-noharness, go-decoder, rust-nolibfuzzer, java-noharness — the deep-lane toolchains
  absent on this box, or no fuzzable entry point). Families a runtime oracle cannot reach
  (weak-crypto config, unpinned dependencies, path traversal, ReDoS) are build-free-lane territory
  and are listed out of scope, not counted as misses.


---

_Generated by `python -m raksha.benchmark` at commit 376fc75 on 2026-10-04 13:10 UTC. Re-run it to reproduce every number. ARVO: no ARVO manifest at .: offline mode, 0 ARVO cases. The full ARVO / AutoPatchBench baseline is assembled on a networked prep machine, which writes this manifest; this box ships without it by design.._
