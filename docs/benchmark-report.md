# RAKSHA AI — Benchmark Report

## Methodology

Every number below is measured by running the actual pipeline over the target set named in the Results table and reading the finding records — none is borrowed from a published general-coding score. The pipeline is identical to the one demonstrated: ingest → oracle → confirm (reproducer replays) → repair ladder → five-check gate → signed bundle.

**Scope, stated plainly.** This bundled set is small and curated (our demo targets across C, Java, Python and the build-free lanes). The aggregates are a *reproducible baseline*, not a statistical security fix-rate — a fix-rate claim requires the full ARVO / AutoPatchBench run, which plugs into this same harness as additional cases on a networked prep machine. We quote the set size with every number.

## Results

**Timing columns.** *End-to-end* is wall-clock for the whole case: build, hunt, repair and the five-check gate (deep cases), or the whole estate scan (build-free). *Confirm* and *patch* are measured from the finding record's creation; in these deep cases the reproducer is seeded rather than discovered by a fuzzing campaign, so *confirm* is record latency, not time-to-discovery — the end-to-end column is the honest speed number.

| Target | Lang | Bug | Status | Fixed | Evidence | Lane | end-to-end (s) | confirm (s) | patch (s) |
|--------|------|-----|--------|-------|----------|------|----------------|-------------|-----------|
| c-overflow | c/c++ | CWE-121 | VERIFIED | yes | exploit-replay | TEMPLATE | 1.32 | 0.0012 | 1.0656 |
| py-cmdinject | python | CWE-78 | VERIFIED | yes | exploit-replay | TEMPLATE | 2.55 | 0.001184 | 2.48584 |
| java-log4shell | java | CWE-917 | VERIFIED | yes | exploit-replay | TEMPLATE | 66.66 | 0.008956 | 59.372312 |
| autofuzz:c-nolibfuzzer | c/c++ | CWE-121 | VERIFIED | yes | exploit-replay | TEMPLATE | 1.83 | 3.9e-05 | 0.795638 |
| autofuzz:py-noharness | python | CWE-78 | VERIFIED | yes | exploit-replay | TEMPLATE | 2.08 | 3.4e-05 | 1.803571 |
| estate:generic-password-assign@config/app.properties:2 | any | CWE-798 | CONFIRMED | — | deterministic-match | — | 0.011 | 7e-05 | — |
| estate:aws-secret-access-key@config/app.properties:3 | any | CWE-798 | CONFIRMED | — | deterministic-match | — | 0.011 | 2e-05 | — |
| estate:weak-hash-security-context@crypto-svc/signer.py:19 | python | CWE-328 | CONFIRMED | — | deterministic-match | — | 0.011 | 3.1e-05 | — |
| estate:static-iv@crypto-svc/signer.py:24 | python | CWE-329 | CONFIRMED | — | deterministic-match | — | 0.011 | 2e-05 | — |
| estate:weak-rsa-keysize@crypto-svc/signer.py:30 | python | CWE-326 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.3e-05 | — |
| estate:legacy-tls-protocol@crypto-svc/signer.py:34 | python | CWE-757 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.1e-05 | — |
| estate:no-cert-verification@crypto-svc/signer.py:35 | python | CWE-295 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.9e-05 | — |
| estate:no-cert-verification@crypto-svc/signer.py:36 | python | CWE-295 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.1e-05 | — |
| estate:missing-authz@gateway-go/openapi.json:DELETE /users/{id} | api | CWE-862 | CONFIRMED | — | deterministic-match | — | 0.011 | 4.1e-05 | — |
| estate:missing-authz@gateway-go/openapi.json:POST /admin/flush | api | CWE-862 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.1e-05 | — |
| estate:debug-endpoint@gateway-go/openapi.json:POST /admin/flush | api | CWE-489 | CONFIRMED | — | deterministic-match | — | 0.011 | 9e-06 | — |
| estate:version-match@audit-java/pom.xml:9 | java | CWE-917 | CONFIRMED | — | deterministic-match | — | 0.011 | 5.5e-05 | — |
| estate:version-match@audit-java/pom.xml:9 | java | CWE-917 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.6e-05 | — |
| estate:version-match@audit-java/pom.xml:9 | java | CWE-74 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.4e-05 | — |
| estate:version-match@gateway-go/go.mod:6 | go | CWE-444 | CONFIRMED | — | deterministic-match | — | 0.011 | 2.3e-05 | — |
| estate:version-match@service-js/package-lock.json:lodash | javascript | CWE-94 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.2e-05 | — |
| estate:version-match@service-js/package-lock.json:minimist | javascript | CWE-1321 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.3e-05 | — |
| estate:version-match@tool-py/requirements.txt:2 | python | CWE-20 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.2e-05 | — |
| estate:version-match@tool-py/requirements.txt:3 | python | CWE-200 | CONFIRMED | — | deterministic-match | — | 0.011 | 1.3e-05 | — |

## Aggregates (on this set)

- Targets run: **24** of 24 (0 errors)
- Proven findings reported: **24**
- Verified fixes: **5**  ·  report-only: **0**
- Fix rate on this set: **20.8%** (of reported findings; small-set baseline, not a security fix-rate)
- Zero-inference fixes: **100.0%**
- Languages covered: **5** (c/c++, go, java, javascript, python)
- Evidence: 5 exploit-proven, 19 match-proven
- Deep cases, median end-to-end (build → hunt → fix → five-check gate): **2.08s**
- Build-free estate scan, all 19 match-proven findings: **0.011s**

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


---

_Generated by `python -m raksha.benchmark` at commit 4b04894 on 2026-10-04 12:25 UTC. Re-run it to reproduce every number._
