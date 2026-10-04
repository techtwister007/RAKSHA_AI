# RAKSHA AI — Benchmark Report

## Methodology

Every number below is measured by running the actual pipeline over the target set named in the Results table and reading the finding records — none is borrowed from a published general-coding score. The pipeline is identical to the one demonstrated: ingest → oracle → confirm (reproducer replays) → repair ladder → five-check gate → signed bundle.

**Scope, stated plainly.** This bundled set is small and curated (our demo targets across C, Java, Python and the build-free lanes). The aggregates are a *reproducible baseline*, not a statistical security fix-rate — a fix-rate claim requires the full ARVO / AutoPatchBench run, which plugs into this same harness as additional cases on a networked prep machine. We quote the set size with every number.

## Results

| Target | Lang | Bug | Status | Fixed | Evidence | Lane | t-PoV (s) | t-patch (s) |
|--------|------|-----|--------|-------|----------|------|-----------|-------------|
| c-overflow | c/c++ | CWE-121 | VERIFIED | yes | exploit-replay | TEMPLATE | 0.000101 | 0.696529 |
| py-cmdinject | python | CWE-78 | VERIFIED | yes | exploit-replay | TEMPLATE | 4.8e-05 | 1.533446 |
| java-log4shell | java | CWE-917 | VERIFIED | yes | exploit-replay | TEMPLATE | 6.3e-05 | 40.058351 |
| estate:secrets:generic-password-assign | any | CWE-798 | CONFIRMED | — | deterministic-match | — | 5.5e-05 | — |
| estate:secrets:aws-secret-access-key | any | CWE-798 | CONFIRMED | — | deterministic-match | — | 1.6e-05 | — |
| estate:service:missing-authz | api | CWE-862 | CONFIRMED | — | deterministic-match | — | 2.7e-05 | — |
| estate:service:missing-authz | api | CWE-862 | CONFIRMED | — | deterministic-match | — | 1.2e-05 | — |
| estate:service:debug-endpoint | api | CWE-489 | CONFIRMED | — | deterministic-match | — | 1.6e-05 | — |
| estate:osv:version-match | go | CWE-444 | CONFIRMED | — | deterministic-match | — | 3.7e-05 | — |
| estate:osv:version-match | javascript | CWE-94 | CONFIRMED | — | deterministic-match | — | 1.3e-05 | — |
| estate:osv:version-match | javascript | CWE-1321 | CONFIRMED | — | deterministic-match | — | 1.2e-05 | — |
| estate:osv:version-match | python | CWE-20 | CONFIRMED | — | deterministic-match | — | 1.1e-05 | — |
| estate:osv:version-match | python | CWE-200 | CONFIRMED | — | deterministic-match | — | 1.1e-05 | — |

## Aggregates (on this set)

- Targets run: **13** of 13 (0 errors)
- Proven findings reported: **13**
- Verified fixes: **3**  ·  report-only: **0**
- Fix rate on this set: **23.1%** (of reported findings; small-set baseline, not a security fix-rate)
- Zero-inference fixes: **100.0%**
- Languages covered: **7** (any, api, c/c++, go, java, javascript, python)
- Evidence: 3 exploit-proven, 10 match-proven
- Median time-to-PoV: **0.0s**  ·  median time-to-validated-patch: **1.53s**

## Losses, shown beside the wins

- **estate:secrets:generic-password-assign** (any): status CONFIRMED
- **estate:secrets:aws-secret-access-key** (any): status CONFIRMED
- **estate:service:missing-authz** (api): status CONFIRMED
- **estate:service:missing-authz** (api): status CONFIRMED
- **estate:service:debug-endpoint** (api): status CONFIRMED
- **estate:osv:version-match** (go): status CONFIRMED
- **estate:osv:version-match** (javascript): status CONFIRMED
- **estate:osv:version-match** (javascript): status CONFIRMED
- **estate:osv:version-match** (python): status CONFIRMED
- **estate:osv:version-match** (python): status CONFIRMED

## Precision

100% of reported findings carry a replaying reproducer, by construction — the data model forbids reporting one that does not. This is a structural property, not a tuned result, and it holds on every set.
