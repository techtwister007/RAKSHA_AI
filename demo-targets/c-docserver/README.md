# c-docserver — a defect no sanitizer sees (B12 behavioural baseline)

`doc:<name>` serves `data/<name>` with no `..` check. A traversal request reads a file outside the
document root, but nothing crashes, so ASan/UBSan stay silent. RAKSHA's behavioural lane runs the
binary under `raksha/harness/raksha_observe.c` on benign requests, learns that it only ever opens
files under `data/`, and flags the input that opens something new (CWE-22). See
`tests/test_behaviour.py`.
