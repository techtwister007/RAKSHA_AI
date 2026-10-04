# c-nolibfuzzer — a target that ships no fuzz harness

A single parser function, `parse_record(const uint8_t*, size_t)`, with a classic length-field
overflow. There is deliberately **no** harness, no `main`, no build system — RAKSHA's autofuzz
engine discovers the entry point, synthesizes a harness, finds the crash, and drives it through the
same find→fix→prove gate as every other target.
