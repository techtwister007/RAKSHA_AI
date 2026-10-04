"""Bug-class to CWE mapping.

Each oracle speaks its own vocabulary: ASan says "heap-buffer-overflow", Jazzer says
"Remote JNDI Lookup", PySecSan says "command injection". The unified finding record
speaks CWE. This module is the only place the translation lives.
"""

from __future__ import annotations

# ASan / UBSan / MSan abort kinds -> CWE
SANITIZER_CWE: dict[str, str] = {
    "heap-buffer-overflow": "CWE-122",
    "stack-buffer-overflow": "CWE-121",
    "global-buffer-overflow": "CWE-787",
    "heap-use-after-free": "CWE-416",
    "use-after-poison": "CWE-416",
    "double-free": "CWE-415",
    "attempting-free-on-address-which-was-not-malloc": "CWE-590",
    "alloc-dealloc-mismatch": "CWE-762",
    "memory-leaks": "CWE-401",
    "stack-overflow": "CWE-674",
    "negative-size-param": "CWE-1284",
    "dynamic-stack-buffer-overflow": "CWE-121",
    "bad-free": "CWE-590",
    "stack-use-after-return": "CWE-562",
    "stack-use-after-scope": "CWE-416",
    "stack-buffer-underflow": "CWE-124",
    "container-overflow": "CWE-119",
    "allocation-size-too-big": "CWE-789",
    "calloc-overflow": "CWE-190",
    "memcpy-param-overlap": "CWE-475",
    "unknown-crash": "CWE-noinfo",
    "SEGV": "CWE-476",
    "wild-write": "CWE-787",
    "wild-read": "CWE-125",
    "out-of-bounds-read": "CWE-125",
    "FPE": "CWE-369",
    # libFuzzer's own aborts (no sanitizer report)
    "libfuzzer-timeout": "CWE-400",
    "libfuzzer-out-of-memory": "CWE-789",
    "libfuzzer-deadly-signal": "CWE-noinfo",
    # UBSan
    "signed-integer-overflow": "CWE-190",
    "shift-exponent": "CWE-1335",
    "division-by-zero": "CWE-369",
    "null-pointer-dereference": "CWE-476",
    "unsigned-integer-overflow": "CWE-190",
    "index-out-of-bounds": "CWE-129",
    "misaligned-pointer": "CWE-704",
    "float-cast-overflow": "CWE-681",
    # MSan
    "use-of-uninitialized-value": "CWE-457",
}

# Jazzer sanitizer titles -> CWE. Titles are matched case-insensitively by substring,
# longest first, so "Remote JNDI Lookup" wins over a bare "Injection".
JAZZER_CWE: dict[str, str] = {
    "remote jndi lookup": "CWE-917",
    "expression language injection": "CWE-917",
    "ldap injection": "CWE-90",
    "os command injection": "CWE-78",
    "command injection": "CWE-78",
    "sql injection": "CWE-89",
    "script engine injection": "CWE-94",
    "xpath injection": "CWE-643",
    "regular expression injection": "CWE-1333",
    "server side request forgery": "CWE-918",
    "unsafe deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "file path traversal": "CWE-22",
    "path traversal": "CWE-22",
    "file read write hook": "CWE-22",
    "reflective call": "CWE-470",
    "unsafe reflective call": "CWE-470",
    "integer overflow": "CWE-190",
    "out of memory": "CWE-789",
    "stack overflow": "CWE-674",
    "unrestricted class loading": "CWE-470",
    "arbitrary class loading": "CWE-470",
    "native library loading": "CWE-114",
    "timeout": "CWE-400",       # a hang / resource exhaustion — not ReDoS unless the title says so
}

#: Jazzer's umbrella titles. Consulted only when no specific title above matched, so a "Remote Code
#: Execution" whose detail line says "Deserialization of arbitrary classes" is CWE-502, not generic.
JAZZER_GENERIC_CWE: dict[str, str] = {
    "remote code execution": "CWE-94",
}

# PySecSan detector names -> CWE.
PYSECSAN_CWE: dict[str, str] = {
    "command injection": "CWE-78",
    "shell injection": "CWE-78",
    "subprocess shell": "CWE-78",
    "code injection": "CWE-94",
    "eval injection": "CWE-95",
    "exec injection": "CWE-95",
    "sql injection": "CWE-89",
    "path traversal": "CWE-22",
    "pickle deserialization": "CWE-502",
    "yaml deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "ssrf": "CWE-918",
    "server side request forgery": "CWE-918",
    "xxe": "CWE-611",
}


def _longest_substring_match(text: str, table: dict[str, str]) -> str | None:
    lowered = text.lower()
    for key in sorted(table, key=len, reverse=True):
        if key in lowered:
            return table[key]
    return None


def cwe_for_sanitizer(kind: str) -> str:
    """CWE for an ASan/UBSan/MSan abort kind."""
    return SANITIZER_CWE.get(kind, _longest_substring_match(kind, SANITIZER_CWE) or "CWE-noinfo")


def cwe_for_jazzer(title: str) -> str:
    """CWE for a Jazzer sanitizer title (specific titles first, then umbrella ones)."""
    return (_longest_substring_match(title, JAZZER_CWE)
            or _longest_substring_match(title, JAZZER_GENERIC_CWE) or "CWE-noinfo")


def cwe_for_pysecsan(detector: str) -> str:
    """CWE for a PySecSan detector name."""
    return _longest_substring_match(detector, PYSECSAN_CWE) or "CWE-noinfo"
