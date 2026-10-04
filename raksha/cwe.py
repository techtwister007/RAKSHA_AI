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


# ---- CWE families (W0-3) -----------------------------------------------------------------------
# Many oracles name sibling CWEs for what is, for our purposes, the same class of defect: ASan says
# CWE-121/122 where the structural lane said CWE-120; UBSan says CWE-190 where Go said CWE-190 but
# C said CWE-787. Cross-confirmation, dedup, the mutation factory and the attack graph all need
# "same family", not "same code". This table is the one place that grouping lives. It never widens
# a finding's reported CWE — it only answers whether two codes belong together.

_FAMILY: dict[str, str] = {}


def _fam(name: str, *cwes: str) -> None:
    for c in cwes:
        _FAMILY[c] = name


_fam("memory",            # spatial + temporal memory safety
     "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
     "CWE-787", "CWE-788", "CWE-786", "CWE-170", "CWE-193", "CWE-system")
_fam("use-after-free", "CWE-416", "CWE-415", "CWE-590", "CWE-562", "CWE-825", "CWE-672")
_fam("alloc", "CWE-789", "CWE-762", "CWE-475", "CWE-401", "CWE-404", "CWE-459")
_fam("numeric", "CWE-190", "CWE-191", "CWE-128", "CWE-369", "CWE-681", "CWE-1335", "CWE-1284")
_fam("uninitialised", "CWE-457", "CWE-824", "CWE-908")
_fam("pointer", "CWE-476", "CWE-704", "CWE-763", "CWE-822")
_fam("index", "CWE-129", "CWE-1285")
_fam("injection",         # the command/code/query injection cluster
     "CWE-77", "CWE-78", "CWE-88", "CWE-94", "CWE-95", "CWE-89", "CWE-90", "CWE-564",
     "CWE-643", "CWE-917", "CWE-74", "CWE-75", "CWE-93")
_fam("deserialization", "CWE-502")
_fam("ssrf", "CWE-918")
_fam("path-traversal", "CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-98")
_fam("xss", "CWE-79", "CWE-80", "CWE-83")
_fam("crypto", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335",
     "CWE-338", "CWE-347", "CWE-757", "CWE-759", "CWE-760", "CWE-916")
_fam("cert", "CWE-295", "CWE-296", "CWE-297", "CWE-298", "CWE-299")
_fam("authz", "CWE-862", "CWE-863", "CWE-285", "CWE-284", "CWE-639", "CWE-732")
_fam("authn", "CWE-287", "CWE-306", "CWE-307", "CWE-521", "CWE-798", "CWE-259", "CWE-522")
_fam("dos", "CWE-400", "CWE-405", "CWE-674", "CWE-834", "CWE-1333", "CWE-770")
_fam("info-leak", "CWE-200", "CWE-209", "CWE-532", "CWE-215", "CWE-538", "CWE-1104")
_fam("race", "CWE-362", "CWE-364", "CWE-366", "CWE-367", "CWE-421")
_fam("config", "CWE-16", "CWE-489", "CWE-520", "CWE-1188")
_fam("deps", "CWE-937", "CWE-1035", "CWE-1395")
_fam("api-design", "CWE-20", "CWE-116", "CWE-444", "CWE-611")


def family(cwe: str | None) -> str | None:
    """The defect family a CWE belongs to, or None when we do not group it.

    Grouping is deliberately conservative: an unmapped code returns None and only ever matches
    itself, so a wrong grouping can never silently merge two different bugs.
    """
    if not cwe:
        return None
    return _FAMILY.get(cwe.strip())


def same_family(a: str | None, b: str | None) -> bool:
    """True when two CWEs are the same code, or share a known family. Used by cross-confirmation
    and dedup so a CWE-120 structural hypothesis and a CWE-121 sanitizer crash can be recognised as
    the same memory defect. Unmapped codes match only themselves."""
    if a == b:
        return True
    fa, fb = family(a), family(b)
    return fa is not None and fa == fb
