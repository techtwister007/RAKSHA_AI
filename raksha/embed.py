"""G3 — code vectors for cross-language fix retrieval.

Two backends, chosen at run time:

* ``endpoint`` — a learned code-embedding model served by the local OpenAI-compatible endpoint
  (``/v1/embeddings``, model named by RAKSHA_EMBED_MODEL). Used when configured and reachable.
* ``structural`` — the built-in fallback, always available, and NOT a learned model: code is
  rewritten into a small language-neutral concept vocabulary (taking a byte range — `memcpy`, a Go
  or Rust slice, `System.arraycopy` — is one concept; `sizeof`/`len`/`.length` is another; a shell
  call is another), identifiers and numbers are abstracted, and the unigram+bigram counts are
  hashed into a fixed-width, L2-normalised vector. It is what lets a C copy-length bug and a Go
  slice-bound bug land near each other without any weights on the box.

Vectors are only ever used to *rank* remembered, already-verified fixes; whatever they retrieve is
still proposed to the gate like any other candidate.
"""

from __future__ import annotations

import hashlib
import math
import re

DIM = 256

#: concept lexicon: surface spellings across C, Go, Rust, Java, Python, JS -> one concept token
_LEXICON = {
    "RANGE": ("memcpy", "memmove", "strcpy", "strncpy", "strcat", "copy", "copy_from_slice",
              "clone_from_slice", "arraycopy", "copyOf", "copyOfRange", "subarray", "slice"),
    "SIZE": ("sizeof", "len", "length", "size", "cap", "capacity", "strlen"),
    "CLAMP": ("min", "max", "clamp", "saturating_sub", "checked_sub"),
    "SHELL": ("system", "popen", "exec", "execSync", "execFile", "spawn", "shell", "Popen",
              "check_output", "getoutput", "run", "Runtime"),
    "ALLOC": ("malloc", "calloc", "realloc", "make", "new", "with_capacity", "alloc"),
    "PARSE": ("parse", "decode", "read", "unmarshal", "load", "loads", "deserialize"),
    "LOOP": ("for", "while", "loop", "range"),
    "COND": ("if", "else", "switch", "match", "case"),
    "RET": ("return",),
    "ERR": ("panic", "throw", "raise", "abort", "err", "Err", "error"),
}
_WORD2CONCEPT = {w.lower(): c for c, ws in _LEXICON.items() for w in ws}
_SLICE = re.compile(r"\[[^\[\]]*(?::|\.\.)[^\[\]]*\]")      # a[lo:hi] (Go/Python) / a[lo..hi] (Rust)
_INDEX = re.compile(r"\[[^\[\]]+\]")
_TOK = re.compile(r"[A-Za-z_]\w*|\d+|<=|>=|==|!=|->|::|[<>+\-*/%&|?:=]")


def concepts(code: str) -> list[str]:
    """The language-neutral concept token stream for a code fragment."""
    s = _SLICE.sub(" __RANGE__ ", code)
    s = _INDEX.sub(" __INDEX__ ", s)
    out: list[str] = []
    for t in _TOK.findall(s):
        if t == "__RANGE__":
            out.append("RANGE")
        elif t == "__INDEX__":
            out.append("INDEX")
        elif t[0].isdigit():
            out.append("NUM")
        elif t[0].isalpha() or t[0] == "_":
            out.append(_WORD2CONCEPT.get(t.lower(), "ID"))
        elif t in ("<", ">", "<=", ">="):
            out.append("CMP")
        elif t in ("+", "-"):
            out.append("ARITH")
        elif t == "?":
            out.append("COND")
    # identifiers carry no cross-language meaning on their own: keep them only as context in bigrams
    return out


def _hash(feat: str) -> int:
    return int.from_bytes(hashlib.blake2s(feat.encode(), digest_size=4).digest(), "big") % DIM


def structural_vector(code: str, *, family: str | None = None) -> list[float]:
    toks = concepts(code)
    v = [0.0] * DIM
    for t in toks:
        if t != "ID":
            v[_hash("u:" + t)] += 1.0
    for a, b in zip(toks, toks[1:]):
        if (a, b) != ("ID", "ID"):
            v[_hash(f"b:{a}>{b}")] += 0.5
    if family:
        v[_hash("fam:" + family)] += 2.0       # same CWE family pulls fixes together
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


class Embedder:
    """`vector(code, family)` from the endpoint when available, else the structural fallback.
    `backend` says which one produced the vectors (it is recorded with every retrieval)."""

    def __init__(self, client=None, model: str | None = None) -> None:
        self.client = client
        self.model = model
        self.backend = "endpoint" if (client is not None and model) else "structural"

    def vector(self, code: str, *, family: str | None = None) -> list[float]:
        if self.backend == "endpoint":
            try:
                return self.client.embed([code], model=self.model)[0]
            except Exception:  # noqa: BLE001 — the endpoint failing degrades to the fallback, visibly
                self.backend = "structural"
        return structural_vector(code, family=family)


def default_embedder() -> Embedder:
    import os
    model = os.environ.get("RAKSHA_EMBED_MODEL")
    if not model:
        return Embedder()
    try:
        from .inference import get_client
        client = get_client()
    except Exception:  # noqa: BLE001
        client = None
    return Embedder(client, model) if client is not None else Embedder()
