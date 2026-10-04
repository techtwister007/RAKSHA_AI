"""Patch hygiene — the zero-cost checks a candidate must pass before it earns a gate run.

The gate judges behaviour. It cannot see intent: a diff that fixes the overflow *and* opens a
socket, or edits a file the finding never named, passes every behavioural check as long as the
corpus never exercises the new code. Those diffs come from exactly one place — a model whose
context contained untrusted target source (comments, strings, docs that may address the model
directly). So, before any candidate is applied:

  scope       it may touch only the files in the finding's fix-site set
  size        it may not add more than MAX_ADDED_LINES (a fix is local; a rewrite is not)
  primitives  added lines may not introduce an execution / network / dynamic-load primitive
              that the removed lines did not already contain

A rejection is recorded on the finding and on the Scorecard; it never counts as a gate run. The
templates go through the same check — our own code earns no exemption.
"""

from __future__ import annotations

import re

from .finding import Finding

MAX_ADDED_LINES = 150

#: Primitives whose *appearance* in a security patch is a red flag in any language we gate.
_PRIMITIVES = [
    r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexec(?:l|lp|le|v|vp|vpe)?\s*\(", r"\bdlopen\s*\(",
    r"\bsocket\s*\(", r"\bconnect\s*\(", r"\bfork\s*\(", r"\bptrace\s*\(",
    r"\bos\.system\b", r"\bos\.popen\b", r"\bsubprocess\.", r"\beval\s*\(", r"\bexec\s*\(",
    r"__import__", r"\bimportlib\b", r"\bctypes\b", r"\burllib\b", r"\brequests\.",
    r"\bshell\s*=\s*True\b", r"\bpickle\.loads?\b", r"\bmarshal\.loads?\b",
    r'"os/exec"', r'"net"', r'"net/http"', r"\bexec\.Command\b", r"\bnet\.Dial\b", r"\bsyscall\.",
    r"\bRuntime\.getRuntime\b", r"\bProcessBuilder\b", r"\bClass\.forName\b", r"\bjava\.net\.",
    r"\bchild_process\b", r"\bnew Function\s*\(", r"\brequire\s*\(\s*['\"](?:net|http|https|fs)['\"]",
    r"\bstd::process::Command\b", r"\bunsafe\s*\{",
    r"\bcurl\s", r"\bwget\s", r"\bnc\s", r"/dev/tcp/",
]
_PRIM_RE = [re.compile(p) for p in _PRIMITIVES]


#: Each primitive's class. A patch may swap one primitive for another of the SAME class (replace
#: `os.system(cmd)` with `subprocess.run([...])`, the standard fix for command injection) — that adds
#: no new capability. What hygiene refuses is a class the original lines did not have at all: a
#: "fix" that suddenly opens a socket, loads code or spawns a process where none was spawned before.
_CLASS_RULES = (
    ("network", ("socket", "connect", "urllib", "requests", "net", "java.net", "curl", "wget", "nc",
                 "/dev/tcp/", "net.Dial", "require")),
    ("dynamic-load", ("dlopen", "__import__", "importlib", "ctypes", "Class.forName", "new Function",
                      "eval", "unsafe", "exec (code)", "ptrace")),
    ("deserialise", ("pickle", "marshal")),
    ("shell", ("system", "popen", "os.system", "os.popen", "shell=True")),
    ("exec", ("system", "popen", "exec", "fork", "ptrace", "subprocess", "shell", "os/exec",
              "syscall", "Runtime.getRuntime", "ProcessBuilder", "child_process", "std::process")),
)


def _class(label: str) -> str:
    """The class of a primitive label. Keys match as whole tokens, so "nc" does not match "Function"."""
    for cls, keys in _CLASS_RULES:
        for k in keys:
            if re.search(r"(?<![A-Za-z])" + re.escape(k) + r"(?![A-Za-z])", label):
                return cls
    return label


def _label(pattern: str) -> str:
    """A readable name for a matched primitive ("os.system", "socket(") for the record."""
    cleaned = re.sub(r"\(\?:[^)]*\)", "", pattern)                    # drop alternation groups
    cleaned = re.sub(r"\\[bsdw]|[\\^$?*+(){}\[\]|]", "", cleaned)
    return cleaned.replace('"', "").strip() or pattern

_FILE_RE = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)", re.M)


def touched_files(diff: str) -> set[str]:
    return {m for m in _FILE_RE.findall(diff) if m not in ("/dev/null",)}


def _primitives(lines: list[str]) -> set[str]:
    hits: set[str] = set()
    for ln in lines:
        for rx in _PRIM_RE:
            if rx.search(ln):
                # Python's exec() runs code, not a command: label it apart from the exec*() family
                hits.add("exec (code)" if rx.pattern == r"\bexec\s*\(" else _label(rx.pattern))
    return hits


def check(diff: str, finding: Finding) -> str | None:
    """None when the candidate may be gated; otherwise the one-line reason it was refused."""
    allowed = {s.uri for s in finding.fix_site_set} | {s.uri.rsplit("/", 1)[-1] for s in finding.fix_site_set}
    if not allowed:
        return "no fix site on the finding; a patch cannot be scoped"
    for f in touched_files(diff):
        if f not in allowed and f.rsplit("/", 1)[-1] not in allowed:
            return f"touches {f}, which is not in the fix-site set"
    added = [ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln[1:] for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---")]
    if len(added) > MAX_ADDED_LINES:
        return f"adds {len(added)} lines (cap {MAX_ADDED_LINES}); a fix is local, a rewrite is not"
    added_p, removed_p = _primitives(added), _primitives(removed)
    removed_classes = {_class(p) for p in removed_p}
    # A new primitive is allowed only when it is a plain argument-list process call ("exec" class)
    # replacing lines that already ran a command (exec or shell): the standard command-injection fix.
    # Any new shell-invoking, network, code-loading or deserialising primitive is still refused.
    new = sorted(p for p in added_p - removed_p
                 if not (_class(p) == "exec" and removed_classes & {"exec", "shell"}))
    if new:
        return "introduces an execution/network primitive absent from the original: " + ", ".join(new)
    return None
