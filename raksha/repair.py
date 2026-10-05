"""The repair ladder — cheapest lane first, model only when it must run.

    TEMPLATE   zero inference: a known bug shape -> a known fix shape
    RETRIEVAL  the nearest historical fix for this bug class
    LLM        the model proposes; several candidates, the gate picks
    MITIGATION a provably-safe hardening floor when nothing better validates

Each lane yields zero or more candidate patches; the caller gates them in order and stops at the
first that passes. The LLM lane goes through the one inference interface and simply yields nothing
when no endpoint is configured — so on a CPU-only or model-free box the ladder still runs
(template, retrieval, mitigation), which is the degrade path, not a failure.

This module produces candidates; it never decides truth. The gate does that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .finding import Finding, RepairLane
from .inference import REPAIR, InferenceClient, InferenceError, get_client


@dataclass(frozen=True)
class Candidate:
    diff: str
    lane: RepairLane
    model_version: str | None = None
    prompt_version: str | None = None
    #: A proposed regression test the candidate carries (model-written, or a deterministic template
    #: one). It is NEVER trusted here: the gate verifies fail-before/pass-after and only a verified
    #: test is shipped on the finding. Carried so the test rides with the diff that motivated it.
    regression_test: str | None = None


#: A template: given a finding, return a patch diff or None. Zero inference.
TemplateFn = Callable[[Finding], str | None]
#: A retrieval source: given a finding, return nearest historical patch diffs.
RetrievalFn = Callable[[Finding], Iterable[str]]


def template_candidates(finding: Finding, templates: Iterable[TemplateFn]) -> list[Candidate]:
    out = []
    for fn in templates:
        diff = fn(finding)
        if diff and diff.strip():
            out.append(Candidate(diff, RepairLane.TEMPLATE))
    return out


def retrieval_candidates(finding: Finding, source: RetrievalFn | None) -> list[Candidate]:
    if source is None:
        return []
    return [Candidate(d, RepairLane.RETRIEVAL) for d in source(finding) if d and d.strip()]


def llm_candidates(finding: Finding, *, client: InferenceClient | None = None, n: int = 4) -> list[Candidate]:
    """Model-proposed patches, or [] when no endpoint is configured (model-free operation)."""
    client = client or get_client()
    if client is None:
        return []
    prompt = _repair_prompt(finding)
    try:
        completions = client.complete(prompt, role=REPAIR, n=n, temperature=0.4)
    except InferenceError:
        return []  # transport failure degrades the lane; the run continues on templates/mitigation
    model = client.config.model_for(REPAIR)
    out = []
    for text in completions:
        diff = _extract_diff(text)
        if diff:
            out.append(Candidate(diff, RepairLane.LLM, model_version=model))
    return out


def mitigation_candidates(finding: Finding, floors: Iterable[TemplateFn]) -> list[Candidate]:
    """The provably-safe hardening floor: blunt but verified, used only when nothing else validates."""
    out = []
    for fn in floors:
        diff = fn(finding)
        if diff and diff.strip():
            out.append(Candidate(diff, RepairLane.MITIGATION))
    return out


def ladder(finding: Finding, *, templates: Iterable[TemplateFn] = (), retrieval: RetrievalFn | None = None,
           client: InferenceClient | None = None, floors: Iterable[TemplateFn] = (),
           n: int = 4) -> list[Candidate]:
    """All candidates in cost order. The caller gates them and stops at the first that passes."""
    return [
        *template_candidates(finding, templates),
        *retrieval_candidates(finding, retrieval),
        *llm_candidates(finding, client=client, n=n),
        *mitigation_candidates(finding, floors),
    ]


def _repair_prompt(finding: Finding) -> list[dict]:
    site = finding.fix_site_set[0] if finding.fix_site_set else None
    where = f"{site.uri}:{site.start_line}" if site and site.start_line else (site.uri if site else "unknown")
    return [
        {"role": "system", "content":
         "You are a security patch generator. Output ONLY a unified diff that fixes the "
         "vulnerability at the given site without changing any other behaviour. No prose."},
        {"role": "user", "content":
         f"Bug class: {finding.bug_class}\nLanguage: {finding.language}\nFix site: {where}\n"
         f"Finding: {finding.message}\n\nProduce the minimal unified diff."},
    ]


def _extract_diff(text: str) -> str | None:
    """Pull a unified diff out of a model response, tolerating code fences."""
    t = text.strip()
    if "```" in t:
        parts = t.split("```")
        for p in parts:
            body = p[4:] if p.lower().startswith("diff") else p
            if "--- " in body and "+++ " in body:
                return body.strip() + "\n"
    if "--- " in t and "+++ " in t:
        return t if t.endswith("\n") else t + "\n"
    return None


#: The model may append a regression test after this marker. A cheap, unambiguous delimiter the
#: prompt asks for, so the diff and the test are told apart without guessing.
_TEST_MARKER = re.compile(r"^={2,}\s*REGRESSION[ _-]?TEST\s*={2,}\s*$", re.MULTILINE | re.IGNORECASE)


def _strip_fences(text: str) -> str:
    """Drop a single wrapping code fence (``` or ```lang) from a block, if present."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


def split_diff_and_test(text: str) -> tuple[str | None, str | None]:
    """Split a model completion into (unified diff, regression test). The test is whatever follows
    the `=== REGRESSION TEST ===` marker; absent the marker there is no test. The test is never
    trusted here — the gate decides it by fail-before/pass-after."""
    m = _TEST_MARKER.search(text)
    if not m:
        return _extract_diff(text), None
    diff = _extract_diff(text[: m.start()])
    test = _strip_fences(text[m.end():])
    return diff, (test or None)


# ---- turning a model's edit into an exact diff ------------------------------------------------
# Small models are unreliable at unified-diff arithmetic (hunk counts, exact context), so a correct
# fix can arrive as a patch that will not apply. Two remedies, both deterministic: the model may
# answer with SEARCH/REPLACE blocks (exact text to find, text to put instead), and any unified diff
# it does send is re-anchored on the real file. Either way RAKSHA writes the final diff itself with
# difflib, so the gate always judges a well-formed patch of exactly the change the model meant.

_EDIT_BLOCK = re.compile(r"<{5,}\s*SEARCH\s*\n(.*?)\n={5,}\s*\n(.*?)\n?>{5,}\s*REPLACE", re.DOTALL)


_TRAILING_COMMENT = re.compile(r"\s*(?:/\*.*?\*/|//.*|#[^'\"]*)\s*$")


def _code_only(s: str) -> str:
    """A line without its trailing comment or surrounding whitespace. Models routinely copy the
    code of a line and drop the comment after it; matching on code alone keeps that fix."""
    return _TRAILING_COMMENT.sub("", s).strip()


def _locate(lines: list[str], block: list[str]) -> int | None:
    """Index where `block` occurs in `lines`: exactly, then ignoring surrounding whitespace, then
    ignoring trailing comments too. None if absent or ambiguous (more than one place)."""
    if not block:
        return None
    for norm in (lambda s: s, lambda s: s.strip(), _code_only):
        want = [norm(b) for b in block]
        hits = [i for i in range(len(lines) - len(block) + 1)
                if [norm(x) for x in lines[i:i + len(block)]] == want]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            return None
    return None


def _make_diff(rel: str, before: str, after: str) -> str | None:
    import difflib
    if before == after:
        return None
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def edits_to_diff(text: str, rel: str, source: str) -> str | None:
    """SEARCH/REPLACE blocks applied to `source` → an exact unified diff, or None."""
    blocks = _EDIT_BLOCK.findall(text)
    if not blocks:
        return None
    lines = source.splitlines()
    for search, replace in blocks:
        s = search.splitlines()
        at = _locate(lines, s)
        if at is None:
            return None
        lines[at:at + len(s)] = replace.splitlines()
    after = "\n".join(lines) + ("\n" if source.endswith("\n") else "")
    return _make_diff(rel, source, after)


def normalise_diff(diff: str, rel: str, source: str) -> str | None:
    """Re-anchor a possibly malformed unified diff for one file on the real source and rewrite it
    exactly. Each hunk's old text (context + removed lines) is located in the file; when the model's
    context is wrong, its removed lines alone are used as the anchor. None if any hunk cannot be
    placed unambiguously — then the original goes to the gate unchanged and fails honestly there."""
    hunks: list[tuple[list[str], list[str], list[str]]] = []      # (old, new, removed-only)
    cur = None
    for ln in diff.splitlines():
        if ln.startswith(("--- ", "+++ ")):
            continue
        if ln.startswith("@@"):
            cur = ([], [], [])
            hunks.append(cur)
            continue
        if cur is None:
            continue
        tag, body = (ln[:1], ln[1:]) if ln else (" ", "")
        if tag == " ":
            cur[0].append(body); cur[1].append(body)
        elif tag == "-":
            cur[0].append(body); cur[2].append(body)
        elif tag == "+":
            cur[1].append(body)
    if not hunks:
        return None
    lines = source.splitlines()
    for old, new, removed in hunks:
        at = _locate(lines, old)
        if at is not None:
            lines[at:at + len(old)] = new
            continue
        at = _locate(lines, removed)
        if at is None:
            return None
        added = [x for x in new if x not in old]
        lines[at:at + len(removed)] = added
    after = "\n".join(lines) + ("\n" if source.endswith("\n") else "")
    return _make_diff(rel, source, after)
