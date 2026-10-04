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
