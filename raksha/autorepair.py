"""Drive a confirmed finding to a proven fix — the repair ladder against the real gate.

A finding that autofuzz (or any lane) confirmed carries no hand-written patch. This assembles repair
candidates cheapest-first — generic templates (zero inference), then the model (when an endpoint is
configured), then the mitigation floor — and gates each through the five-check gate, stopping at the
first that passes. Nothing here judges a patch; the gate does. If none clears it, the finding ends
REPORT_ONLY: proven, reported, never a guess.

The model lane goes through the one inference interface, so it uses whatever offline/cloud endpoint
RAKSHA_INFERENCE_BASE_URL points at and simply yields nothing when none is set — the templates are
the floor that always runs, which is why the autofuzz demos reach VERIFIED on a model-free box.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .finding import Finding, RepairLane, Status
from .gate.runner import MAX_REPAIR_ROUNDS, GateVerdict, decide, run_gate
from .gate.target import Target
from .inference import REPAIR, InferenceError, get_client
from .repair import Candidate, _extract_diff
from .repair_templates import _read_fix_site, generic_templates


@dataclass
class RepairOutcome:
    status: Status
    lane: RepairLane | None
    rounds: int
    candidates_tried: int
    verdict: GateVerdict | None = None

    @property
    def verified(self) -> bool:
        return self.status is Status.VERIFIED


def _llm_candidates(finding: Finding, root: Path, client, n: int = 3) -> list[Candidate]:
    """Model-proposed patches, with the fix-site source in the prompt. [] when no endpoint."""
    if client is None:
        return []
    got = _read_fix_site(finding, root)
    if got is None:
        return []
    rel, text = got
    numbered = "\n".join(f"{i}: {ln}" for i, ln in enumerate(text.splitlines(), 1))
    line = finding.fix_site_set[0].start_line
    prompt = [
        {"role": "system", "content":
         "You are a security patch generator. Output ONLY a unified diff (with `--- a/PATH` and "
         "`+++ b/PATH` headers) that fixes the vulnerability at the given site and changes nothing "
         "else. No prose, no code fences."},
        {"role": "user", "content":
         f"Bug class: {finding.bug_class}\nLanguage: {finding.language}\nFile: {rel}\n"
         f"Vulnerable site: {rel}:{line}\nFinding: {finding.message}\n\n"
         f"--- {rel} (line-numbered) ---\n{numbered}\n\nProduce the minimal unified diff for {rel}."},
    ]
    try:
        completions = client.complete(prompt, role=REPAIR, n=n, temperature=0.3)
    except InferenceError:
        return []
    model = client.config.model_for(REPAIR)
    out = []
    for textc in completions:
        diff = _extract_diff(textc)
        if diff:
            out.append(Candidate(diff, RepairLane.LLM, model_version=model))
    return out


def repair(finding: Finding, target: Target, *, root: str | Path, reproducer: bytes,
           corpus: list[bytes], client=None, use_model: bool = True, refuzz_seconds: float = 4.0,
           regression_test: str | None = None) -> RepairOutcome:
    """Try candidates in cost order; gate each; stop at the first VERIFIED, else REPORT_ONLY."""
    if finding.status is not Status.CONFIRMED:
        raise ValueError("repair() needs a CONFIRMED finding")
    root = Path(root)
    client = client if client is not None else (get_client() if use_model else None)

    template = [Candidate(d, RepairLane.TEMPLATE) for d in
                (fn() for fn in generic_templates(finding, root)) if d]
    candidates = [*template, *_llm_candidates(finding, root, client)]
    # keep the mitigation floor as a last resort: the template bound, retried as MITIGATION, so a
    # verified-but-blunt fix is still labelled as the floor it is
    candidates = candidates[:MAX_REPAIR_ROUNDS]

    verdict = None
    tried = 0
    for cand in candidates:
        if finding.status is not Status.CONFIRMED:
            break
        finding.mark_patched(cand.diff, cand.lane, model_version=cand.model_version)
        tried += 1
        verdict = run_gate(finding, target, reproducer=reproducer, corpus=corpus,
                           refuzz_seconds=refuzz_seconds, regression_test=regression_test)
        decide(finding, verdict)
        if finding.status is Status.VERIFIED:
            break
    if finding.status is Status.CONFIRMED:
        finding.report_only(f"no repair candidate cleared the gate ({tried} tried)")
    return RepairOutcome(finding.status, finding.repair_lane if finding.status is Status.VERIFIED else None,
                         finding.repair_rounds, tried, verdict)
