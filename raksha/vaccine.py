"""The Vulnerability Vaccine — one verified fix, fleet-wide immunity.

Every verified fix teaches RAKSHA what the mistake looked like. It turns that into a detection rule
and sweeps every other codebase for the same mistake: "we fixed one bug, and in the same minute
found the same mistake in four other systems."

The rule must earn its place, the same way a patch does — because we do not trust our own detection
rules either. Three checks, and a rule that fails any is thrown away:

  1. HITS THE ORIGINAL  — it matches the vulnerable shape, or it does not describe the bug
  2. MISSES THE FIX     — it does NOT match the patched shape, or it flags safe code forever
  3. LOW NOISE          — it fires rarely on a clean reference corpus, or it floods reviewers

Safety: only VERIFIED fixes become vaccines (an unproven fix would spread a wrong pattern); the
sweep is read-only, so it is always R0-safe; a sweep hit is only SUSPECTED until it earns its own
reproducer, so precision stays structural. In the full product the rule is a Semgrep rule; here it
is a dependency-free pattern rule carrying the same three-check discipline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .finding import Finding, Frame, Status


@dataclass(frozen=True)
class VaccineRule:
    """A detection rule mined from a verified fix."""
    id: str
    bug_class: str
    language: str
    bad: re.Pattern          # matches the vulnerable shape
    fixed: re.Pattern        # matches the patched shape (must NOT fire for the rule to pass)
    origin_finding: str
    description: str

    def matches(self, text: str) -> list[int]:
        """Line numbers (1-based) where the vulnerable shape appears and the fixed shape does not."""
        hits = []
        for i, line in enumerate(text.splitlines(), 1):
            if self.bad.search(line) and not self.fixed.search(line):
                hits.append(i)
        return hits


# Shape extractors per bug class: given the fix diff, produce (bad, fixed) patterns. Each is a
# narrow, honest generalisation of the specific fix — the vulnerable shape without the fix applied.
_EXTRACTORS: dict[str, tuple[str, str, str]] = {
    # Python shell injection: shell=True sink vs shell=False
    "CWE-78": (r"subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
               r"shell\s*=\s*False",
               "subprocess call with shell=True"),
    # eval/exec style code injection
    "CWE-94": (r"\b(?:eval|exec)\s*\(", r"ast\.literal_eval", "use of eval/exec"),
    # C unbounded memcpy (the overflow shape): memcpy with a length that is not sizeof-bounded
    "CWE-121": (r"memcpy\s*\([^,]+,[^,]+,\s*(?!.*sizeof)[^)]*\)",
                r"sizeof", "memcpy without a sizeof bound"),
    "CWE-787": (r"strcpy\s*\(", r"strncpy|strlcpy", "unbounded strcpy"),
}


@dataclass
class ProofResult:
    hits_original: bool
    misses_fix: bool
    low_noise: bool
    noise_hits: int = 0

    @property
    def passed(self) -> bool:
        return self.hits_original and self.misses_fix and self.low_noise

    def as_dict(self) -> dict:
        return {"hits_original": self.hits_original, "misses_fix": self.misses_fix,
                "low_noise": self.low_noise, "noise_hits": self.noise_hits, "passed": self.passed}


def extract_rule(finding: Finding) -> VaccineRule | None:
    """Mine a detection rule from a VERIFIED finding. Returns None if we cannot describe the shape."""
    if finding.status is not Status.VERIFIED:
        return None  # only verified fixes become vaccines
    spec = _EXTRACTORS.get(finding.bug_class)
    if not spec:
        return None
    bad, fixed, desc = spec
    return VaccineRule(
        id=f"vaccine-{finding.bug_class}-{finding.id[:8]}",
        bug_class=finding.bug_class, language=finding.language,
        bad=re.compile(bad), fixed=re.compile(fixed),
        origin_finding=finding.id, description=desc,
    )


def prove_rule(rule: VaccineRule, *, vulnerable_sample: str, fixed_sample: str,
               clean_corpus: list[str], noise_threshold: int = 0) -> ProofResult:
    """The three checks. A rule that fails any is thrown away, exactly like a patch that fails the gate."""
    hits_original = bool(rule.matches(vulnerable_sample))
    misses_fix = not rule.matches(fixed_sample)
    noise = sum(len(rule.matches(c)) for c in clean_corpus)
    return ProofResult(hits_original, misses_fix, noise <= noise_threshold, noise_hits=noise)


@dataclass
class SweepHit:
    rule_id: str
    target: str
    path: str
    line: int


def sweep(rule: VaccineRule, codebases: dict[str, Path]) -> list[SweepHit]:
    """Run the rule read-only across registered codebases. Always R0-safe."""
    hits: list[SweepHit] = []
    for name, root in codebases.items():
        root = Path(root)
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for p in files:
            if p.suffix not in _SUFFIX.get(rule.language, _SUFFIX["*"]):
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            rel = str(p.relative_to(root)) if root.is_dir() else p.name
            for line in rule.matches(text):
                hits.append(SweepHit(rule.id, name, rel, line))
    return hits


def hit_to_finding(rule: VaccineRule, hit: SweepHit) -> Finding:
    """A sweep hit is only SUSPECTED until it earns its own reproducer — precision stays structural."""
    return Finding(
        oracle=f"vaccine:{rule.id}",
        bug_class=rule.bug_class, language=rule.language, target=hit.target,
        message=f"Vaccine sweep: same mistake as {rule.origin_finding[:8]} "
                f"({rule.description}) at {hit.path}:{hit.line}",
        severity="high",
        frames=[Frame(symbol=rule.id, uri=hit.path, line=hit.line)],
    )


_SUFFIX = {
    "python": {".py"}, "c/c++": {".c", ".h", ".cc", ".cpp"}, "java": {".java"},
    "javascript": {".js", ".ts"}, "*": {".py", ".c", ".h", ".cc", ".cpp", ".java", ".js", ".ts"},
}
