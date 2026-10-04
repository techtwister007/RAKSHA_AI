"""The retrieval lane source — a memory of verified fixes, so the SECOND occurrence of a bug class
is fixed at ZERO inference (retrieval, not the model).

Every fix that clears the five-check gate teaches RAKSHA a reusable rewrite: "this vulnerable shape
becomes that safe shape." `FixMemory.remember` mines that rewrite from a VERIFIED finding's own
`patch_diff` (never from an unproven one), generalising the concrete diff into an identifier-agnostic
template by anti-unifying the changed line against its replacement. `FixMemory.candidates` then
re-targets a remembered rewrite to a NEW finding of the same bug class and language whose fix-site
source carries the same shape — rebuilding the unified diff over the NEW file via difflib, so the
header and hunk always name the new path and lines. The old file's bytes are never pasted blindly; a
rewrite that does not apply at the new site yields nothing.

This is the vaccine idea at the repair layer: one proven fix, reused across the estate at no model
cost. The gate still judges every retrieved candidate — retrieval proposes, it never certifies.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path

from . import vaccine
from .finding import Finding, Status
from .repair import RetrievalFn
from .repair_templates import _diff, _import_insertion_point, _read_fix_site

_ID = re.compile(r"[A-Za-z_]\w*")
#: one token: an identifier, a run of whitespace, or any single other character.
_TOK = re.compile(r"[A-Za-z_]\w*|\s+|.", re.S)


# ---- the learned, identifier-agnostic rewrite --------------------------------------------------

@dataclass(frozen=True)
class LineRewrite:
    """A single changed line generalised: a regex that matches the vulnerable shape (identifiers
    captured, whitespace flexible, literals fixed) and a segment template that rebuilds the safe
    shape, carrying the matched identifiers across to a new site."""

    pattern: str
    ids: tuple[str, ...]
    segs: tuple[tuple[str, str], ...]   # (("lit", text) | ("slot", id), ...)

    def apply(self, line: str) -> str | None:
        """Rewrite `line` if it carries the vulnerable shape; else None. Indentation and any trailing
        comment are preserved — the pattern matches only the code span inside the line."""
        nl = ""
        body = line
        if body.endswith("\n"):
            nl, body = "\n", body[:-1]
        m = re.compile(self.pattern).search(body)
        if not m:
            return None
        idval = {self.ids[i]: m.group(i + 1) for i in range(len(self.ids))}
        newcode = "".join(idval[s] if kind == "slot" else s for kind, s in self.segs)
        cand = body[: m.start()] + newcode + body[m.end():]
        return cand + nl if cand != body else None


def _strip_trailing_comment(line: str, language: str) -> str:
    """The code portion of a line: leading indent and a trailing comment removed. Quote-aware so a
    `#`/`//` inside a string literal is not mistaken for a comment."""
    in_s: str | None = None
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_s:
            if c == "\\":
                i += 2
                continue
            if c == in_s:
                in_s = None
            i += 1
            continue
        if c in ("'", '"'):
            in_s = c
        elif language == "python" and c == "#":
            return line[:i].rstrip()
        elif language != "python" and c == "/" and i + 1 < n and line[i + 1] in "/*":
            return line[:i].rstrip()
        i += 1
    return line.rstrip()


def _learn_line_rewrite(before_line: str, after_line: str, language: str) -> LineRewrite | None:
    """Anti-unify a removed line against its replacement into an identifier-agnostic rewrite."""
    before = _strip_trailing_comment(before_line, language).strip()
    after = _strip_trailing_comment(after_line, language).strip()
    if not before or before == after:
        return None
    group_of: dict[str, int] = {}
    parts: list[str] = []
    for tok in _TOK.findall(before):
        if _ID.fullmatch(tok):
            if tok in group_of:
                parts.append(f"\\{group_of[tok]}")
            else:
                group_of[tok] = len(group_of) + 1
                parts.append(r"([A-Za-z_]\w*)")
        elif tok.isspace():
            parts.append(r"\s*")
        else:
            parts.append(re.escape(tok))
    if not group_of:
        return None
    ids = tuple(group_of)
    segs: list[tuple[str, str]] = []
    for tok in _TOK.findall(after):
        if _ID.fullmatch(tok) and tok in group_of:
            segs.append(("slot", tok))
        else:
            segs.append(("lit", tok))
    try:
        re.compile("".join(parts))
    except re.error:
        return None
    return LineRewrite(pattern="".join(parts), ids=ids, segs=tuple(segs))


def _parse_hunks(diff: str) -> list[tuple[list[str], list[str]]]:
    """(before, after) line fragments per hunk — context on both sides, so a line-level diff of the
    two sides tells a true rewrite apart from a pure insertion."""
    hunks: list[tuple[list[str], list[str]]] = []
    before: list[str] = []
    after: list[str] = []
    started = False
    for ln in diff.splitlines():
        if ln.startswith("@@"):
            if started:
                hunks.append((before, after))
            before, after, started = [], [], True
            continue
        if ln.startswith(("---", "+++")) or not started:
            continue
        if ln.startswith("-"):
            before.append(ln[1:])
        elif ln.startswith("+"):
            after.append(ln[1:])
        elif ln.startswith(" "):
            before.append(ln[1:])
            after.append(ln[1:])
    if started:
        hunks.append((before, after))
    return hunks


def _learn_from_diff(diff: str, language: str) -> tuple[list[LineRewrite], list[str]]:
    """Turn a unified diff into (line rewrites, pure-insert lines). Replaced lines are paired by
    similarity, so a hunk that both rewrites a sink and inserts an import learns both."""
    rewrites: list[LineRewrite] = []
    inserts: list[str] = []
    for before, after in _parse_hunks(diff):
        sm = difflib.SequenceMatcher(None, before, after, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            a_block, b_block = before[i1:i2], after[j1:j2]
            if tag == "insert":
                inserts.extend(b_block)
            elif tag == "replace":
                remaining = list(b_block)
                for a_line in a_block:
                    best, best_r = None, 0.0
                    for b_line in remaining:
                        r = difflib.SequenceMatcher(None, a_line, b_line).ratio()
                        if r > best_r:
                            best_r, best = r, b_line
                    if best is not None and best_r >= 0.4:
                        rw = _learn_line_rewrite(a_line, best, language)
                        if rw is not None:
                            rewrites.append(rw)
                        remaining.remove(best)
                inserts.extend(remaining)
            # 'delete' blocks (a removed line with no replacement) are not reusable rewrites
    return rewrites, [s for s in inserts if s.strip()]


# ---- the memory --------------------------------------------------------------------------------

@dataclass(frozen=True)
class FixRecord:
    """A compact, reusable record of one verified fix."""

    bug_class: str
    language: str
    origin_finding: str
    origin_uri: str
    origin_line: int | None
    rewrites: tuple[LineRewrite, ...]
    inserts: tuple[str, ...]
    patch_diff: str
    rule_id: str | None = None


class FixMemory:
    """A memory of verified fixes. `remember` stores one; `candidates` re-targets the matching ones
    to a new finding. Append-only within a process; nothing here is persisted to disk."""

    def __init__(self) -> None:
        self._records: list[FixRecord] = []
        self._banned: set[str] = set()   # E7: shapes an operator marked wrong; never re-offered

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> list[FixRecord]:
        return list(self._records)

    @staticmethod
    def _shape_key(bug_class: str, language: str, rewrites) -> str:
        return "|".join([bug_class, language, *sorted(r.pattern for r in rewrites)])

    def save(self, path) -> None:
        """E5: persist the memory so a learned fix survives a reboot (Stage 9 must not reset)."""
        import json
        from dataclasses import asdict
        from pathlib import Path as _P
        data = {"records": [asdict(r) for r in self._records], "banned": sorted(self._banned)}
        p = _P(path); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2))

    def load(self, path) -> int:
        """Merge persisted records from disk (idempotent on origin_finding). Returns how many added."""
        import json
        from pathlib import Path as _P
        p = _P(path)
        if not p.is_file():
            return 0
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            return 0
        self._banned |= set(data.get("banned", []))
        have = {r.origin_finding for r in self._records}
        n = 0
        for d in data.get("records", []):
            if d.get("origin_finding") in have:
                continue
            rewrites = tuple(LineRewrite(pattern=w["pattern"], ids=tuple(w["ids"]),
                                         segs=tuple(tuple(x) for x in w["segs"])) for w in d["rewrites"])
            self._records.append(FixRecord(
                bug_class=d["bug_class"], language=d["language"], origin_finding=d["origin_finding"],
                origin_uri=d["origin_uri"], origin_line=d.get("origin_line"), rewrites=rewrites,
                inserts=tuple(d.get("inserts", ())), patch_diff=d["patch_diff"], rule_id=d.get("rule_id")))
            n += 1
        return n

    def demote(self, finding: Finding) -> int:
        """E7: an operator marked this fix wrong in the field. Drop every record learned from it and
        ban its shape so it is never relearned or re-offered. Returns how many records were removed."""
        key = None
        if finding.patch_diff:
            rewrites, _ = _learn_from_diff(finding.patch_diff, finding.language)
            if rewrites:
                key = self._shape_key(finding.bug_class, finding.language, rewrites)
        before = len(self._records)
        self._records = [r for r in self._records
                         if r.origin_finding != finding.id
                         and (key is None or self._shape_key(r.bug_class, r.language, r.rewrites) != key)]
        if key:
            self._banned.add(key)
        return before - len(self._records)

    def remember(self, finding: Finding) -> FixRecord | None:
        """Store a reusable record from a VERIFIED finding. No-op (returns None) for anything else,
        or when the diff holds no rewrite we can generalise."""
        if finding.status is not Status.VERIFIED or not finding.patch_diff:
            return None
        rewrites, inserts = _learn_from_diff(finding.patch_diff, finding.language)
        if not rewrites and not inserts:
            return None
        if self._shape_key(finding.bug_class, finding.language, rewrites) in self._banned:
            return None   # E7: this shape was marked wrong by a human; do not relearn it
        site = finding.fix_site_set[0] if finding.fix_site_set else None
        rule = vaccine.extract_rule(finding)   # may be None; used only as a provenance tag here
        rec = FixRecord(
            bug_class=finding.bug_class, language=finding.language,
            origin_finding=finding.id,
            origin_uri=site.uri if site else "",
            origin_line=site.start_line if site else None,
            rewrites=tuple(rewrites), inserts=tuple(inserts),
            patch_diff=finding.patch_diff, rule_id=rule.id if rule else None,
        )
        self._records.append(rec)
        return rec

    def candidates(self, finding: Finding, root: str | Path | None = None) -> list[str]:
        """Unified-diff candidate(s) for `finding`, re-targeted to its fix site, from every
        remembered fix of the same bug class and language whose shape it carries. Zero inference."""
        out: list[str] = []
        seen: set[str] = set()
        for rec in self._records:
            if rec.bug_class != finding.bug_class or rec.language != finding.language:
                continue
            diff = self._retarget(rec, finding, root)
            if diff and diff not in seen:
                seen.add(diff)
                out.append(diff)
        return out

    def _retarget(self, rec: FixRecord, finding: Finding, root: str | Path | None) -> str | None:
        got = _read_new_source(finding, root)
        if got is None:
            return None
        rel, text = got
        lines = text.splitlines(keepends=True)
        after = list(lines)
        site_line = finding.fix_site_set[0].start_line if finding.fix_site_set else None
        first_idx: int | None = None
        changed = False
        for rw in rec.rewrites:
            idx = _find_and_apply(rw, after, site_line)
            if idx is not None:
                changed = True
                first_idx = idx if first_idx is None else min(first_idx, idx)
        if not changed:
            return None
        # Do not re-offer a fix for the exact location it was learned from: retrieval exists to fix
        # the same mistake ELSEWHERE. Same file basename and (near) the same line is the origin.
        if (rel.rsplit("/", 1)[-1] == rec.origin_uri.rsplit("/", 1)[-1]
                and rec.origin_line is not None and first_idx is not None
                and abs((first_idx + 1) - rec.origin_line) <= 2):
            return None
        _apply_inserts(rec, after, first_idx)
        return _diff(text, "".join(after), rel)


def _read_new_source(finding: Finding, root: str | Path | None) -> tuple[str, str] | None:
    if root is not None:
        return _read_fix_site(finding, Path(root))
    if not finding.fix_site_set:
        return None
    rel = finding.fix_site_set[0].uri
    p = Path(rel)
    if p.is_file():
        try:
            return rel, p.read_text()
        except OSError:
            return None
    return None


def _find_and_apply(rw: LineRewrite, lines: list[str], site_line: int | None) -> int | None:
    """Apply `rw` to the first matching line, nearest the fix site when one is known. Returns the
    index of the line it rewrote, or None if nothing matched."""
    order = range(len(lines))
    if site_line:
        order = sorted(range(len(lines)), key=lambda i: (abs((i + 1) - site_line), i))
    for i in order:
        new = rw.apply(lines[i])
        if new is not None:
            lines[i] = new
            return i
    return None


def _apply_inserts(rec: FixRecord, lines: list[str], first_idx: int | None) -> None:
    for ins in rec.inserts:
        s = ins.strip()
        if not s or any(ln.strip() == s for ln in lines):
            continue
        ins_line = ins if ins.endswith("\n") else ins + "\n"
        if re.match(r"\s*(?:import|from)\s+\w", ins):
            pos = _import_insertion_point(lines)
        else:
            pos = first_idx if first_idx is not None else 0
        lines.insert(pos, ins_line)


# ---- module-level default memory + the RetrievalFn adapter -------------------------------------

_DEFAULT_MEMORY = FixMemory()


def default_memory() -> FixMemory:
    """The shared process memory used by `autorepair.repair` when no memory is passed in."""
    return _DEFAULT_MEMORY


def retrieval_source(memory: FixMemory) -> RetrievalFn:
    """Adapt a memory to the `RetrievalFn` shape `repair.retrieval_candidates` expects (it reads the
    new fix-site source from the finding's own path, for the model-free `repair.ladder`)."""
    def source(finding: Finding):
        return memory.candidates(finding)
    return source
