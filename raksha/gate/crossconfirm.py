"""Lane cross-confirmation.

A static-analysis finding has no reproducer and so stays SUSPECTED. If another lane later lands a
reproducer on the same fix site with the same bug class, the static finding was right — and the
reproducer proves it. Two rules keep this honest:

- **same fix site AND same CWE.** A null dereference at line 71 does not confirm a SQL-injection
  match at line 71.
- **the records merge.** One bug, one record, or Performance counts it twice.

The survivor is the finding that actually holds the reproducer; the promoted static finding is
confirmed (its history records why) and then folded into the survivor's `merged_from`.
"""

from __future__ import annotations

from ..finding import Finding, FixSite, Status


def _same_site(a: FixSite, b: FixSite, tol: int) -> bool:
    if a.uri.rsplit("/", 1)[-1] != b.uri.rsplit("/", 1)[-1]:
        return False
    if a.start_line is None or b.start_line is None:
        return True
    return abs(a.start_line - b.start_line) <= tol


def cross_confirm(findings: list[Finding], *, line_tolerance: int = 3) -> list[Finding]:
    """Promote and merge. Returns the surviving list; order is preserved for survivors."""
    proven = [f for f in findings if f.status is not Status.SUSPECTED and f.reproducer and f.replay_before]
    absorbed: set[str] = set()
    for f in findings:
        if f.status is not Status.SUSPECTED or f.reproducer is not None:
            continue
        for g in proven:
            if g.id == f.id or g.bug_class != f.bug_class:
                continue
            if not any(_same_site(a, b, line_tolerance) for a in f.fix_site_set for b in g.fix_site_set):
                continue
            f.attach_reproducer(g.reproducer)
            f.record_replay_before(g.replay_before)
            f.confirm(reason=f"cross-confirmed by {g.oracle} reproducer on finding {g.id}")
            g.merged_from.append(f.id)
            absorbed.add(f.id)
            break
    return [f for f in findings if f.id not in absorbed]
