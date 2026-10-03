"""The jury exporter — the submission format.

The finale runs our system on real code and scores the output, so a clean, machine-readable export
is the actual deliverable. For every reportable finding this writes a self-contained folder:

    submission/
      summary.json                 one row per finding: id, cwe, status, severity, evidence kind
      findings.sarif               the full SARIF 2.1 log with the proof block
      <finding-id>/
        finding.json               the finding's proof block
        reproducer.bin             the reproducer artifact (if any)
        replay.sh                  how to replay it
        patch.diff                 the validated patch (VERIFIED findings only)
        report.md                  plain-English report (the Commander's Brief seed)

The layout is deliberately simple so it maps onto whatever exact format the organisers specify with
a thin adapter — the content (reproducer + patch + replay + SARIF) is what any harness needs.
"""

from __future__ import annotations

import json
from pathlib import Path

from .finding import Finding, Status, reportable, to_sarif_log


def export(findings: list[Finding], out_dir: str | Path, *, tool_version: str = "0.1.0") -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports = reportable(findings)

    (out / "findings.sarif").write_text(json.dumps(to_sarif_log(reports, tool_version=tool_version), indent=2))

    summary = []
    for f in reports:
        fdir = out / _safe(f.id)
        fdir.mkdir(exist_ok=True)
        proof = f.proof_block()
        (fdir / "finding.json").write_text(json.dumps(proof, indent=2))

        if f.reproducer and f.reproducer.artifact_path:
            # The reproducer bytes are the target's own file/input; we record the pointer and the
            # replay command rather than copying target code into the submission.
            (fdir / "replay.sh").write_text(_replay_script(f))
        elif f.reproducer:
            (fdir / "replay.sh").write_text(_replay_script(f))

        if f.status is Status.VERIFIED and f.patch_diff:
            (fdir / "patch.diff").write_text(f.patch_diff)
        (fdir / "report.md").write_text(_report_md(f))

        summary.append({
            "id": f.id,
            "bug_class": f.bug_class,
            "status": f.status.value,
            "severity": f.severity,
            "language": f.language,
            "target": f.target,
            "evidence_kind": f.reproducer.kind if f.reproducer else None,
            "has_patch": f.status is Status.VERIFIED and bool(f.patch_diff),
            "fix_site": f.fix_site_set[0].uri if f.fix_site_set else None,
        })

    (out / "summary.json").write_text(json.dumps({
        "tool": "RAKSHA AI", "version": tool_version,
        "counts": _counts(reports), "findings": summary,
    }, indent=2))
    return out


def _counts(reports: list[Finding]) -> dict:
    c = {"total": len(reports), "verified": 0, "report_only": 0, "confirmed": 0,
         "exploit": 0, "match": 0}
    for f in reports:
        if f.status is Status.VERIFIED:
            c["verified"] += 1
        elif f.status is Status.REPORT_ONLY:
            c["report_only"] += 1
        elif f.status is Status.CONFIRMED:
            c["confirmed"] += 1
        if f.reproducer:
            c["exploit" if f.reproducer.kind == "exploit-replay" else "match"] += 1
    return c


def _replay_script(f: Finding) -> str:
    cmd = " ".join(f.reproducer.replay_cmd) if f.reproducer else "# no reproducer"
    detail = (f.reproducer.detail or "") if f.reproducer else ""
    return (f"#!/usr/bin/env sh\n"
            f"# Replay for finding {f.id} ({f.bug_class})\n"
            f"# Evidence: {f.reproducer.kind if f.reproducer else 'none'}\n"
            f"# {detail}\n"
            f"{cmd}\n")


def _report_md(f: Finding) -> str:
    repro = f.reproducer
    lines = [
        f"# {f.bug_class} — {f.severity.upper()}",
        "",
        f"- **Status:** {f.status.value}",
        f"- **Target:** {f.target}",
        f"- **Language:** {f.language}",
        f"- **Detected by:** {f.oracle}",
        f"- **Evidence:** {repro.kind if repro else 'none'}"
        + (f" — {repro.detail}" if repro and repro.detail else ""),
    ]
    if f.fix_site_set:
        s = f.fix_site_set[0]
        lines.append(f"- **Fix site:** {s.uri}" + (f":{s.start_line}" if s.start_line else ""))
        if s.rationale:
            lines.append(f"- **Recommended fix:** {s.rationale}")
    lines += ["", "## What was found", "", f.message, ""]
    if f.status is Status.VERIFIED:
        lines += ["## Proof the fix holds", "",
                  "All five gate checks passed and the original attack no longer triggers on the "
                  "patched build. The validated patch is in `patch.diff`.", ""]
    elif f.status is Status.REPORT_ONLY:
        lines += ["## No validated fix", "",
                  "This vulnerability is proven real but no proposed patch cleared the gate, so no "
                  "fix is claimed. It is reported for human remediation rather than auto-patched.", ""]
    return "\n".join(lines)


def _safe(fid: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in fid)[:40]
