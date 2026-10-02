"""Phase 0 keystone demo: `python -m raksha.demo`

Drives a C, a Java and a Python finding through the same pipeline, with no
language-specific code anywhere below the oracle layer, and prints the scorecard.

This is the Phase 0 checkpoint made visible. It is also the seed of console Screen 5.
"""

from __future__ import annotations

import json
import pathlib
import sys

from .finding import (
    GATE_ORDER,
    Finding,
    Frame,
    GateCheck,
    RepairLane,
    ReplayResult,
    Reproducer,
    dedup,
    reportable,
    to_sarif_log,
    utcnow,
)
from .metrics import scorecard
from .oracles import KEYSTONE_ORACLES

FIXTURES = pathlib.Path(__file__).parents[1] / "tests" / "fixtures"

#: (fixture, does a patch validate?) -- the last one deliberately fails the gate, so
#: the demo shows REPORT_ONLY as a real outcome rather than only the happy path.
SCENARIOS = [
    ("asan_heap_overflow.txt", True),
    ("jazzer_jndi.txt", True),
    ("pysecsan_cmd_injection.txt", False),
]

GREEN, RED, AMBER, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m",
)


def ingest(raw: str, target: str):
    """Route raw tool output to whichever oracle recognises it."""
    for oracle in KEYSTONE_ORACLES:
        found = oracle.parse(raw, target=target)
        if found:
            return found[0]
    return None


def run() -> int:
    print(f"\n{BOLD}RAKSHA AI — Phase 0 keystone{OFF}")
    print(f"{DIM}three oracles → one record → one gate{OFF}\n")

    findings = []
    for name, patch_validates in SCENARIOS:
        raw = (FIXTURES / name).read_text()
        finding = ingest(raw, target=name.split("_")[0])
        if finding is None:
            print(f"  {RED}no oracle claimed {name}{OFF}")
            continue
        findings.append(finding)

        print(f"  {BOLD}{finding.language:<8}{OFF} {finding.bug_class:<12} "
              f"{finding.oracle}")
        print(f"  {DIM}         {finding.message[:70]}{OFF}")
        print(f"  {DIM}         fix site: {finding.fix_site_set[0].uri}"
              f":{finding.fix_site_set[0].start_line}{OFF}")

        # --- the pipeline, identical for every language ---
        finding.attach_reproducer(
            Reproducer.from_bytes(b"<minimised reproducer>", ["./replay.sh"],
                                  minimised=True)
        )
        finding.record_replay_before(
            ReplayResult(oracle_fired=True, at=utcnow(),
                         abort_signature=finding.abort_signature)
        )
        finding.confirm()

        if patch_validates:
            finding.mark_patched("--- a/f\n+++ b/f\n", RepairLane.TEMPLATE)
            for check in GATE_ORDER:
                finding.record_gate(check, True, detail="ok")
            finding.record_replay_after(
                ReplayResult(oracle_fired=False, at=utcnow(), exit_code=0)
            )
            finding.verify()
            print(f"           {GREEN}✓ VERIFIED{OFF} "
                  f"{DIM}all five checks passed, PoV dead{OFF}\n")
        else:
            finding.mark_patched("--- a/f\n+++ b/f\n", RepairLane.LLM)
            finding.record_gate(GateCheck.COMPILES, True)
            finding.record_gate(GateCheck.POV_DEAD, True)
            finding.record_gate(GateCheck.DIFFERENTIAL_CORPUS, False,
                                detail="6 corpus inputs changed output",
                                quarantined_inputs=2)
            finding.gate_failed("differential corpus rejected the patch")
            finding.report_only("no candidate cleared the gate in 1 round")
            print(f"           {AMBER}▲ REPORT_ONLY{OFF} "
                  f"{DIM}gate refused the patch; proven report issued, no guess{OFF}\n")

    # --- the precision guarantee, demonstrated rather than asserted ---
    static_only = Finding(
        oracle="semgrep", bug_class="CWE-89", language="java", target="demo-svc",
        message="possible SQL injection (static match, no reproducer)",
        frames=[Frame(symbol="UserDao.find", uri="com/example/dao/UserDao.java", line=71)],
    )
    findings.append(static_only)
    print(f"  {BOLD}{'static':<8}{OFF} {static_only.bug_class:<12} semgrep")
    print(f"  {DIM}         {static_only.message}{OFF}")
    print(f"           {DIM}· SUSPECTED — no reproducer, so it is never reported{OFF}\n")

    card = scorecard(findings).as_dict()

    print(f"{BOLD}Scorecard{OFF}  {DIM}(every number derived from the records){OFF}")
    rows = [
        ("Precision", f"{card['precision']['reports_with_reproducer_pct']}% of reports "
                      f"have a replaying reproducer "
                      f"({card['precision']['unproven_findings_suppressed']} suppressed)"),
        ("", f"{card['precision']['patches_surviving_differential_pct']}% of "
             f"{card['precision']['candidate_patches_gated']} candidate patches survived "
             f"the differential gate"),
        ("Performance", f"{card['performance']['bugs_verified_fixed']} verified fixed, "
                        f"{card['performance']['report_only']} report-only, "
                        f"{card['performance']['findings_reported']} reported of "
                        f"{card['performance']['findings_total']} found"),
        ("Speed", f"median time-to-PoV {card['speed']['median_time_to_pov_seconds']}s, "
                  f"time-to-patch {card['speed']['median_time_to_validated_patch_seconds']}s"),
        ("Scalability", f"{card['scalability']['language_count']} languages: "
                        f"{', '.join(card['scalability']['languages_covered'])}"),
        ("Functionality", f"{card['functionality']['zero_human_input_verified']} fixes with "
                          f"zero human input, "
                          f"{card['functionality']['repair_rounds_total']} repair rounds"),
        ("Resource", f"{card['resource']['zero_inference_fix_pct']}% of fixes cost zero "
                     f"inference"),
        ("Posture", f"network interfaces {card['posture']['network_interfaces']}, "
                    f"cloud calls {card['posture']['cloud_calls']}"),
    ]
    for label, value in rows:
        print(f"  {BOLD}{label:<14}{OFF}{value}")

    distinct = dedup(findings)
    print(f"\n{DIM}  dedup: {len(findings)} records → {len(distinct)} distinct bugs{OFF}")
    print(f"{DIM}  reportable: {len(reportable(findings))} "
          f"(nothing without a replaying reproducer){OFF}")

    out = pathlib.Path("raksha-findings.sarif")
    out.write_text(json.dumps(to_sarif_log(findings), indent=2))
    print(f"{DIM}  wrote {out} — valid SARIF 2.1.0{OFF}\n")
    return 0


if __name__ == "__main__":
    sys.exit(run())
