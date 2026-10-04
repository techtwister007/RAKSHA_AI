"""Phase 7 — the three WOW beats, each on real mechanisms: `python -m raksha.slice_wow`

  1. Public rejection of a bad patch — a deliberately overfitting "fix" that silences the exact
     reproducer and leaves the hole open; the gate refuses it on its own terms (a fresh campaign
     finds the siblings). No other team demos a failure, which is exactly why it lands.
  2. ROE slider — the same verified fix on an Important asset deploys after one approval; flip the
     asset to Critical and it now waits for two officers' signatures. Confidence buys autonomy.
  3. Vulnerability Vaccine — the verified fix becomes a detection rule that must pass three checks
     of its own, then sweeps a fleet and finds the same mistake in other codebases.

Each beat returns structured data the console renders; nothing here is narrated-only.
"""

from __future__ import annotations

import difflib
import pathlib
import sys

from . import roe, vaccine
from .adapters.python_sink import python_target
from .finding import Finding, GateCheck, RepairLane, Reproducer, ReplayResult, utcnow
from .gate import decide, run_gate
from .oracles import PySecSanOracle
from .slice_three import run_python

ROOT = pathlib.Path(__file__).parents[1]
PY = ROOT / "demo-targets" / "py-cmdinject"
G, A, R, D, B, O = "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


# ---------------------------------------------------------------- beat 1: reject a bad patch

def overfitting_patch(runner_src: str, reproducer: str) -> str:
    """A patch that special-cases the exact reproducer and leaves the sink for everything else."""
    before = runner_src
    sink = '    cmd = "echo handling " + name                 # BUG: input interpolated into a shell line\n'
    guard = (f'    if name == {reproducer!r}:\n'
             f'        return []                                 # OVERFIT: silences the one reproducer\n'
             + sink)
    after = before.replace(sink, guard)
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile="a/app/runner.py", tofile="b/app/runner.py"))


def reject_bad_patch() -> dict:
    target = python_target(PY)
    repro = b"status; rm -rf /tmp/x"
    hunt = target.build(None)
    f = PySecSanOracle().parse(target.run(hunt, repro).text, target="py-cmdinject")[0]
    target.discard(hunt)
    f.attach_reproducer(Reproducer.from_bytes(repro, ["python3", "fuzz_cmd.py", "repro"], minimised=True))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow(), abort_signature=f.abort_signature, exit_code=77))
    f.confirm()
    f.mark_patched(overfitting_patch((PY / "app" / "runner.py").read_text(), repro.decode()), RepairLane.LLM)
    verdict = run_gate(f, target, reproducer=repro,
                       corpus=[b"status", b"report", b"deploy", b"health"], refuzz_seconds=5)
    decide(f, verdict)
    return {
        "rejected": not verdict.passed,
        "failed_check": verdict.failed_check.value if verdict.failed_check else None,
        "detail": verdict.detail,
        "refuzz_findings": verdict.refuzz_findings,
        "final_status": f.status.value,
        "gate": {c.value: f.gate[c].passed for c in GateCheck if c in f.gate},
    }


# ---------------------------------------------------------------- beat 2: the ROE slider

def roe_slider(verified: Finding) -> dict:
    out = {}
    for tier in (roe.AssetTier.ROUTINE, roe.AssetTier.IMPORTANT, roe.AssetTier.CRITICAL,
                 roe.AssetTier.MISSION_CRITICAL):
        asset = roe.Asset(name=f"{tier.name.lower()}-asset", tier=tier)
        d = roe.effective_roe(asset, verified)
        one_sig = [roe.Signature("Maj A", "k1")]
        two_sig = [roe.Signature("Maj A", "k1"), roe.Signature("Capt B", "k2")]
        out[tier.name] = {
            "decision": d.as_dict(),
            "with_one_signature": roe.may_deploy(d, one_sig),
            "with_two_signatures": roe.may_deploy(d, two_sig),
        }
    return out


# ---------------------------------------------------------------- beat 3: the vaccine

def vaccine_sweep(verified: Finding) -> dict:
    rule = vaccine.extract_rule(verified)
    if rule is None:
        return {"error": "no rule could be mined for this bug class"}
    vulnerable = 'subprocess.run(cmd, shell=True, capture_output=True, text=True)\n'
    fixed = 'subprocess.run(cmd, shell=False, capture_output=True, text=True)\n'
    clean = ['print("hello")\n', 'subprocess.run(["ls","-l"])\n', 'x = 1 + 2\n']
    proof = vaccine.prove_rule(rule, vulnerable_sample=vulnerable, fixed_sample=fixed, clean_corpus=clean)
    fleet = _vaccine_fleet()
    hits = vaccine.sweep(rule, fleet) if proof.passed else []
    return {
        "rule_id": rule.id, "description": rule.description,
        "proof": proof.as_dict(),
        "hits": [{"target": h.target, "path": h.path, "line": h.line} for h in hits],
        "fleet_size": len(fleet),
    }


def _vaccine_fleet() -> dict:
    """The sister codebases of the estate (demo-targets/fleet): the sweep reads them, never writes."""
    base = ROOT / "demo-targets" / "fleet"
    return {p.name: p for p in sorted(base.iterdir()) if p.is_dir()}


# ---------------------------------------------------------------- runner

def run() -> int:
    print(f"\n{B}RAKSHA AI — the three WOW beats{O}\n")

    print(f"{B}1 · Public rejection of a bad patch{O}")
    r1 = reject_bad_patch()
    mark = G + "REJECTED" + O if r1["rejected"] else R + "ACCEPTED (!)" + O
    print(f"   overfitting fix → gate {mark} at {r1['failed_check']} "
          f"({r1['refuzz_findings']} siblings found) → finding stays {r1['final_status']}")

    print(f"\n{B}2 · ROE slider — same proven fix, different authority per asset{O}")
    verified = run_python()
    r2 = roe_slider(verified)
    for tier, info in r2.items():
        d = info["decision"]
        print(f"   {tier:16} cap {d['cap']} → effective {d['effective']:3} "
              f"{'· two-person rule' if d['two_person'] else ''}")
    crit = r2["CRITICAL"]
    print(f"   {D}critical asset with one signature: {crit['with_one_signature'][1]}{O}")
    print(f"   {D}critical asset with two signatures: {crit['with_two_signatures'][1]}{O}")

    print(f"\n{B}3 · Vulnerability Vaccine — one fix, fleet-wide immunity{O}")
    r3 = vaccine_sweep(verified)
    p = r3["proof"]
    print(f"   rule mined: {r3['description']}")
    print(f"   rule proof: hits-original={p['hits_original']} misses-fix={p['misses_fix']} "
          f"low-noise={p['low_noise']} → {G+'PROVEN'+O if p['passed'] else R+'DISCARDED'+O}")
    print(f"   swept {r3['fleet_size']} codebases → same mistake in "
          f"{len({h['target'] for h in r3['hits']})} others:")
    for h in r3["hits"]:
        print(f"     {A}·{O} {h['target']}/{h['path']}:{h['line']}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
