"""J8 — the internal-CERT advisory: one verified fix becomes a signed, numbered advisory.

This is the product framing. A national-level CERT does not ship "a finding"; it ships an advisory
with an identifier, the affected assets, how bad it is, and the remedy. RAKSHA can issue one only
for what it has proven: a VERIFIED finding whose patch passed all five gate checks. Everything in the
advisory is read from that record and the asset registry — nothing is typed by hand:

  id              RAKSHA-CERT-<year>-<NNNN>, numbered sequentially within the advisory directory
  affected        the asset the finding is on, plus every other finding in the session with the
                  same defect signature (the fleet variants), each with its registry tier, mission
                  function and owner unit
  severity        the record's severity, the derived CVSS 3.1 score/vector and the 4.0 vector,
                  ATT&CK techniques and the D3FEND counter (all labelled derived)
  proof           the five gate results, the red-team round, the reproducer's sha256 (never its
                  bytes), and the sealed evidence bundle's manifest hash when one was built
  remedy          the exact proven patch, and the rollback note

Signed like the evidence bundle (HMAC over the canonical body with the deployment key, plus the
post-quantum signature when the library is present). `verify_advisory()` recomputes it; one changed
byte fails. ``python -m raksha.advisory verify DIR`` is the judge-side check.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .finding import GATE_ORDER, Finding, Status

ADVISORY = "advisory.json"
TEXT = "advisory.md"
SIGNATURE = "advisory.sig.json"
_ID_RE = re.compile(r"^RAKSHA-CERT-(\d{4})-(\d{4})$")


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def next_id(advisory_root: str | Path, *, year: int | None = None) -> str:
    """The next sequential id for `year` among advisories already under `advisory_root`."""
    year = year or datetime.now(timezone.utc).year
    root = Path(advisory_root)
    taken = 0
    if root.is_dir():
        for p in root.iterdir():
            m = _ID_RE.match(p.name)
            if m and int(m.group(1)) == year:
                taken = max(taken, int(m.group(2)))
    return f"RAKSHA-CERT-{year}-{taken + 1:04d}"


def _asset_row(name: str | None, registry) -> dict:
    a = registry.lookup(name or "") if (registry is not None and name) else None
    return {"target": name, "asset": a.name if a else None, "tier": a.tier if a else "unclassified",
            "mission_function": a.mission_function if a else None, "owner_unit": a.owner_unit if a else None}


def affected(finding: Finding, others=(), registry=None) -> list[dict]:
    """The asset this finding is on, then every distinct target carrying the same defect."""
    from .signature import same_defect
    rows = [dict(_asset_row(finding.target, registry), finding=finding.id, status=finding.status.value,
                 basis="the verified finding")]
    seen = {finding.target}
    for o in others:
        if o.id == finding.id or o.target in seen:
            continue
        try:
            same = same_defect(o, finding)
        except Exception:  # noqa: BLE001
            same = False
        if same:
            seen.add(o.target)
            rows.append(dict(_asset_row(o.target, registry), finding=o.id, status=o.status.value,
                             basis="same defect signature"))
    return rows


def body_for(finding: Finding, *, advisory_id: str, others=(), registry=None,
             bundle_manifest_sha256: str | None = None) -> dict:
    if finding.status is not Status.VERIFIED or not finding.patch_diff:
        raise ValueError("an advisory is issued only for a VERIFIED finding with a proven patch")
    if not finding.gate_passed:
        raise ValueError("the finding's gate record is incomplete; no advisory")
    from .brief import plain_summary
    from .cvss import attack_map, derive
    try:
        sev = derive(finding)
    except Exception:  # noqa: BLE001
        sev = None
    try:
        att = attack_map(finding)
    except Exception:  # noqa: BLE001
        att = None
    site = finding.fix_site_set[0] if finding.fix_site_set else None
    return {
        "schema": "raksha-cert-advisory/1",
        "id": advisory_id,
        "issued": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "title": f"{finding.bug_class} in {finding.target}"
                 + (f" ({site.uri}{':' + str(site.start_line) if site.start_line else ''})" if site else ""),
        "classification": "RESTRICTED — internal distribution",
        "finding": {"id": finding.id, "oracle": finding.oracle, "bug_class": finding.bug_class,
                    "language": finding.language, "severity": finding.severity,
                    "message": finding.message},
        "summary": plain_summary(finding),
        "affected": affected(finding, others, registry),
        "severity": {"record": finding.severity, "derived": sev, "attack": att},
        "proof": {
            "gate": {c.value: {"passed": finding.gate[c].passed, "detail": finding.gate[c].detail}
                     for c in GATE_ORDER if c in finding.gate},
            "red_team": finding.red_team,
            "reproducer_sha256": finding.reproducer.artifact_sha256 if finding.reproducer else None,
            "replay_cmd": finding.reproducer.replay_cmd if finding.reproducer else None,
            "evidence_bundle_manifest_sha256": bundle_manifest_sha256,
            "bound_proof": finding.bound_proof, "rollback_proof": finding.rollback_proof,
        },
        "remedy": {"lane": finding.repair_lane.value if finding.repair_lane else None,
                   "patch_diff": finding.patch_diff,
                   "patch_sha256": hashlib.sha256(finding.patch_diff.encode()).hexdigest(),
                   "rollback": "reverse-apply the patch (the evidence bundle ships rollback.sh); "
                               "the rollback is proven byte-identical where rollback_proof is present"},
        "roe_level": finding.roe_level.value,
    }


def render_text(body: dict) -> str:
    L = [f"# {body['id']} — {body['title']}", "", f"*{body['classification']}* · issued {body['issued']}", "",
         "## Summary", "", body["summary"], "", "## Affected assets", "",
         "| target | asset | tier | mission function | owner | basis |", "|---|---|---|---|---|---|"]
    for a in body["affected"]:
        L.append(f"| {a['target']} | {a['asset'] or '—'} | {a['tier']} | {a['mission_function'] or '—'} | "
                 f"{a['owner_unit'] or '—'} | {a['basis']} |")
    d = (body["severity"].get("derived") or {}).get("cvss31") or {}
    L += ["", "## Severity", "", f"- record: **{body['severity']['record']}**"]
    if d:
        L.append(f"- CVSS 3.1 (derived): {d.get('score')} `{d.get('vector')}`")
    att = body["severity"].get("attack") or {}
    if att.get("attack"):
        L.append("- ATT&CK: " + ", ".join(f"{t['id']} {t['name']}" for t in att["attack"]))
    L += ["", "## Proof", ""]
    for c, g in body["proof"]["gate"].items():
        L.append(f"- {c}: {'pass' if g['passed'] else 'FAIL'} — {g.get('detail') or ''}")
    rt = body["proof"].get("red_team")
    if rt:
        L.append(f"- red team: {'held' if rt.get('held') else 'BROKE THE FIX'} over {rt.get('attempts')} attempts")
    L.append(f"- reproducer sha256: `{body['proof']['reproducer_sha256']}`")
    L += ["", "## Remedy (the proven patch)", "", "```diff", body["remedy"]["patch_diff"].rstrip(), "```", "",
          body["remedy"]["rollback"], ""]
    return "\n".join(L)


def issue(finding: Finding, advisory_root: str | Path, *, others=(), registry=None,
          bundle_dir: str | Path | None = None, key: bytes | None = None,
          advisory_id: str | None = None) -> Path:
    """Write and sign the advisory under `advisory_root/<id>/`. Returns that directory."""
    from .bundle import signing_key
    root = Path(advisory_root)
    aid = advisory_id or next_id(root)
    msha = None
    if bundle_dir is not None and (Path(bundle_dir) / "bundle.json").is_file():
        msha = hashlib.sha256((Path(bundle_dir) / "bundle.json").read_bytes()).hexdigest()
    body = body_for(finding, advisory_id=aid, others=others, registry=registry, bundle_manifest_sha256=msha)
    out = root / aid
    out.mkdir(parents=True, exist_ok=False)
    body_bytes = json.dumps(body, indent=2, sort_keys=True).encode()
    text = render_text(body).encode()
    (out / ADVISORY).write_bytes(body_bytes)
    (out / TEXT).write_bytes(text)
    k, key_id = (key, "caller") if key is not None else signing_key()
    material = _material(body_bytes, text)
    sig = {"alg": "HMAC-SHA256", "key_id": key_id, "id": aid,
           "advisory_sha256": hashlib.sha256(body_bytes).hexdigest(),
           "text_sha256": hashlib.sha256(text).hexdigest(),
           "signature": hmac.new(k, material, hashlib.sha256).hexdigest()}
    try:
        from . import pqsign
        sig["pq"] = pqsign.sign(material, k)
    except Exception:  # noqa: BLE001 — additive
        pass
    (out / SIGNATURE).write_text(json.dumps(sig, indent=2, sort_keys=True))
    return out


def _material(body_bytes: bytes, text: bytes) -> bytes:
    return (f"{ADVISORY}={hashlib.sha256(body_bytes).hexdigest()}\n"
            f"{TEXT}={hashlib.sha256(text).hexdigest()}").encode()


def verify_advisory(adv_dir: str | Path, *, key: bytes | None = None) -> tuple[bool, list[str]]:
    from .bundle import _DEMO_KEY, signing_key
    d = Path(adv_dir)
    problems: list[str] = []
    try:
        body_bytes = (d / ADVISORY).read_bytes()
        text = (d / TEXT).read_bytes()
        sig = json.loads((d / SIGNATURE).read_text())
        body = json.loads(body_bytes)
    except (OSError, ValueError) as e:
        return False, [f"missing or malformed advisory ({e})"]
    if key is None:
        key = _DEMO_KEY if sig.get("key_id", "demo") == "demo" else signing_key()[0]
    if hashlib.sha256(body_bytes).hexdigest() != sig.get("advisory_sha256"):
        problems.append(f"CHANGED {ADVISORY}")
    if hashlib.sha256(text).hexdigest() != sig.get("text_sha256"):
        problems.append(f"CHANGED {TEXT}")
    want = hmac.new(key, _material(body_bytes, text), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(sig.get("signature", ""))):
        problems.append("SIGNATURE INVALID")
    if body.get("id") != sig.get("id") or body.get("id") != d.name:
        problems.append("id mismatch between directory, body and signature")
    if hashlib.sha256((body.get("remedy", {}).get("patch_diff") or "").encode()).hexdigest() \
            != body.get("remedy", {}).get("patch_sha256"):
        problems.append("patch hash mismatch inside the advisory")
    return not problems, problems


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m raksha.advisory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify"); v.add_argument("dir")
    a = ap.parse_args(argv)
    ok, problems = verify_advisory(a.dir)
    print("advisory signature valid; body, text and patch unchanged" if ok else
          "VERIFICATION FAILED:\n" + "\n".join("  " + p for p in problems))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
