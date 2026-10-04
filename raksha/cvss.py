"""G7 — a severity vector and an attack-technique / defence mapping per finding, DERIVED and labelled so.

A cyber cell speaks CVSS and ATT&CK. Every finding gets, deterministically from its own record:

* a **CVSS 4.0 base vector** (``CVSS:4.0/AV:../AC:../AT:../PR:../UI:../VC:../VI:../VA:../SC:../SI:../SA:..``).
  The 4.0 *score* is defined by FIRST's MacroVector lookup table, which is not bundled; the score is
  therefore reported as not computed rather than approximated.
* a **CVSS 3.1 base vector and its exact base score**, whose formula is closed-form (FIRST CVSS v3.1
  specification, section 7), so it is computed, not estimated.
* **MITRE ATT&CK Enterprise technique IDs** for how an adversary would use the weakness, and the
  **D3FEND tactic** (Harden / Detect / Isolate / Deceive / Evict / Restore) the fix belongs to with a
  plain statement of what the fix does.

Each record carries ``derived: true`` and the ``basis`` — the reasons each metric took its value — so
nobody mistakes it for an assessed score. The rules are coarse by design (CWE family, the evidence
lane, the asset's declared exposure); an analyst can override any metric, and the basis says what to
check. Nothing here changes status or severity.
"""

from __future__ import annotations

import math

from .cwe import family
from .finding import DETERMINISTIC_MATCH, EXPLOIT_REPLAY, Finding

# ---------------------------------------------------------------- impact by family
#: (confidentiality, integrity, availability) on the vulnerable system, and the subsequent-system
#: impact (SC, SI, SA) for 4.0. H / L / N.
_IMPACT = {
    "memory": ("H", "H", "H", "N", "N", "N"),
    "numeric": ("H", "H", "H", "N", "N", "N"),
    "index": ("H", "N", "H", "N", "N", "N"),
    "use-after-free": ("H", "H", "H", "N", "N", "N"),
    "pointer": ("N", "N", "H", "N", "N", "N"),
    "uninitialised": ("L", "N", "L", "N", "N", "N"),
    "alloc": ("N", "N", "L", "N", "N", "N"),
    "injection": ("H", "H", "H", "L", "L", "L"),
    "deserialization": ("H", "H", "H", "L", "L", "L"),
    "path-traversal": ("H", "N", "N", "N", "N", "N"),
    "ssrf": ("L", "L", "N", "L", "L", "N"),
    "xss": ("L", "L", "N", "N", "N", "N"),
    "crypto": ("L", "L", "N", "N", "N", "N"),
    "cert": ("H", "H", "N", "N", "N", "N"),
    "authz": ("H", "L", "N", "N", "N", "N"),
    "authn": ("H", "H", "L", "L", "L", "N"),
    "dos": ("N", "N", "H", "N", "N", "N"),
    "info-leak": ("L", "N", "N", "N", "N", "N"),
    "race": ("L", "L", "L", "N", "N", "N"),
    "config": ("L", "L", "N", "N", "N", "N"),
    "api-design": ("L", "L", "L", "N", "N", "N"),
}
#: CWE codes that read memory out of bounds (no write): integrity is not hit.
_READ_ONLY = {"CWE-125", "CWE-126", "CWE-127"}

_ATTACK = {
    "injection": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "deserialization": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "memory": [("T1203", "Exploitation for Client Execution")],
    "numeric": [("T1203", "Exploitation for Client Execution")],
    "index": [("T1203", "Exploitation for Client Execution")],
    "use-after-free": [("T1203", "Exploitation for Client Execution")],
    "path-traversal": [("T1190", "Exploit Public-Facing Application"), ("T1005", "Data from Local System")],
    "ssrf": [("T1190", "Exploit Public-Facing Application")],
    "authz": [("T1190", "Exploit Public-Facing Application")],
    "config": [("T1190", "Exploit Public-Facing Application")],
    "authn": [("T1552.001", "Unsecured Credentials: Credentials In Files"), ("T1078", "Valid Accounts")],
    "cert": [("T1557", "Adversary-in-the-Middle")],
    "crypto": [("T1557", "Adversary-in-the-Middle"), ("T1110.002", "Brute Force: Password Cracking")],
    "dos": [("T1499.004", "Endpoint Denial of Service: Application or System Exploitation")],
    "alloc": [("T1499.004", "Endpoint Denial of Service: Application or System Exploitation")],
    "info-leak": [("T1005", "Data from Local System")],
}
#: D3FEND tactic and the plain action, by family.
_DEFENCE = {
    "memory": ("Harden", "bound the copy/index to the buffer's size (application hardening)"),
    "numeric": ("Harden", "check the arithmetic before it is used as a size or index"),
    "index": ("Harden", "bound the index to the container's length"),
    "use-after-free": ("Harden", "end the object's use before it is released"),
    "injection": ("Harden", "pass arguments as a list, never through a shell or interpreter"),
    "deserialization": ("Harden", "replace native deserialisation of untrusted data with a safe format"),
    "path-traversal": ("Harden", "canonicalise the path and confine it to the intended root"),
    "authn": ("Evict", "remove the credential from code and history, rotate it, load it from a vault"),
    "cert": ("Harden", "enable certificate verification"),
    "crypto": ("Harden", "move to a current algorithm / key size"),
    "authz": ("Harden", "require authorisation on the endpoint"),
    "config": ("Harden", "disable the debug/unsafe setting in production"),
    "dos": ("Harden", "bound the work an input can cause (timeouts, linear-time matching)"),
    "alloc": ("Harden", "release the resource on every path"),
}


def _exposure(f: Finding) -> tuple[str, str]:
    """(AV value, reason)."""
    declared = getattr(f, "exposure", None)
    if declared in ("network", "adjacent", "local", "physical"):
        return {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}[declared], \
            f"asset declares exposure '{declared}'"
    o = f.oracle
    if o.startswith(("osv:", "service:", "binary:version")):
        return "N", "a dependency or API of a deployed service: assumed network-reachable"
    if o.startswith("crypto:"):
        return "N", "weak cryptography in a service is attacked on the wire or on captured data"
    if o.startswith(("secrets:", "githistory:")):
        return "N", "a credential is usable from wherever the service it unlocks is reachable"
    if o.startswith(("js", "jazzer", "interpose", "behaviour")):
        return "N", "a service-side sink reached through its request input"
    return "L", "input arrives as a file/buffer; network exposure not established on the record"


def _metrics(f: Finding) -> tuple[dict, list[str]]:
    fam = family(f.bug_class)
    basis = []
    av, why = _exposure(f)
    basis.append(f"AV:{av} — {why}")
    proven = f.reproducer is not None and f.reproducer.kind in (EXPLOIT_REPLAY, DETERMINISTIC_MATCH)
    reach = getattr(f, "reachability", None)
    ac = "L" if proven and reach != "not-imported" else "H"
    if fam in ("crypto", "cert"):
        ac = "H"
        basis.append("AC:H — needs a network position (interception) or offline computation")
    else:
        basis.append("AC:L — a replaying reproducer / deterministic match exists" if ac == "L"
                     else "AC:H — not reproduced, or the vulnerable code is not imported")
    at = "P" if (f.contract or reach in ("not-imported", "unknown")) else "N"
    basis.append("AT:P — a precondition or unknown reachability stands in the way" if at == "P"
                 else "AT:N — no attack precondition on the record")
    pr, ui = "N", "N"
    basis.append("PR:N, UI:N — the reproducer needed no privilege or user action")
    vc, vi, va, sc, si, sa = _IMPACT.get(fam or "", ("L", "L", "L", "N", "N", "N"))
    if f.bug_class in _READ_ONLY:
        vi = "N"
    basis.append(f"impact from the CWE family '{fam or 'unmapped'}'"
                 + (" (out-of-bounds read: no integrity impact)" if f.bug_class in _READ_ONLY else ""))
    return {"AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui, "VC": vc, "VI": vi, "VA": va,
            "SC": sc, "SI": si, "SA": sa}, basis


# ---------------------------------------------------------------- CVSS 3.1 (closed form)

_W31 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    """CVSS v3.1 Appendix A Roundup: the smallest number, to one decimal, >= x."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31(m: dict) -> dict:
    scope_changed = any(m[k] != "N" for k in ("SC", "SI", "SA"))
    s = "C" if scope_changed else "U"
    pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
    ui = "R" if m["UI"] != "N" else "N"
    ac = "H" if (m["AC"] == "H" or m["AT"] == "P") else "L"        # 3.1 folds AT into AC
    c, i, a = _W31["CIA"][m["VC"]], _W31["CIA"][m["VI"]], _W31["CIA"][m["VA"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    expl = 8.22 * _W31["AV"][m["AV"]] * _W31["AC"][ac] * pr * _W31["UI"][ui]
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + expl), 10))
    else:
        score = _roundup(min(impact + expl, 10))
    sev = ("None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7
           else "High" if score < 9 else "Critical")
    vec = (f"CVSS:3.1/AV:{m['AV']}/AC:{ac}/PR:{m['PR']}/UI:{ui}/S:{s}/"
           f"C:{m['VC']}/I:{m['VI']}/A:{m['VA']}")
    return {"vector": vec, "base_score": score, "severity": sev}


# ---------------------------------------------------------------- public

def derive(f: Finding) -> dict:
    m, basis = _metrics(f)
    v4 = "CVSS:4.0/" + "/".join(f"{k}:{m[k]}" for k in
                                ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"))
    return {"derived": True, "cvss40": {"vector": v4, "score": None,
                                        "score_note": "4.0 scores come from FIRST's MacroVector table, "
                                                      "which is not bundled; not approximated"},
            "cvss31": cvss31(m), "basis": basis}


def attack_map(f: Finding) -> dict:
    fam = family(f.bug_class)
    techniques = [{"id": t, "name": n} for t, n in _ATTACK.get(fam or "", [])]
    if f.oracle.startswith(("osv:", "binary:version")) and not any(t["id"] == "T1190" for t in techniques):
        techniques.insert(0, {"id": "T1190", "name": "Exploit Public-Facing Application"})
    if _exposure(f)[0] == "N" and fam in ("memory", "numeric", "index", "use-after-free"):
        techniques.insert(0, {"id": "T1190", "name": "Exploit Public-Facing Application"})
    tactic, action = _DEFENCE.get(fam or "", (None, None))
    return {"derived": True, "attack": techniques,
            "defence": ({"d3fend_tactic": tactic, "action": action} if tactic else None),
            "note": None if techniques else "no direct ATT&CK technique for this weakness family"}
