"""Attack graph — composition of individually-moderate findings into chains, with attack economics.

A leaked credential is "high". An unauthenticated admin endpoint is "high". A deserialisation CVE in
an imported library is "critical but not reached". Read separately, an operator fixes them in
severity order; read together they are one path: log in with the credential, reach the endpoint the
gateway never checks, hand the service the payload the library deserialises. This module reads them
together. Nothing here is a new finding: every node is a finding another lane already proved (status
CONFIRMED or beyond), every edge is a deterministic rule listed below, and a chain is a path through
those edges. The output ranks triage; it never changes a finding's status.

Capabilities (what a finding gives an attacker), from the record's CWE / oracle / reachability:
  credential       secrets lane, CWE-798 / 321 / 259
  unauth-endpoint  service lane, CWE-862 / 489
  rce              CWE-78 / 94 / 917 / 502 / 77 / 95 — for a dependency CVE also when its advisory
                   summary names code execution (OSV files many RCEs under CWE-20 / CWE-1321), and
                   never when the codebase is proven not to import it (`reachability == "not-imported"`)
  memory           CWE-119 / 120 / 121 / 122 / 125 / 787
  info-leak        CWE-200 / 209 / 532
  weak-crypto      CWE-327 / 328 / 326 / 295 / 329 / 757
  authz            CWE-284 / 285 / 863 / 639 / 306

Edge rules (each deterministic; "service" is the top-level directory of the finding's path, and a
credential in an estate-level config directory or at the root is estate-wide):
  1. credential → unauth-endpoint     same service, or the credential is estate-wide config
  2. unauth-endpoint → rce            same service, or the rce is a dependency CVE the estate's code
                                      imports (an unauthenticated gateway fronts every service)
  3. info-leak → credential           same service, or the credential is estate-wide
  4. weak-crypto (CWE-295) → credential  no certificate verification lets an on-path attacker read
                                      the credential in transit: same service or estate-wide
  5. memory → rce                     same service (the same binary, as far as paths can say)

A chain is a path of two or more nodes ending in `rce`, or ending in `authz` / `credential` on a
critical asset (tier "mission-critical" in the registry handed in, or a name in a set of critical
scopes). Attack economics: each step costs by its evidence — exploit-proven 1.0, deterministic match
1.5, unknown reachability 2.0, not-imported 4.0 — and a chain is `viable` when its cost is within the
budget (default 6.0). Ids are the hash of the sorted finding ids, so two runs over the same findings
agree. Edges are computed pairwise, O(n²); chains are the cheapest path from each node over the
layered DAG the rules form (so a long chain and its cheaper tail both appear, each a real option for
an attacker starting with that capability), at most n chains, each O(depth) to rebuild — O(n²) in all.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .finding import DETERMINISTIC_MATCH, EXPLOIT_REPLAY, Finding, Status

DEFAULT_BUDGET = 6.0

_CRED_CWE = {"CWE-798", "CWE-321", "CWE-259"}
_UNAUTH_CWE = {"CWE-862", "CWE-489"}
_RCE_CWE = {"CWE-78", "CWE-94", "CWE-917", "CWE-502", "CWE-77", "CWE-95"}
_MEMORY_CWE = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787"}
_LEAK_CWE = {"CWE-200", "CWE-209", "CWE-532"}
_CRYPTO_CWE = {"CWE-327", "CWE-328", "CWE-326", "CWE-295", "CWE-329", "CWE-757"}
_AUTHZ_CWE = {"CWE-284", "CWE-285", "CWE-863", "CWE-639", "CWE-306"}
_RCE_WORDS = re.compile(r"(?i)\b(?:remote|arbitrary)\s+code\s+execution\b|\bcommand injection\b|\bRCE\b")
_CONFIG_DIRS = {"config", "conf", "configs", "deploy", "env", "infra", "k8s", "helm", "etc", ""}

#: Capability ordering: every edge rule goes strictly forward in this order, so the graph is a DAG.
_ORDER = {"info-leak": 0, "weak-crypto": 0, "memory": 0, "credential": 1, "unauth-endpoint": 2,
          "authz": 3, "rce": 3}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_RANK_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def capability(f: Finding) -> str | None:
    """The capability a finding grants, or None when it composes with nothing (then it is no node)."""
    cwe = f.bug_class
    if f.oracle.startswith("secrets:") or cwe in _CRED_CWE:
        return "credential"
    if f.oracle.startswith("service:") or cwe in _UNAUTH_CWE:
        return "unauth-endpoint"
    is_dep = f.oracle == "osv:version-match"
    if cwe in _RCE_CWE or (is_dep and _RCE_WORDS.search(f.message or "")):
        if is_dep and f.reachability == "not-imported":
            return None                         # proven present, proven not reached: not a step
        return "rce"
    if cwe in _MEMORY_CWE:
        return "memory"
    if cwe in _LEAK_CWE:
        return "info-leak"
    if cwe in _CRYPTO_CWE:
        return "weak-crypto"
    if cwe in _AUTHZ_CWE:
        return "authz"
    return None


def step_cost(f: Finding) -> float:
    """Attack economics per step, from the evidence on the record."""
    if f.reachability == "not-imported":
        return 4.0
    if f.reachability == "unknown":
        return 2.0
    if f.reproducer is not None and f.reproducer.kind == EXPLOIT_REPLAY:
        return 1.0
    if f.reproducer is not None and f.reproducer.kind == DETERMINISTIC_MATCH:
        # G6: a dependency step is priced by measured exploitation data where the offline snapshots
        # have it — CISA KEV (exploited in the wild) costs what a proven exploit costs; otherwise
        # FIRST EPSS maps 1.0 (certain exploitation) .. 2.0 (none). Without data: the 1.5 prior.
        if getattr(f, "kev", False):
            return 1.0
        epss = getattr(f, "epss", None)
        if isinstance(epss, (int, float)):
            return round(1.0 + (1.0 - max(0.0, min(1.0, float(epss)))), 2)
        return 1.5
    return 2.0


def service_of(f: Finding) -> str:
    """Top-level directory of the finding's path: the service it belongs to within the estate. A
    bare target name (a deep-lane finding records its target, e.g. `c-nolibfuzzer`) is its own
    service; a bare file name (`app.properties`) sits at the estate root."""
    path = (f.target or "").strip("/")
    if "/" in path:
        return path.split("/", 1)[0]
    return path if path and "." not in path else ""


def estate_wide(f: Finding) -> bool:
    """A credential in estate-level config (or at the root) is one every service may use."""
    return service_of(f).lower() in _CONFIG_DIRS


@dataclass(frozen=True)
class Node:
    finding_id: str
    capability: str
    service: str
    severity: str
    cost: float
    oracle: str
    cwe: str
    target: str
    reachability: str | None = None
    estate_wide: bool = False

    def as_dict(self) -> dict:
        return {"finding_id": self.finding_id, "capability": self.capability, "service": self.service,
                "severity": self.severity, "cost": self.cost, "oracle": self.oracle, "cwe": self.cwe,
                "target": self.target}


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    rule: str


@dataclass
class Chain:
    id: str
    finding_ids: list[str]
    steps: list[str]
    combined_severity: str
    cost: float
    viable: bool

    def as_dict(self) -> dict:
        return {"id": self.id, "finding_ids": list(self.finding_ids), "steps": list(self.steps),
                "combined_severity": self.combined_severity, "cost": self.cost, "viable": self.viable}


@dataclass
class AttackGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)
    findings_in: int = 0
    budget: float = DEFAULT_BUDGET

    def summary(self) -> dict:
        viable = [c for c in self.chains if c.viable]
        cheapest = min(self.chains, key=lambda c: (c.cost, c.id)) if self.chains else None
        return {
            "findings": self.findings_in,
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "chains": len(self.chains),
            "viable_chains": len(viable),
            "cheapest_path": ({"id": cheapest.id, "cost": cheapest.cost, "steps": list(cheapest.steps)}
                              if cheapest else None),
            "budget": self.budget,
        }

    def as_dict(self) -> dict:
        return {"nodes": [n.as_dict() for n in self.nodes.values()],
                "edges": [{"src": e.src, "dst": e.dst, "rule": e.rule} for e in self.edges],
                "chains": [c.as_dict() for c in self.chains], "summary": self.summary()}


def _edge_rule(a: Node, b: Node) -> str | None:
    same = a.service == b.service
    if a.capability == "credential" and b.capability == "unauth-endpoint":
        if same or a.estate_wide:
            return "1 credential→unauth-endpoint (same service / estate-wide credential)"
    elif a.capability == "unauth-endpoint" and b.capability == "rce":
        if same:
            return "2 unauth-endpoint→rce (same service)"
        if b.oracle == "osv:version-match" and b.reachability == "imported":
            return "2 unauth-endpoint→rce (gateway fronts an imported dependency CVE)"
    elif a.capability == "info-leak" and b.capability == "credential":
        if same or b.estate_wide:
            return "3 info-leak→credential (same service / estate-wide credential)"
    elif a.capability == "weak-crypto" and a.cwe == "CWE-295" and b.capability == "credential":
        if same or b.estate_wide:
            return "4 no-cert-verify→credential (credential readable in transit)"
    elif a.capability == "memory" and b.capability == "rce":
        if same:
            return "5 memory→rce (same binary)"
    return None


def _critical(node: Node, assets, critical_scopes: frozenset[str]) -> bool:
    if node.service in critical_scopes or node.target in critical_scopes:
        return True
    lookup = getattr(assets, "lookup", None)
    if lookup is None:
        return False
    for name in (node.target, node.service):
        asset = lookup(name) if name else None
        if asset is not None and getattr(asset, "tier", None) == "mission-critical":
            return True
    return False


def _chain_id(finding_ids: list[str]) -> str:
    return "chain-" + hashlib.sha256("|".join(sorted(finding_ids)).encode()).hexdigest()[:12]


def build(findings: list[Finding], *, assets=None, budget: float = DEFAULT_BUDGET,
          critical_scopes: frozenset[str] | set[str] = frozenset()) -> AttackGraph:
    """Nodes from every reportable finding with a capability, edges by the rules, chains by cost.

    `assets` is anything with `lookup(name) -> object with .tier` (the asset registry);
    `critical_scopes` is a plain set of service / target names for callers without one.
    """
    graph = AttackGraph(findings_in=len(findings), budget=budget)
    critical = frozenset(critical_scopes)
    for f in findings:
        if f.status is Status.SUSPECTED:
            continue                              # unproven findings are not steps in anything
        cap = capability(f)
        if cap is None:
            continue
        graph.nodes[f.id] = Node(f.id, cap, service_of(f), f.severity, step_cost(f), f.oracle, f.bug_class,
                                 f.target, f.reachability, estate_wide(f))
    ordered = sorted(graph.nodes.values(), key=lambda n: (_ORDER[n.capability], n.finding_id))
    for a in ordered:                              # pairwise: O(n²), the documented bound
        for b in ordered:
            if a.finding_id == b.finding_id or _ORDER[a.capability] >= _ORDER[b.capability]:
                continue
            rule = _edge_rule(a, b)
            if rule:
                graph.edges.append(Edge(a.finding_id, b.finding_id, rule))

    succ: dict[str, list[str]] = {n: [] for n in graph.nodes}
    for e in graph.edges:
        succ[e.src].append(e.dst)

    def terminal(n: Node) -> bool:
        return n.capability == "rce" or (n.capability in ("authz", "credential") and _critical(n, assets, critical))

    # Cheapest path to a terminal, by DP in reverse capability order (the rules form a layered DAG).
    best: dict[str, tuple[float, list[str]]] = {}
    for n in sorted(ordered, key=lambda n: (-_ORDER[n.capability], n.finding_id)):
        options: list[tuple[float, list[str]]] = []
        if terminal(n):
            options.append((n.cost, [n.finding_id]))
        for s in sorted(succ[n.finding_id]):
            if s in best:
                cost, path = best[s]
                options.append((n.cost + cost, [n.finding_id, *path]))
        if options:
            best[n.finding_id] = min(options, key=lambda o: (o[0], o[1]))

    for n in ordered:                             # one chain per start node: the cheapest from it
        if n.finding_id not in best:
            continue
        cost, path = best[n.finding_id]
        if len(path) < 2:
            continue
        nodes = [graph.nodes[i] for i in path]
        sev = max(_SEVERITY_RANK.get(x.severity, 0) for x in nodes)
        if nodes[-1].capability == "rce" and len(path) >= 3:
            sev = 4                               # three proven steps to code execution is critical
        steps = [f"{x.capability} ({x.oracle}, {x.cwe}, {x.target})" for x in nodes]
        graph.chains.append(Chain(_chain_id(path), list(path), steps, _RANK_SEVERITY[sev],
                                  round(cost, 2), cost <= budget))
    graph.chains.sort(key=lambda c: (c.cost, c.id))
    return graph


def annotate(findings: list[Finding], graph: AttackGraph) -> None:
    """Stamp each finding with the ids of the chains it is a link of (sorted, deduplicated)."""
    by_finding: dict[str, set[str]] = {}
    for c in graph.chains:
        for fid in c.finding_ids:
            by_finding.setdefault(fid, set()).add(c.id)
    for f in findings:
        f.chain_ids = sorted(by_finding.get(f.id, set()))
