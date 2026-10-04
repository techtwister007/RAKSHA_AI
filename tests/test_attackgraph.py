"""Attack graph (chains + attack economics) and the asset registry (tiers as data)."""

from __future__ import annotations

import pathlib

import pytest

from raksha import assets, attackgraph, roe
from raksha.finding import DETERMINISTIC_MATCH, EXPLOIT_REPLAY, Finding, Frame, Reproducer, ReplayResult, utcnow
from raksha.lanes import scan_target

REPO = pathlib.Path(__file__).parents[1]
ESTATE = REPO / "demo-targets" / "mixed-estate"


def proven(oracle: str, cwe: str, target: str, *, severity: str = "medium", kind: str = DETERMINISTIC_MATCH,
           reachability: str | None = None, message: str = "") -> Finding:
    f = Finding(oracle=oracle, bug_class=cwe, language="any", target=target, message=message or oracle,
                severity=severity, frames=[Frame(symbol=oracle, uri=target, line=1)])
    f.attach_reproducer(Reproducer.from_bytes(b"x", ["raksha", "match"], kind=kind))
    f.record_replay_before(ReplayResult(oracle_fired=True, at=utcnow()))
    f.confirm()
    f.reachability = reachability
    return f


# ---------------------------------------------------------------- chains on the demo estate

@pytest.fixture(scope="module")
def estate_findings():
    return scan_target(ESTATE).findings


def test_estate_yields_credential_to_endpoint_to_rce_chain(estate_findings):
    g = attackgraph.build(estate_findings)
    caps = [tuple(attackgraph.capability(estate_findings[i]) for i in range(len(estate_findings)))]
    assert caps                                                     # typing ran on every finding
    want = [c for c in g.chains if [s.split(" ")[0] for s in c.steps] == ["credential", "unauth-endpoint", "rce"]]
    assert want, [c.steps for c in g.chains]
    chain = want[0]
    assert chain.cost == 4.5 and chain.viable and chain.combined_severity == "critical"
    assert chain.id.startswith("chain-") and len(chain.finding_ids) == 3
    assert "config/app.properties" in chain.steps[0] and "openapi.json" in chain.steps[1]
    assert "audit-java/pom.xml" in chain.steps[2] and "CWE-917" in chain.steps[2]   # imported Log4Shell


def test_not_imported_dependency_is_never_an_rce_step(estate_findings):
    lodash = next(f for f in estate_findings if f.bug_class == "CWE-94")
    assert lodash.reachability == "not-imported" and attackgraph.capability(lodash) is None
    g = attackgraph.build(estate_findings)
    assert lodash.id not in g.nodes


def test_lone_medium_finding_yields_no_chain():
    f = proven("osv:version-match", "CWE-444", "svc/go.mod", reachability="unknown")
    g = attackgraph.build([f])
    assert g.chains == [] and g.summary()["chains"] == 0 and g.summary()["cheapest_path"] is None
    assert attackgraph.build([proven("secrets:x", "CWE-798", "config/app.properties")]).chains == []


def test_suspected_findings_are_not_nodes():
    f = Finding(oracle="cpg:python", bug_class="CWE-78", language="python", target="svc/a.py", message="static")
    assert attackgraph.build([f]).nodes == {}


def test_annotate_fills_chain_ids(estate_findings):
    g = attackgraph.build(estate_findings)
    attackgraph.annotate(estate_findings, g)
    in_chain = [f for f in estate_findings if f.chain_ids]
    assert in_chain and all(cid.startswith("chain-") for f in in_chain for cid in f.chain_ids)
    assert {cid for f in in_chain for cid in f.chain_ids} == {c.id for c in g.chains}
    lodash = next(f for f in estate_findings if f.bug_class == "CWE-94")
    assert lodash.chain_ids == []


def test_summary_keys_are_stable_and_ids_deterministic(estate_findings):
    g1 = attackgraph.build(estate_findings)
    g2 = attackgraph.build(list(reversed(estate_findings)))
    assert set(g1.summary()) == {"findings", "nodes", "edges", "chains", "viable_chains", "cheapest_path", "budget"}
    assert g1.summary()["findings"] == len(estate_findings)
    assert [c.id for c in g1.chains] == [c.id for c in g2.chains]
    assert set(g1.summary()["cheapest_path"]) == {"id", "cost", "steps"}
    assert g1.as_dict()["summary"] == g1.summary()


# ---------------------------------------------------------------- edge rules and economics

def test_edges_follow_the_documented_rules():
    cred = proven("secrets:k", "CWE-798", "api/settings.py")
    ep = proven("service:missing-authz", "CWE-862", "api/openapi.json")
    rce = proven("pysecsan:cmd", "CWE-78", "api/app.py", kind=EXPLOIT_REPLAY, severity="high")
    other_rce = proven("pysecsan:cmd", "CWE-78", "worker/app.py", kind=EXPLOIT_REPLAY)
    leak = proven("osv:version-match", "CWE-200", "api/requirements.txt", reachability="imported")
    nocert = proven("crypto:no-cert-verification", "CWE-295", "api/client.py")
    mem = proven("asan:overflow", "CWE-120", "parser/src/tlv.c", kind=EXPLOIT_REPLAY)
    g = attackgraph.build([cred, ep, rce, other_rce, leak, nocert, mem])
    rules = {(e.src, e.dst): e.rule[:1] for e in g.edges}
    assert rules[(cred.id, ep.id)] == "1" and rules[(ep.id, rce.id)] == "2"
    assert rules[(leak.id, cred.id)] == "3" and rules[(nocert.id, cred.id)] == "4"
    assert (ep.id, other_rce.id) not in rules                      # a different service
    assert (mem.id, rce.id) not in rules                           # a different binary
    assert (cred.id, rce.id) not in rules                          # no such rule
    cheapest = g.summary()["cheapest_path"]
    assert cheapest["cost"] == 2.5                                 # ep (1.5) + exploit-proven rce (1.0)


def test_estate_wide_credential_reaches_another_service():
    cred = proven("secrets:k", "CWE-798", "config/app.properties")
    ep = proven("service:missing-authz", "CWE-862", "gateway/openapi.json")
    rce = proven("pysecsan:cmd", "CWE-78", "gateway/app.py", kind=EXPLOIT_REPLAY)
    g = attackgraph.build([cred, ep, rce])
    assert any(len(c.finding_ids) == 3 for c in g.chains)


def test_memory_to_rce_same_binary():
    mem = proven("asan:overflow", "CWE-121", "parser/src/tlv.c", kind=EXPLOIT_REPLAY)
    rce = proven("asan:cmd", "CWE-78", "parser/src/exec.c", kind=EXPLOIT_REPLAY)
    (chain,) = attackgraph.build([mem, rce]).chains
    assert chain.cost == 2.0 and chain.viable and [s.split(" ")[0] for s in chain.steps] == ["memory", "rce"]


def test_cost_and_budget():
    cred = proven("secrets:k", "CWE-798", "config/app.properties")
    ep = proven("service:missing-authz", "CWE-862", "svc/openapi.json")
    rce = proven("osv:version-match", "CWE-502", "svc/requirements.txt", reachability="unknown")
    g = attackgraph.build([cred, ep, rce], budget=4.0)
    long = next(c for c in g.chains if len(c.finding_ids) == 3)
    assert long.cost == 5.0 and not long.viable                    # 1.5 + 1.5 + 2.0 (unknown reachability)
    assert attackgraph.step_cost(proven("x", "CWE-78", "a", kind=EXPLOIT_REPLAY)) == 1.0
    assert attackgraph.step_cost(proven("x", "CWE-78", "a", reachability="not-imported")) == 4.0


def test_chain_ends_on_credential_only_for_a_critical_asset():
    leak = proven("osv:version-match", "CWE-200", "c-nolibfuzzer/requirements.txt", reachability="imported")
    cred = proven("secrets:k", "CWE-798", "c-nolibfuzzer/settings.py")
    assert attackgraph.build([leak, cred]).chains == []
    (chain,) = attackgraph.build([leak, cred], assets=assets.load()).chains
    assert [s.split(" ")[0] for s in chain.steps] == ["info-leak", "credential"]
    (by_scope,) = attackgraph.build([leak, cred], critical_scopes={"c-nolibfuzzer"}).chains
    assert by_scope.id == chain.id


# ---------------------------------------------------------------- asset registry

def test_registry_lookup_by_glob():
    reg = assets.load()
    assert reg.lookup("demo-targets/c-nolibfuzzer").tier == "mission-critical"
    assert reg.lookup("java-log4shell").mission_function == "audit logging"
    assert reg.lookup("demo-targets/mixed-estate/tool-py").name == "mixed-estate/tool-py"
    assert reg.lookup("mixed-estate/new-service").name == "mixed-estate"       # the catch-all glob
    assert reg.lookup("demo-targets/mixed-estate").name == "mixed-estate"      # the directory itself
    assert reg.lookup("fleet/ops-tools").tier == "support"
    assert reg.lookup("go-decoder").tier == "operational" and reg.lookup("py-noharness").tier == "support"
    assert reg.critical_names() == {"c-nolibfuzzer", "c-overflow"}


def test_registry_default_when_unknown():
    reg = assets.load()
    assert reg.lookup("something-never-seen") is None
    assert reg.tier_for("something-never-seen") == assets.DEFAULT_TIER == "operational"
    assert reg.multiplier_for("something-never-seen") == 1.0                  # never inflated
    assert assets.mission_multiplier(None) == 1.0


def test_mission_multiplier_table():
    assert [assets.mission_multiplier(t) for t in ("mission-critical", "operational", "support", "test")] == \
        [2.0, 1.5, 1.0, 0.5]


def test_round_trip_to_roe_asset():
    reg = assets.load()
    a = reg.to_roe_asset("demo-targets/c-nolibfuzzer")
    assert isinstance(a, roe.Asset) and a.tier is roe.AssetTier.MISSION_CRITICAL and a.name == "c-nolibfuzzer"
    assert reg.to_roe_asset("java-log4shell").tier is roe.AssetTier.IMPORTANT
    assert reg.to_roe_asset("fleet/audit-cli").tier is roe.AssetTier.ROUTINE
    unknown = reg.to_roe_asset("unknown-thing", operator_cap=roe.Level.R1)
    assert unknown.tier is roe.AssetTier.IMPORTANT and unknown.operator_cap is roe.Level.R1
    assert unknown.name == "unknown-thing"


def test_registry_loads_from_a_custom_file_and_rejects_bad_tiers(tmp_path):
    p = tmp_path / "assets.json"
    p.write_text('{"assets": [{"name": "x", "pattern": "x*", "tier": "test", "mission_function": "", "owner_unit": ""}]}')
    reg = assets.load(p)
    assert reg.lookup("x-service").tier == "test" and reg.path == p
    p.write_text('{"assets": [{"name": "x", "pattern": "x", "tier": "vital"}]}')
    with pytest.raises(ValueError):
        assets.load(p)


def test_annotate_sets_mission_impact(estate_findings):
    reg = assets.load()
    assets.annotate(estate_findings, reg, target="demo-targets/mixed-estate")
    by_target = {f.target: f.mission_impact for f in estate_findings}
    assert by_target["gateway-go/openapi.json"] == "operational"
    assert by_target["tool-py/requirements.txt"] == "support"
    unknown = proven("secrets:k", "CWE-798", "settings.py")
    assets.annotate([unknown], reg)
    assert unknown.mission_impact == "operational"                             # the documented default
    assets.annotate([unknown], reg, target="c-nolibfuzzer")
    assert unknown.mission_impact == "mission-critical"
