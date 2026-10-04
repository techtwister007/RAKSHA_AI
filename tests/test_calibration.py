"""G6: fusion reliabilities and dependency step costs come from measured data, with the table shown."""
from __future__ import annotations


from raksha import calibrate, evidence
from raksha.attackgraph import step_cost
from raksha.finding import DETERMINISTIC_MATCH, Finding, Reproducer


def test_wilson_and_posterior():
    assert calibrate.wilson(0, 0) == (None, None)
    lo, hi = calibrate.wilson(10, 10)
    assert 0.7 < lo < 0.75 and hi == 1.0
    obs = calibrate.Observations()
    for _ in range(6):
        obs.add({"exploit"}, True)
    row = calibrate.estimate(obs)["exploit"]
    k, prior = calibrate.PRIOR_STRENGTH, evidence._PRIOR_RELIABILITY["exploit"]
    assert row["calibrated"] == round((k * prior + 6) / (k + 6), 3)
    assert calibrate.estimate(obs)["parliament"]["status"].startswith("uncalibrated")


def test_labels_come_from_ground_truth():
    t = calibrate.load_truth()
    assert t.label("c-overflow/src/parser.c", "CWE-121")          # memory defect, memory CWE
    assert not t.label("c-overflow/src/parser.c", "CWE-78")       # wrong family at a planted file
    assert not t.label("fleet/audit-cli/safe.py", "CWE-78")       # deliberately safe sister code
    assert t.label("mixed-estate/config/app.properties", "CWE-798")


def test_fusion_uses_the_shared_formula():
    chans = {"exploit": 0.9, "structural": 0.7}
    f = Finding(oracle="o", bug_class="CWE-121", language="c", target="t", message="m")
    conf, capped = evidence.fuse_channels(chans)
    assert not capped and 0 < conf <= 1
    assert evidence.fuse_channels({"structural": 0.99, "crossconfirm": 0.99}) == (evidence.NONPROVEN_CAP, True)
    assert evidence.fuse(f).confidence == 0.0


def test_committed_table_drives_the_reliabilities():
    table = evidence.calibration()
    assert table and table["channels"]["exploit"]["n"] > 0
    for name, row in table["channels"].items():
        expected = row["calibrated"] if row["n"] else evidence._PRIOR_RELIABILITY[name]
        assert evidence._reliabilities()[name] == expected
    assert table["channels"]["parliament"]["n"] == 0            # no panel data: stays the prior
    assert "in-sample" in table["in_sample"]["structural"]


def test_reliabilities_fall_back_to_priors_without_a_table(monkeypatch, tmp_path):
    monkeypatch.setattr(evidence, "_CALIBRATION_FILE", tmp_path / "absent.json")
    assert evidence._reliabilities() == evidence._PRIOR_RELIABILITY


def test_dependency_step_cost_from_kev_and_epss():
    def dep(**kw):
        f = Finding(oracle="osv:version-match", bug_class="CWE-917", language="java", target="p", message="m")
        f.reproducer = Reproducer.from_bytes(b"x", ["raksha", "match"], kind=DETERMINISTIC_MATCH)
        for k, v in kw.items():
            setattr(f, k, v)
        return f
    assert step_cost(dep(kev=True, epss=0.1)) == 1.0
    assert step_cost(dep(epss=0.97)) == 1.03
    assert step_cost(dep(epss=0.0)) == 2.0
    assert step_cost(dep()) == 1.5


def test_no_false_positive_on_the_labelled_corpus():
    """Standing precision guard: every structural and build-free firing on the demo estate and the
    negative controls must be a planted defect. A new false positive anywhere fails here."""
    obs = calibrate.Observations()
    truth = calibrate.load_truth()
    calibrate._structural(obs, truth)
    calibrate._deterministic(obs, truth)
    for ch in ("structural", "deterministic"):
        assert obs.by_channel[ch] and all(obs.by_channel[ch]), ch
