# RAKSHA AI

Offline find → fix → prove system for software weaknesses. Read `HANDOFF.md` first.

- Code: `raksha/` (Python 3.11+, stdlib only at runtime), console `console/`, tests `tests/`.
- Branch: `claude/magical-mayer-gs2xno`.
- Check an install: `python -m raksha.airgap && python scripts/model_lane_check.py && python -m raksha.slice_autofuzz`.
- Tests: `python -m pytest -q` (~880 tests). Run the touched test files before committing, and the
  full suite before pushing.
- The five-check gate decides; models only propose. No reproducer, no report. Never call a target
  "secure". Every number is measured or null. No network calls outside `raksha/inference.py`
  (`python -m raksha.airgap` enforces this).
- New features come with tests in `tests/`. Match the surrounding style: short docstrings that
  say why, no new runtime dependencies.
