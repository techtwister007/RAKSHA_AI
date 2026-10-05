import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_text():
    def _read(name: str) -> str:
        return (FIXTURES / name).read_text()

    return _read


@pytest.fixture(autouse=True, scope="session")
def _isolated_tempdir(tmp_path_factory):
    """Everything the product creates under the temp dir during tests (scratch builds, sealed
    evidence bundles) lands in a pytest-managed directory and is cleaned up with it."""
    import tempfile
    previous = tempfile.tempdir
    tempfile.tempdir = str(tmp_path_factory.mktemp("scratch-tmp"))
    yield
    tempfile.tempdir = previous


@pytest.fixture(autouse=True)
def _fresh_fix_memory(monkeypatch):
    """Each test starts with an empty process-wide fix memory: a fix verified by one test must not
    become a retrieval (or cross-language) candidate in another and change what that test measures."""
    from raksha import retrieval
    monkeypatch.setattr(retrieval, "_DEFAULT_MEMORY", retrieval.FixMemory())


@pytest.fixture(autouse=True)
def _isolated_project_store(monkeypatch, tmp_path):
    """Wave 5: project reports and learning state go to a per-test RAKSHA_HOME, never the real one."""
    if not __import__("os").environ.get("RAKSHA_HOME_KEEP"):
        monkeypatch.setenv("RAKSHA_HOME", str(tmp_path / "raksha-home"))


_OPERATOR_ENV = ("RAKSHA_INFERENCE_BASE_URL", "RAKSHA_INFERENCE_API_KEY", "RAKSHA_REPAIR_MODEL",
                 "RAKSHA_ADVISOR_MODEL", "RAKSHA_TRIAGE_MODEL", "RAKSHA_RED_MODEL", "RAKSHA_JUDGE_MODEL",
                 "RAKSHA_EMBED_MODEL", "RAKSHA_SEALED", "RAKSHA_TAKE_ALL", "RAKSHA_TAKE_SEMGREP",
                 "RAKSHA_TAKE_GITLEAKS", "RAKSHA_TAKE_OSV_SCANNER", "RAKSHA_TAKE_CHECKOV",
                 "RAKSHA_OSV_OFFLINE", "RAKSHA_OPA", "RAKSHA_PROVIDER", "RAKSHA_COSIGN_KEY", "RAKSHA_GUIDED_DECODING")


@pytest.fixture(autouse=True)
def _no_operator_settings(monkeypatch):
    """A laptop shell set up for real use (a model on Ollama, scanners on) must not leak into the
    tests: each test sees the model-free, scanner-off default and opts in to anything it needs."""
    for name in _OPERATOR_ENV:
        monkeypatch.delenv(name, raising=False)
