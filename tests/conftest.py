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
