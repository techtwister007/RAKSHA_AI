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
    tempfile.tempdir = str(tmp_path_factory.mktemp("raksha-tmp"))
    yield
    tempfile.tempdir = previous
