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
