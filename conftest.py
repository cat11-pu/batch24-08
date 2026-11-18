import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest

import rate_guard as rg


@pytest.fixture(autouse=True)
def _clean_rate_guard_state():
    rg.reset_all()
    yield
    rg.reset_all()
