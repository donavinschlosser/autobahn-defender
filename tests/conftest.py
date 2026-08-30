"""Pytest fixtures: isolate HOME/XDG dirs so tests never touch real user data."""
import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Point HOME and XDG_DATA_HOME at a temp dir for every test.

    This must run BEFORE any engine module is imported in a test body
    (modules read env lazily in function calls, so fixture ordering works
    as long as imports happen inside test functions/after fixtures).
    """
    fake_home = tmp_path / "home"
    fake_data = tmp_path / "xdgdata"
    fake_home.mkdir()
    fake_data.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(fake_data))
    yield {"home": fake_home, "data": fake_data}