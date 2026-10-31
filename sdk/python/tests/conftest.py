"""tests/conftest.py — shared fixtures for revoc-sdk tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure REVOC_BASE_URL doesn't leak between tests."""
    monkeypatch.delenv("REVOC_BASE_URL", raising=False)
