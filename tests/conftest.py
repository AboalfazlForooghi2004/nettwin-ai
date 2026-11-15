"""Shared pytest fixtures for the NetTwin AI test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the synthetic YAML topology fixtures."""
    return FIXTURES_DIR
