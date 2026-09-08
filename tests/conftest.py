"""Isolate tests from the operator's real VedaOps configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from vedaops_mcp.errors import forget_secrets

VEDAOPS_VARIABLES = (
    "VEDAOPS_AGENT_ID",
    "VEDAOPS_PROJECTS_REGISTRY",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    for name in VEDAOPS_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    test_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(test_home))
    forget_secrets()
    yield
    forget_secrets()
