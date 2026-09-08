"""Fail-closed identity and operator-policy settings."""

from __future__ import annotations

from pathlib import Path

import pytest
from support import init_project, write_registry

from vedaops_mcp.errors import IdentityError, SettingsError
from vedaops_mcp.settings import (
    AGENT_ID_ENVIRONMENT_VARIABLE,
    Settings,
    default_registry_path,
    operator_config_dir,
)


def test_default_registry_is_distinct_from_the_legacy_live_path():
    assert operator_config_dir().name == "mcp"
    assert default_registry_path() == Path.home() / ".config" / "vedaops" / "mcp" / "projects.toml"
    assert default_registry_path() != Path.home() / ".config" / "vedaops" / "projects.toml"


def test_missing_agent_id_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(AGENT_ID_ENVIRONMENT_VARIABLE, raising=False)
    with pytest.raises(IdentityError, match="VEDAOPS_IDENTITY_UNAVAILABLE"):
        Settings.load()


@pytest.mark.parametrize(
    "identity",
    ["anonymous", "unknown", "vedaops-local-agent", "local-stdio-agent"],
)
def test_generic_agent_id_is_refused(monkeypatch: pytest.MonkeyPatch, identity: str):
    monkeypatch.setenv(AGENT_ID_ENVIRONMENT_VARIABLE, identity)
    with pytest.raises(IdentityError, match="VEDAOPS_IDENTITY_INVALID"):
        Settings.load()


def test_missing_registry_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(AGENT_ID_ENVIRONMENT_VARIABLE, "test-agent")
    with pytest.raises(SettingsError, match="VEDAOPS_REGISTRY_NOT_CONFIGURED"):
        Settings.load()


def test_symlink_registry_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    root = tmp_path / "project"
    init_project(root)
    real = write_registry(tmp_path / "projects.toml", root=root)
    link = tmp_path / "linked.toml"
    link.symlink_to(real)
    monkeypatch.setenv(AGENT_ID_ENVIRONMENT_VARIABLE, "test-agent")
    monkeypatch.setenv("VEDAOPS_PROJECTS_REGISTRY", str(link))
    with pytest.raises(SettingsError, match="VEDAOPS_REGISTRY_INSECURE"):
        Settings.load()


def test_environment_registry_and_agent_id_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)
    monkeypatch.setenv(AGENT_ID_ENVIRONMENT_VARIABLE, "test-agent")
    monkeypatch.setenv("VEDAOPS_PROJECTS_REGISTRY", str(registry))

    settings = Settings.load()

    assert settings.principal_id == "test-agent"
    assert settings.registry_path == registry.resolve()
    assert "environment" in settings.config_source
