"""Stdio startup refuses missing identity or unknown principals."""

from __future__ import annotations

from pathlib import Path

from support import init_project, write_registry

from vedaops_mcp.entrypoints import main


def test_startup_without_agent_id_fails_closed(capsys):
    assert main(["stdio"]) == 2
    captured = capsys.readouterr()
    assert "VEDAOPS_IDENTITY_UNAVAILABLE" in captured.err


def test_startup_with_unknown_principal_fails_closed(
    monkeypatch,
    tmp_path: Path,
    capsys,
):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)
    monkeypatch.setenv("VEDAOPS_AGENT_ID", "other-agent")
    monkeypatch.setenv("VEDAOPS_PROJECTS_REGISTRY", str(registry))

    assert main(["stdio"]) == 2
    captured = capsys.readouterr()
    assert "VEDAOPS_PRINCIPAL_UNKNOWN" in captured.err
