"""Shared fixtures for MCP-01 authorization and inspect tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

DEFAULT_CAPABILITIES = ("read",)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    ).stdout.strip()


def write_manifest(
    root: Path,
    *,
    project_id: str = "example",
    name: str = "Example",
    capabilities: tuple[str, ...] = DEFAULT_CAPABILITIES,
    mutable: bool = False,
    extra: str = "",
) -> None:
    manifest = root / ".vedaops" / "project.toml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    grants = ", ".join(repr(item) for item in capabilities)
    manifest.write_text(
        f"schema_version = 1\nid = {project_id!r}\nname = {name!r}\n"
        f"mutable = {str(mutable).lower()}\ncapabilities = [{grants}]\n{extra}"
    )


def init_repository(root: Path) -> str:
    """Initialize a Git repository and commit everything currently present."""
    if not (root / ".git").exists():
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        git(root, "config", "user.name", "Test")
        git(root, "config", "user.email", "test@example.invalid")
        git(root, "config", "commit.gpgsign", "false")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


def init_project(
    root: Path,
    *,
    project_id: str = "example",
    capabilities: tuple[str, ...] = DEFAULT_CAPABILITIES,
    mutable: bool = False,
    files: dict[str, str] | None = None,
    gitignore: str = ".env\nignored.txt\n",
) -> str:
    """Create a committed Git project with a manifest and return its HEAD."""
    root.mkdir(parents=True, exist_ok=True)
    write_manifest(
        root,
        project_id=project_id,
        capabilities=capabilities,
        mutable=mutable,
    )
    payload = {
        "README.md": "# Example\nhello world\n",
        "src/app.py": 'MESSAGE = "hello"\n',
        ".gitignore": gitignore,
    }
    if files is not None:
        payload.update(files)
    for relative_path, content in payload.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    (root / ".env").write_text("TOKEN=secret\n")
    (root / "ignored.txt").write_text("hidden\n")
    return init_repository(root)


def write_registry(
    path: Path,
    *,
    root: Path,
    project_id: str = "example",
    name: str = "Example",
    status: str = "active",
    workspace_id: str = "primary",
    mutable: bool = False,
    capabilities: tuple[str, ...] = DEFAULT_CAPABILITIES,
    context_files: tuple[str, ...] = (),
    principal_id: str = "test-agent",
    principal_capabilities: tuple[str, ...] | None = None,
    extra_project: str = "",
    extra_principal: str = "",
) -> Path:
    """Write a trusted operator policy file outside every managed project root."""
    grants = ", ".join(repr(item) for item in capabilities)
    documents = ", ".join(repr(item) for item in context_files)
    principal_grants = capabilities if principal_capabilities is None else principal_capabilities
    if principal_grants:
        grant_items = ", ".join(repr(item) for item in principal_grants)
        principal_projects = f"{project_id} = [{grant_items}]\n"
    else:
        principal_projects = ""
    path.write_text(
        "schema_version = 1\n\n"
        "[[projects]]\n"
        f"id = {project_id!r}\n"
        f"name = {name!r}\n"
        f"status = {status!r}\n"
        f"root = {str(root)!r}\n"
        f"workspace_id = {workspace_id!r}\n"
        f"mutable = {str(mutable).lower()}\n"
        f"capabilities = [{grants}]\n"
        f"context_files = [{documents}]\n"
        f"{extra_project}\n"
        "[[principals]]\n"
        f"id = {principal_id!r}\n"
        f"{extra_principal}"
        + (f"[principals.projects]\n{principal_projects}" if principal_grants else "")
    )
    path.chmod(0o600)
    return path
