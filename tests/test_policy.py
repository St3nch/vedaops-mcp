"""Path and Git policy kernel for untrusted repositories."""

from __future__ import annotations

from pathlib import Path

import pytest
from support import git, init_project, write_registry

from vedaops_mcp.errors import PolicyError
from vedaops_mcp.inspect import project_file_read, project_tree
from vedaops_mcp.policy import (
    ensure_git_repository,
    ensure_safe_local_git_config,
    normalize_relative,
    protected_reason,
    resolve_within_root,
)


def test_paths_must_be_normalized_and_relative():
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative("../secret")
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative("/etc/passwd")
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative("a\\b")
    assert normalize_relative("src/app.py") == "src/app.py"


def test_paths_with_leading_or_trailing_whitespace_are_invalid():
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative(" README.md")
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative("README.md ")
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative(" src/app.py")
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        normalize_relative("src/app.py\n")
    assert normalize_relative("", allow_root=True) == ""
    assert normalize_relative(".", allow_root=True) == ""


def test_git_internals_and_secret_names_are_protected():
    assert protected_reason(".git/config") == "Git internal path"
    assert protected_reason(".env") == "secret-like filename"
    assert protected_reason(".env.local") == "secret-like filename"
    assert protected_reason("tls/server.pem") == "secret-like file suffix"
    assert protected_reason("README.md") is None


def test_file_read_refuses_git_internals_and_secrets(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_file_read(
            registry,
            principal_id="test-agent",
            project_id="example",
            path=".git/config",
        )
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_file_read(
            registry,
            principal_id="test-agent",
            project_id="example",
            path=".env",
        )


def test_file_read_refuses_whitespace_padded_paths(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        project_file_read(
            registry,
            principal_id="test-agent",
            project_id="example",
            path=" README.md",
        )
    with pytest.raises(PolicyError, match="VEDAOPS_PATH_INVALID"):
        project_file_read(
            registry,
            principal_id="test-agent",
            project_id="example",
            path="README.md ",
        )


def test_ignored_paths_are_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_file_read(
            registry,
            principal_id="test-agent",
            project_id="example",
            path="ignored.txt",
        )


def test_symlink_to_a_secret_is_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    (root / "visible.txt").symlink_to(root / ".env")
    git(root, "add", "visible.txt")
    git(root, "commit", "-q", "-m", "symlink")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_file_read(
            registry,
            principal_id="test-agent",
            project_id="example",
            path="visible.txt",
        )


def test_path_escape_outside_the_root_is_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    (root / "escape.txt").symlink_to(outside)
    git(root, "add", "escape.txt")
    git(root, "commit", "-q", "-m", "escape")

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_ESCAPE"):
        resolve_within_root(root, "escape.txt", must_exist=True)


def test_git_file_pointer_is_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    git_dir = root / ".git"
    # Replace the directory with a gitdir file, as linked worktrees do.
    import shutil

    shutil.rmtree(git_dir)
    git_dir.write_text("gitdir: /tmp/somewhere\n")

    with pytest.raises(PolicyError, match="VEDAOPS_PROJECT_CONFIG_UNSAFE"):
        ensure_git_repository(root)


def test_unsafe_local_git_config_is_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    git(root, "config", "core.fsmonitor", "false")

    with pytest.raises(PolicyError, match="VEDAOPS_PROJECT_CONFIG_UNSAFE"):
        ensure_safe_local_git_config(root)


def test_local_git_config_does_not_follow_external_include_path(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    external = tmp_path / "external.gitconfig"
    external.write_text("[core]\n\tfsmonitor = true\n[user]\n\texternalmarker = followed\n")
    git(root, "config", "include.path", str(external))

    with pytest.raises(PolicyError, match="VEDAOPS_PROJECT_CONFIG_UNSAFE") as captured:
        ensure_safe_local_git_config(root)

    assert "include.path" in captured.value.detail
    assert "fsmonitor" not in captured.value.detail
    assert "externalmarker" not in captured.value.detail


def test_local_git_config_does_not_follow_matching_includeif(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    external = tmp_path / "external.gitconfig"
    external.write_text("[core]\n\tfsmonitor = true\n[user]\n\texternalmarker = followed\n")
    gitdir = (root / ".git").resolve()
    git(root, "config", f"includeIf.gitdir:{gitdir}.path", str(external))

    with pytest.raises(PolicyError, match="VEDAOPS_PROJECT_CONFIG_UNSAFE") as captured:
        ensure_safe_local_git_config(root)

    assert "includeif." in captured.value.detail
    assert "fsmonitor" not in captured.value.detail
    assert "externalmarker" not in captured.value.detail


def test_tree_skips_protected_tracked_secrets(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    git(root, "add", "-f", ".env")
    git(root, "commit", "-q", "-m", "track env")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    tree = project_tree(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    paths = {entry.path for entry in tree.entries}
    assert ".env" not in paths
    assert tree.skipped_count >= 1
