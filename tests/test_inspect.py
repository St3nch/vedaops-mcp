"""Bounded inspect, context, Git status, and exact commit comparison."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from support import git, init_project, write_registry

import vedaops_mcp.policy as policy_module
from vedaops_mcp.errors import PolicyError
from vedaops_mcp.inspect import (
    orient_project,
    project_context_get,
    project_file_read,
    project_git_compare,
    project_git_status,
    project_search,
    project_tree,
)


def test_file_read_returns_content_sha256_and_completeness(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)
    expected = hashlib.sha256((root / "README.md").read_bytes()).hexdigest()

    result = project_file_read(
        registry,
        principal_id="test-agent",
        project_id="example",
        path="README.md",
    )

    assert result.project_id == "example"
    assert result.workspace_id == "primary"
    assert "hello world" in result.content
    assert result.sha256 == expected
    assert result.truncated is False
    assert result.bytes_returned == result.bytes_total


def test_file_read_content_and_digest_bind_same_open_inode_during_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)
    target = root / "README.md"
    original_bytes = target.read_bytes()
    replacement_bytes = original_bytes.replace(b"hello world", b"hello other")
    assert len(replacement_bytes) == len(original_bytes)
    original_open = policy_module.os.open
    swapped = False

    def replace_after_final_open(path, flags, *args, **kwargs):
        nonlocal swapped
        descriptor = original_open(path, flags, *args, **kwargs)
        if path == "README.md" and kwargs.get("dir_fd") is not None and not swapped:
            temporary = root / "README.replacement"
            temporary.write_bytes(replacement_bytes)
            os.replace(temporary, target)
            swapped = True
        return descriptor

    monkeypatch.setattr(policy_module.os, "open", replace_after_final_open)
    result = project_file_read(
        registry,
        principal_id="test-agent",
        project_id="example",
        path="README.md",
    )

    assert swapped is True
    assert result.content.encode() == original_bytes
    assert result.sha256 == hashlib.sha256(original_bytes).hexdigest()
    assert target.read_bytes() == replacement_bytes


def test_file_read_truncation_is_explicit(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, files={"big.txt": "abcdefghij"})
    registry = write_registry(tmp_path / "projects.toml", root=root)

    result = project_file_read(
        registry,
        principal_id="test-agent",
        project_id="example",
        path="big.txt",
        max_bytes=4,
    )
    assert result.content == "abcd"
    assert result.truncated is True
    assert result.bytes_returned == 4
    assert result.bytes_total == 10


def test_search_is_literal_and_bounded(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    result = project_search(
        registry,
        principal_id="test-agent",
        project_id="example",
        query="hello",
    )
    assert result.returned_count >= 1
    assert result.truncated is False
    assert all("hello" in match.text for match in result.matches)

    empty = project_search(
        registry,
        principal_id="test-agent",
        project_id="example",
        query="this-does-not-occur",
    )
    assert empty.returned_count == 0
    assert empty.truncated is False


def test_search_preserves_leading_and_trailing_spaces_in_the_query(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, files={"notes.txt": "hello world\nxx hello yy\n"})
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(PolicyError, match="VEDAOPS_INVALID_ARGUMENT"):
        project_search(
            registry,
            principal_id="test-agent",
            project_id="example",
            query="",
        )

    literal = project_search(
        registry,
        principal_id="test-agent",
        project_id="example",
        query=" hello ",
    )
    assert literal.query == " hello "
    assert literal.returned_count == 1
    assert literal.matches[0].path == "notes.txt"
    assert literal.matches[0].line == 2
    assert "xx hello yy" in literal.matches[0].text

    unpadded = project_search(
        registry,
        principal_id="test-agent",
        project_id="example",
        query="hello",
    )
    assert unpadded.query == "hello"
    assert unpadded.returned_count >= 2


def test_tree_truncation_flag(tmp_path: Path):
    root = tmp_path / "project"
    files = {f"src/file{i:02d}.txt": f"n={i}\n" for i in range(8)}
    init_project(root, files=files)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    result = project_tree(
        registry,
        principal_id="test-agent",
        project_id="example",
        max_entries=3,
    )
    assert result.returned_count == 3
    assert result.total_count > 3
    assert result.truncated is True


def test_context_reads_only_registry_selected_documents(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, files={"NOTES.md": "not context\n", "AGENTS.md": "# Agents\n"})
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        context_files=("README.md", "AGENTS.md"),
    )

    result = project_context_get(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    paths = [document.path for document in result.documents]
    assert paths == ["README.md", "AGENTS.md"]
    assert "NOTES.md" not in paths
    assert result.truncated is False


def test_git_status_reports_branch_head_and_dirty_state(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    clean = project_git_status(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert clean.git_head == head
    assert clean.clean is True
    assert clean.detached is False
    assert clean.branch is not None

    (root / "README.md").write_text("# Example\ndirty\n")
    dirty = project_git_status(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert dirty.clean is False
    assert "README.md" in dirty.status


def test_tracked_secret_changes_are_hidden_but_keep_status_dirty(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    git(root, "add", "-f", ".env")
    git(root, "commit", "-q", "-m", "track env")
    (root / ".env").write_text("TOKEN=changed\n")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    status = project_git_status(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert status.clean is False
    assert ".env" not in status.status
    assert status.hidden_entries >= 1


def test_git_compare_requires_exact_commit_ids_and_returns_changed_files(tmp_path: Path):
    root = tmp_path / "project"
    base = init_project(root)
    (root / "README.md").write_text("# Example\nchanged\n")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "change")
    head = git(root, "rev-parse", "HEAD")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    result = project_git_compare(
        registry,
        principal_id="test-agent",
        project_id="example",
        base_commit=base,
        head_commit=head,
    )
    assert result.base_commit == base
    assert result.head_commit == head
    assert result.returned_count == 1
    assert result.files[0].path == "README.md"
    assert result.files[0].status == "M"
    assert "changed" in result.diff
    assert result.truncated is False

    with pytest.raises(PolicyError, match="VEDAOPS_INVALID_ARGUMENT"):
        project_git_compare(
            registry,
            principal_id="test-agent",
            project_id="example",
            base_commit="main",
            head_commit=head,
        )
    with pytest.raises(PolicyError, match="VEDAOPS_INVALID_ARGUMENT"):
        project_git_compare(
            registry,
            principal_id="test-agent",
            project_id="example",
            base_commit=base[:12],
            head_commit=head,
        )


def test_compare_excludes_protected_paths(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    git(root, "add", "-f", ".env")
    git(root, "commit", "-q", "-m", "track env")
    base = git(root, "rev-parse", "HEAD")
    (root / ".env").write_text("TOKEN=changed\n")
    (root / "README.md").write_text("# Example\nvisible change\n")
    git(root, "add", "-f", ".env", "README.md")
    git(root, "commit", "-q", "-m", "both")
    head = git(root, "rev-parse", "HEAD")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    result = project_git_compare(
        registry,
        principal_id="test-agent",
        project_id="example",
        base_commit=base,
        head_commit=head,
    )
    paths = {item.path for item in result.files}
    assert "README.md" in paths
    assert ".env" not in paths
    assert result.excluded_count >= 1
    assert ".env" not in result.diff


def test_project_orientation_includes_workspace_permissions_and_git(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root)
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        context_files=("README.md",),
    )

    detail = orient_project(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert detail.id == "example"
    assert detail.workspace_id == "primary"
    assert detail.workspace_kind == "ordinary"
    assert detail.principal_id == "test-agent"
    assert detail.effective_capabilities == ["read"]
    assert detail.git.state == "observed"
    assert detail.git.git_head == head
    assert detail.git.clean is True
    assert detail.authority_sources["project_manifest"] == ".vedaops/project.toml"
