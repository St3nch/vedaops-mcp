"""MCP-04 bounded file and local Git mutation semantics."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from support import git, init_project, write_registry

import vedaops_mcp.change as change_module
import vedaops_mcp.fs_helper as fs_helper
import vedaops_mcp.policy as policy_module
from vedaops_mcp.change import (
    project_file_delete,
    project_file_write,
    project_git_branch_create,
    project_git_branch_delete,
    project_git_branches,
    project_git_commit,
    project_git_diff,
    project_git_merge_ff,
    project_git_switch,
    project_patch_apply,
    project_text_replace,
)
from vedaops_mcp.errors import AuthorityError, PolicyError


def _change_project(tmp_path: Path) -> tuple[Path, Path, str]:
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "change"),
        mutable=True,
    )
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=True,
        capabilities=("read", "change"),
        principal_capabilities=("read", "change"),
    )
    return root, registry, head


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_change_requires_intersection_and_mutable_project(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "change"),
        mutable=True,
    )
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=True,
        capabilities=("read", "change"),
        principal_capabilities=("read",),
    )

    with pytest.raises(AuthorityError, match="VEDAOPS_CAPABILITY_DENIED"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="new.txt",
            content="nope\n",
        )

    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=False,
        capabilities=("read", "change"),
        principal_capabilities=("read", "change"),
    )
    with pytest.raises(AuthorityError, match="VEDAOPS_PROJECT_IMMUTABLE"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="new.txt",
            content="nope\n",
        )


def test_file_mutations_use_exact_hashes_and_protect_authority(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    before = _sha(readme)

    replaced = project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=before,
        find="hello world",
        replacement="hello MCP-04",
    )
    assert replaced.sha256_before == before
    assert replaced.sha256_after == _sha(readme)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_text_replace(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="README.md",
            expected_sha256=before,
            find="hello MCP-04",
            replacement="stale",
        )

    created = project_file_write(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="docs/new.txt",
        content="created\n",
    )
    assert created.action == "created"
    assert (root / "docs/new.txt").read_text() == "created\n"

    deleted = project_file_delete(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="docs/new.txt",
        expected_sha256=created.sha256_after or "",
    )
    assert deleted.action == "deleted"
    assert not (root / "docs/new.txt").exists()

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path=".vedaops/project.toml",
            content="schema_version = 1\n",
            expected_sha256=_sha(root / ".vedaops/project.toml"),
        )


def test_patch_is_bounded_to_validated_paths(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    patch = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,2 @@
 # Example
-hello world
+hello patch
"""
    result = project_patch_apply(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        patch=patch,
    )
    assert result.files_changed == ["README.md"]
    assert "hello patch" in (root / "README.md").read_text()

    mismatched = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/.vedaops/project.toml
@@ -1 +1 @@
-x
+y
"""
    with pytest.raises(PolicyError, match="VEDAOPS_PATCH_INVALID"):
        project_patch_apply(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            patch=mismatched,
        )


def test_git_diff_reports_tracked_change_and_hides_protected_paths(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello diff",
    )
    diff = project_git_diff(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert diff.files == ["README.md"]
    assert "hello diff" in diff.diff
    assert diff.truncated is False


def test_exact_commit_preserves_unrelated_dirty_and_disables_hooks(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    app = root / "src/app.py"

    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello commit",
    )
    new_file = project_file_write(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="docs/new.txt",
        content="new file\n",
    )
    assert new_file.sha256_after
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="src/app.py",
        expected_sha256=_sha(app),
        find="hello",
        replacement="unrelated",
    )

    sentinel = root / "hook-ran"
    hook = root / ".git/hooks/pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {sentinel}\n")
    hook.chmod(0o755)

    result = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        paths=["README.md", "docs/new.txt"],
        message="test: exact commit",
    )
    assert set(result.committed_paths) == {"README.md", "docs/new.txt"}
    assert git(root, "rev-parse", f"{result.git_head}^") == head
    assert "src/app.py" in result.remaining_status
    assert not sentinel.exists()
    assert 'MESSAGE = "unrelated"' in app.read_text()


def test_commit_refuses_preexisting_staged_state(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    (root / "README.md").write_text("changed\n")
    (root / "src/app.py").write_text("changed\n")
    git(root, "add", "src/app.py")

    with pytest.raises(PolicyError, match="VEDAOPS_GIT_INDEX_DIRTY"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="should refuse",
        )
    assert git(root, "rev-parse", "HEAD") == head
    assert git(root, "diff", "--cached", "--name-only") == "src/app.py"
    assert "README.md" not in git(root, "diff", "--cached", "--name-only")
    assert (root / "README.md").read_text() == "changed\n"


def _unstaged_names(root: Path) -> set[str]:
    return {line for line in git(root, "diff", "--name-only").splitlines() if line}


def _untracked_names(root: Path) -> set[str]:
    return {
        line
        for line in git(root, "ls-files", "--others", "--exclude-standard").splitlines()
        if line
    }


def _cached_names(root: Path) -> set[str]:
    return {line for line in git(root, "diff", "--cached", "--name-only").splitlines() if line}


def _commit_journal(registry: Path) -> list[dict]:
    records = [
        json.loads(path.read_text())
        for path in (registry.parent / "operations").glob("*.json")
        if path.name.endswith(".json")
    ]
    return [item for item in records if item["kind"] == "git_commit"]


def test_commit_failure_after_staging_restores_index_and_allows_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello recovered",
    )
    created = project_file_write(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="docs/retry.txt",
        content="retry me\n",
    )
    assert created.sha256_after
    (root / "src/app.py").write_text('MESSAGE = "unrelated dirty"\n')

    original = change_module.run_git_text

    def fail_commit(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure")
        return original(project_root, *args, **kwargs)

    monkeypatch.setattr(change_module, "run_git_text", fail_commit)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_UNAVAILABLE"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md", "docs/retry.txt"],
            message="test: recovered commit",
        )

    assert git(root, "rev-parse", "HEAD") == head
    assert _cached_names(root) == set()
    assert "README.md" in _unstaged_names(root)
    assert "src/app.py" in _unstaged_names(root)
    assert "docs/retry.txt" in _untracked_names(root)
    assert "hello recovered" in readme.read_text()
    assert (root / "docs/retry.txt").read_text() == "retry me\n"
    failed_journals = _commit_journal(registry)
    assert len(failed_journals) == 1
    assert failed_journals[0]["state"] == "failed"
    failed_operation_id = failed_journals[0]["operation_id"]

    monkeypatch.setattr(change_module, "run_git_text", original)
    result = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        paths=["README.md", "docs/retry.txt"],
        message="test: recovered commit",
    )
    assert set(result.committed_paths) == {"README.md", "docs/retry.txt"}
    assert result.git_head_before == head
    assert git(root, "rev-parse", f"{result.git_head}^") == head
    assert _cached_names(root) == set()
    committed = git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", result.git_head)
    assert "src/app.py" not in committed
    assert 'MESSAGE = "unrelated dirty"' in (root / "src/app.py").read_text()
    assert "src/app.py" in _unstaged_names(root)
    retry_journals = [
        item
        for item in _commit_journal(registry)
        if item["operation_id"] != failed_operation_id
    ]
    assert len(retry_journals) == 1
    retry_journal = retry_journals[0]
    assert retry_journal["state"] == "succeeded"
    assert "detail" not in retry_journal


def test_commit_does_not_unstage_unrelated_paths_when_index_is_unprovable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello mixed",
    )
    original = change_module.run_git_text

    def fail_after_foreign_stage(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            (root / "src/app.py").write_text('MESSAGE = "foreign staged"\n')
            git(root, "add", "src/app.py")
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure")
        return original(project_root, *args, **kwargs)

    monkeypatch.setattr(change_module, "run_git_text", fail_after_foreign_stage)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="should not unstage foreign paths",
        )

    assert git(root, "rev-parse", "HEAD") == head
    assert _cached_names(root) == {"README.md", "src/app.py"}
    assert "hello mixed" in readme.read_text()
    assert 'MESSAGE = "foreign staged"' in (root / "src/app.py").read_text()

    with pytest.raises(PolicyError, match="VEDAOPS_GIT_INDEX_DIRTY"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="retry still refused",
        )
    assert _cached_names(root) == {"README.md", "src/app.py"}


def test_commit_head_drift_prevents_index_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello drift",
    )
    original = change_module.run_git_text

    def fail_after_head_drift(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            git(root, "restore", "--staged", "--source=HEAD", "--", "README.md")
            git(root, "commit", "--allow-empty", "-m", "external drift")
            git(root, "add", "-A", "--", "README.md")
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure after drift")
        return original(project_root, *args, **kwargs)

    monkeypatch.setattr(change_module, "run_git_text", fail_after_head_drift)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="should not restore after drift",
        )

    drifted = git(root, "rev-parse", "HEAD")
    assert drifted != head
    assert git(root, "rev-parse", f"{drifted}^") == head
    assert git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", drifted) == ""
    assert _cached_names(root) == {"README.md"}
    assert "hello drift" in readme.read_text()

    with pytest.raises(PolicyError, match="VEDAOPS_GIT_PRECONDITION_FAILED"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="retry with stale HEAD",
        )
    assert git(root, "rev-parse", "HEAD") == drifted
    assert _cached_names(root) == {"README.md"}


def _porcelain_index_dirty_paths(root: Path) -> set[str]:
    raw = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "core.hooksPath=/dev/null",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--no-renames",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    ).stdout
    dirty: set[str] = set()
    for line in raw.splitlines():
        if len(line) >= 4 and line[0] not in {" ", "?"}:
            dirty.add(line[3:])
    return dirty


def test_commit_failure_after_staging_tracked_deletion_restores_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    digest = _sha(readme)
    project_file_delete(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=digest,
    )
    (root / "src/app.py").write_text('MESSAGE = "unrelated dirty"\n')
    assert not readme.exists()

    original = change_module.run_git_text

    def fail_commit(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure")
        return original(project_root, *args, **kwargs)

    monkeypatch.setattr(change_module, "run_git_text", fail_commit)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_UNAVAILABLE"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="test: recovered deletion",
        )

    assert git(root, "rev-parse", "HEAD") == head
    assert _cached_names(root) == set()
    assert _porcelain_index_dirty_paths(root) == set()
    assert not readme.exists()
    assert "src/app.py" in _unstaged_names(root)
    assert _commit_journal(registry)[-1]["state"] == "failed"

    monkeypatch.setattr(change_module, "run_git_text", original)
    result = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        paths=["README.md"],
        message="test: recovered deletion",
    )
    assert result.committed_paths == ["README.md"]
    assert git(root, "rev-parse", f"{result.git_head}^") == head
    assert "README.md" not in git(root, "ls-tree", "-r", "--name-only", result.git_head)
    assert not readme.exists()
    assert 'MESSAGE = "unrelated dirty"' in (root / "src/app.py").read_text()
    assert "src/app.py" in _unstaged_names(root)


def test_commit_restore_staged_failure_remains_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello unrestored",
    )
    original = change_module.run_git_text

    def fail_commit_and_restore(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure")
        if args and args[0] == "restore" and "--staged" in args:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated restore failure")
        return original(project_root, *args, **kwargs)

    monkeypatch.setattr(change_module, "run_git_text", fail_commit_and_restore)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN") as caught:
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="should remain uncertain",
        )

    message = str(caught.value)
    assert git(root, "rev-parse", "HEAD") == head
    assert _cached_names(root) == {"README.md"}
    assert _porcelain_index_dirty_paths(root) == {"README.md"}
    assert "staged none" not in message
    assert "README.md" in message
    assert f"observed HEAD {head}" in message
    assert "hello unrestored" in readme.read_text()
    assert _commit_journal(registry)[-1]["state"] == "uncertain"

    with pytest.raises(PolicyError, match="VEDAOPS_GIT_INDEX_DIRTY"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="retry still refused",
        )
    assert _cached_names(root) == {"README.md"}
    assert _porcelain_index_dirty_paths(root) == {"README.md"}


def test_empty_cached_name_only_does_not_prove_index_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello porcelain",
    )
    original_text = change_module.run_git_text
    original_staged = change_module._commit_staged_paths
    hide_cached_names = False

    def fail_commit(project_root: Path, *args: str, **kwargs) -> str:
        nonlocal hide_cached_names
        if args and args[0] == "commit":
            hide_cached_names = True
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure")
        return original_text(project_root, *args, **kwargs)

    def maybe_hide_cached_names(project_root: Path) -> list[str]:
        if hide_cached_names:
            return []
        return original_staged(project_root)

    monkeypatch.setattr(change_module, "run_git_text", fail_commit)
    monkeypatch.setattr(change_module, "_commit_staged_paths", maybe_hide_cached_names)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="should not claim restore",
        )

    assert git(root, "rev-parse", "HEAD") == head
    assert "README.md" in git(root, "diff", "--cached", "--name-only")
    assert _porcelain_index_dirty_paths(root) == {"README.md"}
    assert _commit_journal(registry)[-1]["state"] == "uncertain"


def test_uncertain_effect_rereads_state_after_restore_mutates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello reread",
    )
    original = change_module.run_git_text
    current_branch = git(root, "branch", "--show-current")

    def fail_commit(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated commit failure")
        return original(project_root, *args, **kwargs)

    def unstage_then_fail(project_root: Path, **kwargs) -> bool:
        change_module._unstage_paths(project_root, kwargs["staged_paths"])
        return False

    monkeypatch.setattr(change_module, "run_git_text", fail_commit)
    monkeypatch.setattr(change_module, "_restore_own_commit_staging", unstage_then_fail)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN") as caught:
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="should reread after restore",
        )

    message = str(caught.value)
    assert git(root, "rev-parse", "HEAD") == head
    assert _cached_names(root) == set()
    assert "staged none" in message
    assert f"observed HEAD {head}" in message
    assert f"branch {current_branch}" in message
    assert "hello reread" in readme.read_text()
    assert _commit_journal(registry)[-1]["state"] == "uncertain"


def test_recovered_success_does_not_treat_unavailable_status_as_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello unavailable status",
    )

    def fail_status(_project_root: Path) -> str:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "simulated status failure")

    monkeypatch.setattr(change_module, "_status_text", fail_status)
    result = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        paths=["README.md"],
        message="test: unavailable remaining status",
    )

    assert result.git_head != head
    assert result.remaining_status == "unavailable"
    record = _commit_journal(registry)[-1]
    assert record["state"] == "succeeded"
    assert "recovered after exception" in record["detail"]
    assert "remaining_status unavailable" in record["detail"]
    assert git(root, "log", "-1", "--format=%B") == "test: unavailable remaining status"


def test_matching_paths_with_different_message_is_not_recovered_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello other message",
    )
    original = change_module.run_git_text

    def commit_with_other_message(project_root: Path, *args: str, **kwargs) -> str:
        if args and args[0] == "commit":
            original(
                project_root,
                "commit",
                "--no-verify",
                "--no-gpg-sign",
                "-m",
                "not the requested message",
            )
            raise PolicyError("VEDAOPS_TEST_AFTER_COMMIT", "wrapper failure after foreign message")
        return original(project_root, *args, **kwargs)

    monkeypatch.setattr(change_module, "run_git_text", commit_with_other_message)
    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            paths=["README.md"],
            message="requested message",
        )

    drifted = git(root, "rev-parse", "HEAD")
    assert drifted != head
    assert git(root, "log", "-1", "--format=%B") == "not the requested message"
    assert _commit_journal(registry)[-1]["state"] == "uncertain"


def test_complete_local_ticket_cycle_without_terminal_git(tmp_path: Path):
    root, registry, base_head = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")

    created = project_git_branch_create(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        branch="ticket/change-test",
    )
    assert created.previous_branch == target_branch
    assert git(root, "branch", "--show-current") == "ticket/change-test"

    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="hello lifecycle",
    )
    committed = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        paths=["README.md"],
        message="test: lifecycle",
    )
    feature_head = committed.git_head

    branches = project_git_branches(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert {item.name for item in branches.branches} >= {target_branch, "ticket/change-test"}

    switched = project_git_switch(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=feature_head,
        expected_current_branch="ticket/change-test",
        branch=target_branch,
    )
    assert switched.git_head == base_head

    with pytest.raises(PolicyError, match="VEDAOPS_BRANCH_DELETE_REFUSED"):
        project_git_branch_delete(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_current_branch=target_branch,
            branch="ticket/change-test",
            expected_branch_head=feature_head,
        )

    merged = project_git_merge_ff(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        expected_target_branch=target_branch,
        source_branch="ticket/change-test",
        expected_source_head=feature_head,
    )
    assert merged.fast_forward is True
    assert git(root, "rev-parse", "HEAD") == feature_head

    deleted = project_git_branch_delete(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=feature_head,
        expected_current_branch=target_branch,
        branch="ticket/change-test",
        expected_branch_head=feature_head,
    )
    assert deleted.deleted is True
    remaining = project_git_branches(
        registry,
        principal_id="test-agent",
        project_id="example",
    )
    assert "ticket/change-test" not in {item.name for item in remaining.branches}


def test_non_fast_forward_and_dirty_switch_refuse_without_effect(tmp_path: Path):
    root, registry, base_head = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")
    project_git_branch_create(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        branch="ticket/diverge",
    )
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="feature",
    )

    with pytest.raises(PolicyError, match="VEDAOPS_WORKTREE_DIRTY"):
        project_git_switch(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_current_branch="ticket/diverge",
            branch=target_branch,
        )
    assert git(root, "branch", "--show-current") == "ticket/diverge"

    feature_commit = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        paths=["README.md"],
        message="feature",
    )
    project_git_switch(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=feature_commit.git_head,
        expected_current_branch="ticket/diverge",
        branch=target_branch,
    )
    target_file = project_file_write(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        path="target.txt",
        content="target\n",
    )
    assert target_file.sha256_after
    target_commit = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        paths=["target.txt"],
        message="target",
    )

    with pytest.raises(PolicyError, match="VEDAOPS_NON_FAST_FORWARD"):
        project_git_merge_ff(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=target_commit.git_head,
            expected_target_branch=target_branch,
            source_branch="ticket/diverge",
            expected_source_head=feature_commit.git_head,
        )
    assert git(root, "rev-parse", "HEAD") == target_commit.git_head


def test_post_effect_verification_failure_requires_state_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    original = change_module._require_current_branch
    calls = 0

    def fail_after_switch(project_root: Path) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PolicyError("VEDAOPS_TEST_VERIFY", "simulated post-effect verification failure")
        return original(project_root)

    monkeypatch.setattr(change_module, "_require_current_branch", fail_after_switch)

    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN"):
        project_git_branch_create(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            branch="ticket/uncertain",
        )

    # The native Git effect happened before verification failed. The stable
    # uncertain-effect refusal therefore prevents a blind retry.
    assert git(root, "branch", "--show-current") == "ticket/uncertain"
    assert git(root, "rev-parse", "HEAD") == head


def test_patch_refuses_delete_and_mode_semantics(tmp_path: Path):
    _root, registry, head = _change_project(tmp_path)
    patch = """diff --git a/README.md b/README.md
deleted file mode 100644
--- a/README.md
+++ /dev/null
@@ -1,2 +0,0 @@
-# Example
-hello world
"""

    with pytest.raises(PolicyError, match="VEDAOPS_PATCH_INVALID"):
        project_patch_apply(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            patch=patch,
        )


def test_branch_transition_cannot_mutate_project_authority(tmp_path: Path):
    root, registry, base_head = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")

    git(root, "switch", "-c", "ticket/authority-change")
    manifest = root / ".vedaops/project.toml"
    manifest.write_text(manifest.read_text().replace("name = 'Example'", "name = 'Changed'"))
    git(root, "add", ".vedaops/project.toml")
    git(root, "commit", "-m", "change project authority")
    source_head = git(root, "rev-parse", "HEAD")
    git(root, "switch", target_branch)

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_git_switch(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_current_branch=target_branch,
            branch="ticket/authority-change",
        )
    assert git(root, "branch", "--show-current") == target_branch
    assert git(root, "rev-parse", "HEAD") == base_head

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_git_merge_ff(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_target_branch=target_branch,
            source_branch="ticket/authority-change",
            expected_source_head=source_head,
        )
    assert git(root, "branch", "--show-current") == target_branch
    assert git(root, "rev-parse", "HEAD") == base_head


def test_branch_transition_cannot_materialize_symlink_entry(tmp_path: Path):
    root, registry, base_head = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")

    git(root, "switch", "-c", "ticket/symlink-entry")
    (root / "linked-readme").symlink_to("README.md")
    git(root, "add", "linked-readme")
    git(root, "commit", "-m", "add symlink entry")
    source_head = git(root, "rev-parse", "HEAD")
    assert git(root, "ls-tree", source_head, "linked-readme").startswith("120000 blob ")
    git(root, "switch", target_branch)

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_git_switch(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_current_branch=target_branch,
            branch="ticket/symlink-entry",
        )
    assert git(root, "branch", "--show-current") == target_branch
    assert git(root, "rev-parse", "HEAD") == base_head
    assert not (root / "linked-readme").exists()
    assert not (root / "linked-readme").is_symlink()

    with pytest.raises(PolicyError, match="VEDAOPS_PATH_FORBIDDEN"):
        project_git_merge_ff(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_target_branch=target_branch,
            source_branch="ticket/symlink-entry",
            expected_source_head=source_head,
        )
    assert git(root, "branch", "--show-current") == target_branch
    assert git(root, "rev-parse", "HEAD") == base_head
    assert not (root / "linked-readme").exists()
    assert not (root / "linked-readme").is_symlink()


def test_patch_refuses_hidden_traditional_diff_after_git_hunk(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    manifest = root / ".vedaops/project.toml"
    before_manifest = manifest.read_text()
    patch = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,2 @@
 # Example
-hello world
+hello patched
--- .vedaops/project.toml
+++ .vedaops/project.toml
@@ -1,5 +1,5 @@
 schema_version = 1
 id = 'example'
-name = 'Example'
+name = 'Changed'
 mutable = true
 capabilities = ['read', 'change']
"""

    with pytest.raises(PolicyError, match="VEDAOPS_PATCH_INVALID"):
        project_patch_apply(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            patch=patch,
        )

    assert (root / "README.md").read_text() == "# Example\nhello world\n"
    assert manifest.read_text() == before_manifest


def test_branch_switch_refuses_ignored_worktree_collision(tmp_path: Path):
    root, registry, base_head = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")

    git(root, "switch", "-c", "ticket/tracks-ignored")
    (root / "ignored.txt").write_text("tracked on source\n")
    git(root, "add", "-f", "ignored.txt")
    git(root, "commit", "-m", "track ignored path")
    source_head = git(root, "rev-parse", "HEAD")
    git(root, "switch", target_branch)
    (root / "ignored.txt").write_text("valuable local ignored work\n")

    with pytest.raises(PolicyError, match="VEDAOPS_WORKTREE_COLLISION"):
        project_git_switch(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            expected_current_branch=target_branch,
            branch="ticket/tracks-ignored",
        )

    assert git(root, "branch", "--show-current") == target_branch
    assert git(root, "rev-parse", "HEAD") == base_head
    assert (root / "ignored.txt").read_text() == "valuable local ignored work\n"
    assert source_head != base_head


def test_ff_merge_uses_verified_branch_object_not_same_named_tag(tmp_path: Path):
    root, registry, base_head = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")

    git(root, "switch", "-c", "ticket/exact-source")
    (root / "README.md").write_text("# Example\nverified branch\n")
    git(root, "add", "README.md")
    git(root, "commit", "-m", "verified source")
    source_head = git(root, "rev-parse", "HEAD")

    git(root, "switch", "-c", "wrong-tag-target")
    manifest = root / ".vedaops/project.toml"
    manifest.write_text(manifest.read_text().replace("name = 'Example'", "name = 'WrongTag'"))
    git(root, "add", ".vedaops/project.toml")
    git(root, "commit", "-m", "wrong tag protected change")
    wrong_head = git(root, "rev-parse", "HEAD")
    git(root, "tag", "ticket/exact-source", wrong_head)
    git(root, "switch", target_branch)

    result = project_git_merge_ff(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        expected_target_branch=target_branch,
        source_branch="ticket/exact-source",
        expected_source_head=source_head,
    )

    assert result.git_head == source_head
    assert git(root, "rev-parse", "HEAD") == source_head
    assert (root / "README.md").read_text() == "# Example\nverified branch\n"
    assert "WrongTag" not in manifest.read_text()


def test_commit_wrapper_failure_after_real_commit_returns_proven_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, base_head = _change_project(tmp_path)
    readme = root / "README.md"
    project_text_replace(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        path="README.md",
        expected_sha256=_sha(readme),
        find="hello world",
        replacement="commit happened",
    )

    original = change_module.run_git_text

    def fail_after_commit(project_root: Path, *args: str, **kwargs) -> str:
        result = original(project_root, *args, **kwargs)
        if args and args[0] == "commit":
            raise PolicyError("VEDAOPS_TEST_AFTER_COMMIT", "simulated wrapper failure")
        return result

    monkeypatch.setattr(change_module, "run_git_text", fail_after_commit)

    result = project_git_commit(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=base_head,
        paths=["README.md"],
        message="test: post commit failure",
    )

    assert result.git_head != base_head
    assert result.git_head == git(root, "rev-parse", "HEAD")
    assert git(root, "rev-parse", f"{result.git_head}^") == base_head
    assert result.committed_paths == ["README.md"]
    assert git(root, "diff", "--cached", "--name-only") == ""
    assert "commit happened" in readme.read_text()
    record = _commit_journal(registry)[-1]
    assert record["state"] == "succeeded"
    assert "recovered after exception" in record["detail"]
    assert git(root, "log", "-1", "--format=%B") == "test: post commit failure"


def test_manifest_alias_cannot_turn_ordinary_file_into_authority_mutation(tmp_path: Path):
    root, registry, head = _change_project(tmp_path)
    manifest = root / ".vedaops/project.toml"
    alias = root / "authority-alias.toml"
    alias.write_text(manifest.read_text())
    manifest.unlink()
    manifest.symlink_to("../authority-alias.toml")
    before = alias.read_text()

    with pytest.raises(AuthorityError, match="VEDAOPS_MANIFEST_UNAVAILABLE"):
        project_text_replace(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="authority-alias.toml",
            expected_sha256=_sha(alias),
            find="name = 'Example'",
            replacement="name = 'Escalated'",
        )

    assert alias.read_text() == before


def test_concurrent_replacement_is_preserved_instead_of_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"
    expected = _sha(readme)
    original = change_module.conditional_write_project_file

    def replace_then_write(*args, **kwargs):
        replacement = root / "README.concurrent"
        replacement.write_text("concurrent owner bytes\n")
        replacement.replace(readme)
        return original(*args, **kwargs)

    monkeypatch.setattr(change_module, "conditional_write_project_file", replace_then_write)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_text_replace(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="README.md",
            expected_sha256=expected,
            find="hello world",
            replacement="candidate bytes",
        )

    assert readme.read_text() == "concurrent owner bytes\n"


def test_parent_relocation_cannot_redirect_conditional_write_outside_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    nested = root / "nested"
    nested.mkdir()
    target = nested / "file.txt"
    target.write_text("original\n")
    git(root, "add", "nested/file.txt")
    git(root, "commit", "-q", "-m", "nested target")
    head = git(root, "rev-parse", "HEAD")
    expected = _sha(target)
    outside = tmp_path / "outside-nested"
    original = change_module.conditional_write_project_file

    def relocate_then_write(*args, **kwargs):
        nested.rename(outside)
        return original(*args, **kwargs)

    monkeypatch.setattr(change_module, "conditional_write_project_file", relocate_then_write)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_text_replace(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="nested/file.txt",
            expected_sha256=expected,
            find="original",
            replacement="candidate",
        )

    assert (outside / "file.txt").read_text() == "original\n"
    assert not nested.exists()


def test_journal_start_failure_occurs_before_nested_create_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)

    def fail_start(*args, **kwargs):
        raise PolicyError("VEDAOPS_OPERATION_RECORD_UNAVAILABLE", "simulated journal failure")

    monkeypatch.setattr(change_module, "start_operation", fail_start)

    with pytest.raises(PolicyError, match="VEDAOPS_OPERATION_RECORD_UNAVAILABLE"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="new/nested/file.txt",
            content="candidate\n",
        )

    assert not (root / "new").exists()


def test_operation_journal_location_inside_managed_project_is_refused(tmp_path: Path):
    root = tmp_path / "operations"
    head = init_project(
        root,
        capabilities=("read", "change"),
        mutable=True,
    )
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=True,
        capabilities=("read", "change"),
        principal_capabilities=("read", "change"),
    )

    with pytest.raises(AuthorityError, match="VEDAOPS_TRUSTED_PATH_INSIDE_MANAGED_PROJECT"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="new.txt",
            content="candidate\n",
        )

    assert not (root / "new.txt").exists()


def test_grafted_false_fast_forward_is_refused_before_merge_effect(tmp_path: Path):
    root, registry, base = _change_project(tmp_path)
    target_branch = git(root, "branch", "--show-current")
    git(root, "switch", "-c", "ticket/source")
    (root / "README.md").write_text("source\n")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "source")
    source = git(root, "rev-parse", "HEAD")
    git(root, "switch", target_branch)
    (root / "README.md").write_text("target\n")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "target")
    target = git(root, "rev-parse", "HEAD")
    assert git(root, "merge-base", source, target) == base
    grafts = root / ".git" / "info" / "grafts"
    grafts.parent.mkdir(parents=True, exist_ok=True)
    grafts.write_text(f"{source} {target}\n")

    with pytest.raises(PolicyError, match="VEDAOPS_PROJECT_CONFIG_UNSAFE"):
        project_git_merge_ff(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=target,
            expected_target_branch=target_branch,
            source_branch="ticket/source",
            expected_source_head=source,
        )

    assert git(root, "rev-parse", "HEAD") == target


def test_helper_parent_substitution_at_effect_boundary_cannot_reach_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    root = tmp_path / "workspace"
    ordinary = root / "ordinary"
    authority = root / ".vedaops"
    ordinary.mkdir(parents=True)
    authority.mkdir()
    target = ordinary / "project.toml"
    manifest = authority / "project.toml"
    target.write_text("ordinary\n")
    manifest.write_text("authority\n")
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest_before = manifest.read_bytes()
    relocated = root / "ordinary-original"
    original_rename = fs_helper._renameat2
    swapped = False

    def swap_before_effect(old_fd: int, old: str, new_fd: int, new: str, flags: int) -> None:
        nonlocal swapped
        if not swapped:
            ordinary.rename(relocated)
            ordinary.symlink_to(".vedaops", target_is_directory=True)
            swapped = True
        original_rename(old_fd, old, new_fd, new, flags)

    monkeypatch.setattr(fs_helper, "ROOT_PATH", str(root))
    monkeypatch.setattr(fs_helper, "_renameat2", swap_before_effect)

    code = fs_helper._write(
        "ordinary/project.toml",
        expected,
        0o644,
        b"candidate\n",
        "parent-swap",
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert code == 3
    assert payload["state"] == "uncertain"
    assert payload["effect_occurred"] is True
    assert manifest.read_bytes() == manifest_before
    assert (relocated / "project.toml").read_bytes() == b"candidate\n"


def test_helper_post_create_error_is_uncertain_after_real_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    root = tmp_path / "workspace"
    root.mkdir()
    original_rename = fs_helper._renameat2
    original_read = fs_helper._read_regular_at
    effected = False

    def rename_then_mark(old_fd: int, old: str, new_fd: int, new: str, flags: int) -> None:
        nonlocal effected
        original_rename(old_fd, old, new_fd, new, flags)
        effected = True

    def fail_post_effect(parent_fd: int, name: str) -> tuple[bytes, int]:
        if effected:
            raise OSError(5, "simulated post-create EIO")
        return original_read(parent_fd, name)

    monkeypatch.setattr(fs_helper, "ROOT_PATH", str(root))
    monkeypatch.setattr(fs_helper, "_renameat2", rename_then_mark)
    monkeypatch.setattr(fs_helper, "_read_regular_at", fail_post_effect)

    code = fs_helper._write("new.txt", "-", 0o644, b"candidate\n", "post-create")
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert code == 3
    assert payload["state"] == "uncertain"
    assert payload["effect_occurred"] is True
    assert (root / "new.txt").read_bytes() == b"candidate\n"


def test_helper_post_exchange_error_preserves_recovery_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "file.txt"
    target.write_bytes(b"original\n")
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    original_rename = fs_helper._renameat2
    original_read = fs_helper._read_regular_at
    effected = False

    def rename_then_mark(old_fd: int, old: str, new_fd: int, new: str, flags: int) -> None:
        nonlocal effected
        original_rename(old_fd, old, new_fd, new, flags)
        effected = True

    def fail_post_effect(parent_fd: int, name: str) -> tuple[bytes, int]:
        if effected:
            raise OSError(5, "simulated post-exchange EIO")
        return original_read(parent_fd, name)

    monkeypatch.setattr(fs_helper, "ROOT_PATH", str(root))
    monkeypatch.setattr(fs_helper, "_renameat2", rename_then_mark)
    monkeypatch.setattr(fs_helper, "_read_regular_at", fail_post_effect)

    code = fs_helper._write("file.txt", expected, 0o644, b"candidate\n", "post-exchange")
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert code == 3
    assert payload["state"] == "uncertain"
    assert payload["effect_occurred"] is True
    assert target.read_bytes() == b"candidate\n"
    recoveries = [root / name for name in payload["recoveries"]]
    assert len(recoveries) == 2
    assert all(path.exists() for path in recoveries)
    assert all(path.read_bytes() == b"original\n" for path in recoveries)


def test_helper_competing_replacement_is_preserved_without_reverse_exchange(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "file.txt"
    target.write_bytes(b"original\n")
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    original_rename = fs_helper._renameat2
    calls = 0

    def substitute_then_exchange(
        old_fd: int,
        old: str,
        new_fd: int,
        new: str,
        flags: int,
    ) -> None:
        nonlocal calls
        calls += 1
        competitor = root / "competitor.tmp"
        competitor.write_bytes(b"competitor\n")
        competitor.replace(target)
        original_rename(old_fd, old, new_fd, new, flags)

    monkeypatch.setattr(fs_helper, "ROOT_PATH", str(root))
    monkeypatch.setattr(fs_helper, "_renameat2", substitute_then_exchange)

    code = fs_helper._write("file.txt", expected, 0o644, b"candidate\n", "competitor")
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert code == 3
    assert payload["state"] == "uncertain"
    assert calls == 1
    assert target.read_bytes() == b"candidate\n"
    recovery_bytes = {(root / name).read_bytes() for name in payload["recoveries"]}
    assert recovery_bytes == {b"original\n", b"competitor\n"}


def test_helper_post_delete_error_preserves_removed_and_recovery_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "file.txt"
    target.write_bytes(b"original\n")
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    original_rename = fs_helper._renameat2
    original_read = fs_helper._read_regular_at
    effected = False

    def rename_then_mark(old_fd: int, old: str, new_fd: int, new: str, flags: int) -> None:
        nonlocal effected
        original_rename(old_fd, old, new_fd, new, flags)
        effected = True

    def fail_post_effect(parent_fd: int, name: str) -> tuple[bytes, int]:
        if effected:
            raise OSError(5, "simulated post-delete EIO")
        return original_read(parent_fd, name)

    monkeypatch.setattr(fs_helper, "ROOT_PATH", str(root))
    monkeypatch.setattr(fs_helper, "_renameat2", rename_then_mark)
    monkeypatch.setattr(fs_helper, "_read_regular_at", fail_post_effect)

    code = fs_helper._delete("file.txt", expected, "post-delete")
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert code == 3
    assert payload["state"] == "uncertain"
    assert payload["effect_occurred"] is True
    assert not target.exists()
    recoveries = [root / name for name in payload["recoveries"]]
    assert len(recoveries) == 2
    assert all(path.exists() for path in recoveries)
    assert all(path.read_bytes() == b"original\n" for path in recoveries)


def test_public_file_uncertainty_never_journals_failed_after_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    readme = root / "README.md"

    def effect_then_uncertain(
        project_root: Path,
        relative_path: str,
        data: bytes,
        mode: int,
        **kwargs,
    ) -> None:
        del mode, kwargs
        (project_root / relative_path).write_bytes(data)
        raise PolicyError("VEDAOPS_CHANGE_EFFECT_UNCERTAIN", "simulated post-effect uncertainty")

    monkeypatch.setattr(change_module, "conditional_write_project_file", effect_then_uncertain)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_EFFECT_UNCERTAIN"):
        project_text_replace(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="README.md",
            expected_sha256=_sha(readme),
            find="hello world",
            replacement="candidate bytes",
        )

    records = [
        json.loads(path.read_text())
        for path in (registry.parent / "operations").glob("*.json")
    ]
    record = [item for item in records if item["kind"] == "text_replace"][-1]
    assert record["state"] == "uncertain"
    assert "recovery_prefix" in record


def test_real_directory_substitution_before_helper_cannot_modify_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    init_project(root, capabilities=("read", "change"), mutable=True)
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=True,
        capabilities=("read", "change"),
        principal_capabilities=("read", "change"),
    )
    ordinary = root / "ordinary"
    ordinary.mkdir()
    authority = root / ".vedaops"
    manifest = authority / "project.toml"
    before = manifest.read_bytes()
    (ordinary / "project.toml").write_bytes(before)
    git(root, "add", "ordinary/project.toml")
    git(root, "commit", "-q", "-m", "prepare ordinary subject")
    head = git(root, "rev-parse", "HEAD")
    parked = root / "parked"
    real_helper = change_module.conditional_write_project_file

    def substitute(*args, **kwargs):
        ordinary.rename(parked)
        authority.rename(ordinary)
        try:
            return real_helper(*args, **kwargs)
        finally:
            ordinary.rename(authority)
            parked.rename(ordinary)

    monkeypatch.setattr(change_module, "conditional_write_project_file", substitute)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="ordinary/project.toml",
            content="candidate authority bytes\n",
            expected_sha256=hashlib.sha256(before).hexdigest(),
        )

    assert manifest.read_bytes() == before


@pytest.mark.parametrize("action", ["write", "delete"])
def test_preexisting_recovery_entry_is_never_unlinked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
):
    target = tmp_path / "file.txt"
    target.write_bytes(b"original\n")
    suffix = "candidate" if action == "write" else "recovery"
    collision = tmp_path / f".file.txt.vedaops-collision-{suffix}"
    collision.write_bytes(b"competing bytes\n")
    monkeypatch.setattr(fs_helper, "ROOT_PATH", str(tmp_path))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()

    if action == "write":
        code = fs_helper._write("file.txt", digest, 0o644, b"candidate\n", "collision")
    else:
        code = fs_helper._delete("file.txt", digest, "collision")

    assert code == 2
    assert collision.read_bytes() == b"competing bytes\n"


@pytest.mark.parametrize(
    ("payload", "returncode"),
    [
        ({"state": "precondition_failed", "detail": ""}, 2),
        ({"state": "precondition_failed", "detail": "", "effect_occurred": None}, 2),
        ({"state": "succeeded", "detail": "", "effect_occurred": "false"}, 0),
    ],
)
def test_malformed_effect_evidence_is_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    returncode: int,
):
    result = subprocess.CompletedProcess([], returncode, json.dumps(payload).encode(), b"")
    monkeypatch.setattr(policy_module.subprocess, "run", lambda *args, **kwargs: result)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_EFFECT_UNCERTAIN"):
        policy_module._run_file_helper(
            tmp_path,
            "write",
            "file.txt",
            "-",
            "op",
            "644",
            input_bytes=b"x",
        )


def test_cleanup_quarantines_competing_replacement_instead_of_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    root.mkdir()
    candidate = root / ".file.txt.vedaops-cleanup-candidate"
    candidate.write_bytes(b"owned recovery bytes\n")
    info = candidate.stat()
    entry = {"name": candidate.name, "dev": info.st_dev, "ino": info.st_ino}
    guard = policy_module._capture_parent_guard(root, "file.txt")
    real_rename = policy_module.os.rename
    injected = False

    def substitute_then_move(src, dst, *args, **kwargs):
        nonlocal injected
        if src == candidate.name and not injected:
            injected = True
            competitor = root / "competitor"
            competitor.write_bytes(b"competing unique bytes\n")
            competitor.replace(candidate)
        return real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(policy_module.os, "rename", substitute_then_move)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_EFFECT_UNCERTAIN"):
        policy_module._cleanup_helper_entries(
            root,
            "file.txt",
            guard,
            [entry],
            operation_id="cleanup-race",
        )

    preserved = list(tmp_path.glob(".vedaops-mcp-recovery-*/*"))
    assert len(preserved) == 1
    assert preserved[0].read_bytes() == b"competing unique bytes\n"
    shutil.rmtree(preserved[0].parent)


def test_real_directory_substitution_before_create_cannot_modify_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    ordinary = root / "ordinary"
    ordinary.mkdir()
    authority = root / ".vedaops"
    manifest = authority / "project.toml"
    before = manifest.read_bytes()
    parked = root / "parked"
    real_helper = change_module.conditional_write_project_file

    def substitute(*args, **kwargs):
        ordinary.rename(parked)
        authority.rename(ordinary)
        try:
            return real_helper(*args, **kwargs)
        finally:
            ordinary.rename(authority)
            parked.rename(ordinary)

    monkeypatch.setattr(change_module, "conditional_write_project_file", substitute)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="ordinary/new.txt",
            content="candidate\n",
        )

    assert manifest.read_bytes() == before
    assert not (authority / "new.txt").exists()
    assert not (ordinary / "new.txt").exists()


def test_real_directory_substitution_before_delete_cannot_modify_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    init_project(root, capabilities=("read", "change"), mutable=True)
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=True,
        capabilities=("read", "change"),
        principal_capabilities=("read", "change"),
    )
    ordinary = root / "ordinary"
    ordinary.mkdir()
    authority = root / ".vedaops"
    manifest = authority / "project.toml"
    before = manifest.read_bytes()
    ordinary_target = ordinary / "project.toml"
    ordinary_target.write_bytes(before)
    git(root, "add", "ordinary/project.toml")
    git(root, "commit", "-q", "-m", "prepare ordinary delete subject")
    head = git(root, "rev-parse", "HEAD")
    parked = root / "parked"
    real_helper = change_module.conditional_delete_project_file

    def substitute(*args, **kwargs):
        ordinary.rename(parked)
        authority.rename(ordinary)
        try:
            return real_helper(*args, **kwargs)
        finally:
            ordinary.rename(authority)
            parked.rename(ordinary)

    monkeypatch.setattr(change_module, "conditional_delete_project_file", substitute)

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_file_delete(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="ordinary/project.toml",
            expected_sha256=hashlib.sha256(before).hexdigest(),
        )

    assert manifest.read_bytes() == before
    assert ordinary_target.read_bytes() == before


def test_ordinary_real_directory_substitution_is_rejected_before_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    init_project(root, capabilities=("read", "change"), mutable=True)
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        mutable=True,
        capabilities=("read", "change"),
        principal_capabilities=("read", "change"),
    )
    ordinary = root / "ordinary"
    substitute = root / "substitute"
    ordinary.mkdir()
    substitute.mkdir()
    ordinary_target = ordinary / "file.txt"
    substitute_target = substitute / "file.txt"
    ordinary_target.write_bytes(b"same bytes\n")
    substitute_target.write_bytes(b"same bytes\n")
    git(root, "add", "ordinary/file.txt", "substitute/file.txt")
    git(root, "commit", "-q", "-m", "prepare directory substitution subjects")
    head = git(root, "rev-parse", "HEAD")
    parked = root / "parked"
    real_helper = change_module.conditional_write_project_file

    def substitute_before_helper(*args, **kwargs):
        ordinary.rename(parked)
        substitute.rename(ordinary)
        try:
            return real_helper(*args, **kwargs)
        finally:
            ordinary.rename(substitute)
            parked.rename(ordinary)

    monkeypatch.setattr(
        change_module,
        "conditional_write_project_file",
        substitute_before_helper,
    )

    with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
        project_file_write(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            path="ordinary/file.txt",
            content="candidate\n",
            expected_sha256=hashlib.sha256(b"same bytes\n").hexdigest(),
        )

    assert ordinary_target.read_bytes() == b"same bytes\n"
    assert substitute_target.read_bytes() == b"same bytes\n"


def test_git_directory_substitution_during_parent_capture_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, registry, head = _change_project(tmp_path)
    ordinary = root / "ordinary"
    ordinary.mkdir()
    git_directory = root / ".git"
    parked = root / "parked"
    real_capture = change_module._capture_parent_guard
    real_helper = change_module.conditional_write_project_file
    swapped = False

    def restore() -> None:
        nonlocal swapped
        if not swapped:
            return
        ordinary.rename(git_directory)
        parked.rename(ordinary)
        swapped = False

    def substitute_during_capture(*args, **kwargs):
        nonlocal swapped
        ordinary.rename(parked)
        git_directory.rename(ordinary)
        swapped = True
        try:
            return real_capture(*args, **kwargs)
        except Exception:
            restore()
            raise

    def hold_substitution_through_helper(*args, **kwargs):
        try:
            return real_helper(*args, **kwargs)
        finally:
            restore()

    monkeypatch.setattr(
        change_module,
        "_capture_parent_guard",
        substitute_during_capture,
    )
    monkeypatch.setattr(
        change_module,
        "conditional_write_project_file",
        hold_substitution_through_helper,
    )

    try:
        with pytest.raises(PolicyError, match="VEDAOPS_CHANGE_PRECONDITION_FAILED"):
            project_file_write(
                registry,
                principal_id="test-agent",
                project_id="example",
                expected_git_head=head,
                path="ordinary/new.txt",
                content="into-git\n",
            )
    finally:
        restore()

    assert not (git_directory / "new.txt").exists()
    assert not (ordinary / "new.txt").exists()
