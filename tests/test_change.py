"""MCP-04 bounded file and local Git mutation semantics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from support import git, init_project, write_registry

import vedaops_mcp.change as change_module
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


def test_commit_wrapper_failure_after_real_commit_is_effect_uncertain(
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

    with pytest.raises(PolicyError, match="VEDAOPS_GIT_EFFECT_UNCERTAIN"):
        project_git_commit(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=base_head,
            paths=["README.md"],
            message="test: post commit failure",
        )

    assert git(root, "rev-parse", "HEAD") != base_head
    records = [
        json.loads(path.read_text())
        for path in (registry.parent / "operations").glob("*.json")
    ]
    commit_records = [item for item in records if item["kind"] == "git_commit"]
    assert commit_records[-1]["state"] == "uncertain"


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
