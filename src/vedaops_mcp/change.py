"""Bounded local file and native Git mutation plane.

MCP-04 deliberately exposes goal-oriented operations rather than shell or
caller-selected Git argv. Managed repositories remain untrusted inputs.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict

from vedaops_mcp.authority import AuthorizedProject, get_authorized_project
from vedaops_mcp.errors import AuthorityError, PolicyError
from vedaops_mcp.operations import OperationJournal, start_operation
from vedaops_mcp.policy import (
    MAX_FILE_BYTES,
    MAX_GIT_RESULT_BYTES,
    _capture_parent_guard,
    conditional_delete_project_file,
    conditional_write_project_file,
    ensure_mutation_path,
    ensure_not_ignored,
    git_environment,
    literal_pathspec,
    normalize_relative,
    project_lstat,
    protected_reason,
    read_bounded_file,
    resolve_within_root,
    run_git_bytes,
    run_git_input,
    run_git_text,
)

COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_PATCH_BYTES = 256 * 1024
MAX_PATCH_FILES = 64
MAX_COMMIT_PATHS = 64
MAX_COMMIT_MESSAGE_BYTES = 8192
MAX_BRANCH_NAME_BYTES = 240
MAX_DIFF_FILES = 200


class FileChangeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    project_id: str
    workspace_id: str
    git_head: str
    path: str
    action: str
    sha256_before: str | None
    sha256_after: str | None
    bytes_after: int | None


class PatchApplyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    project_id: str
    workspace_id: str
    git_head: str
    files_changed: list[str]
    applied: bool


class GitDiffResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    staged: bool
    path: str | None
    files: list[str]
    excluded_count: int
    diff: str
    bytes_returned: int
    truncated: bool


class BranchEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    git_head: str
    current: bool


class BranchListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    branches: list[BranchEntry]
    returned_count: int


class BranchChangeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    project_id: str
    workspace_id: str
    action: str
    branch: str
    previous_branch: str
    previous_head: str
    git_head: str


class GitCommitResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    project_id: str
    workspace_id: str
    branch: str
    git_head_before: str
    git_head: str
    committed_paths: list[str]
    remaining_status: str


class GitMergeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    project_id: str
    workspace_id: str
    target_branch: str
    source_branch: str
    git_head_before: str
    source_head: str
    git_head: str
    fast_forward: bool


class BranchDeleteResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    project_id: str
    workspace_id: str
    branch: str
    deleted_head: str
    current_branch: str
    current_head: str
    deleted: bool


def project_file_write(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    path: str,
    content: str,
    expected_sha256: str | None = None,
) -> FileChangeResult:
    """Create or replace one bounded UTF-8 file under exact preconditions."""
    if not isinstance(content, str) or "\x00" in content:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "content must be UTF-8 text")
    raw = content.encode("utf-8")
    if len(raw) > MAX_FILE_BYTES:
        raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", "file content exceeds the hard limit")
    expected_digest = _optional_sha256(expected_sha256)
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        normalized, _target = _mutation_target(project.root, path, must_exist=False)
        before_raw: bytes | None = None
        before_mode = 0o644
        info = project_lstat(project.root, normalized)
        if info is None:
            if expected_digest is not None:
                raise PolicyError(
                    "VEDAOPS_CHANGE_PRECONDITION_FAILED",
                    "expected_sha256 was supplied but the target does not exist",
                )
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{normalized} is not a regular file")
            before_raw, before_info = read_bounded_file(
                project.root,
                normalized,
                limit_bytes=MAX_FILE_BYTES,
            )
            if before_info.st_size > MAX_FILE_BYTES or len(before_raw) != before_info.st_size:
                raise PolicyError(
                    "VEDAOPS_CHANGE_TOO_LARGE",
                    "existing file exceeds the hard limit",
                )
            before_mode = stat.S_IMODE(before_info.st_mode)
            actual = hashlib.sha256(before_raw).hexdigest()
            if expected_digest is None or actual != expected_digest:
                raise PolicyError(
                    "VEDAOPS_CHANGE_PRECONDITION_FAILED",
                    "existing file SHA-256 does not match expected_sha256",
                )
            if before_raw == raw:
                raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "write would not change the file")

        parent_guard = _capture_parent_guard(
            project.root,
            normalized,
            authorized_root_identity=project.authorized_root_identity,
            protected_parent_identities=project.protected_parent_identities,
        )
        journal = start_operation(
            registry_path,
            kind="file_write",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={
                "path": normalized,
                "action": "create" if before_raw is None else "replace",
                "expected_sha256": expected_digest,
            },
        )
        recovery_prefix = f".{Path(normalized).name}.vedaops-{journal.operation_id}"
        journal.update(
            recovery_directory=Path(normalized).parent.as_posix(),
            recovery_prefix=recovery_prefix,
        )
        try:
            conditional_write_project_file(
                project.root,
                normalized,
                raw,
                before_mode,
                expected_sha256=expected_digest,
                operation_id=journal.operation_id,
                authorized_root_identity=project.authorized_root_identity,
                protected_parent_identities=project.protected_parent_identities,
                parent_guard=parent_guard,
            )
            _verify_file(project.root, normalized, raw)
            _require_head(project.root, expected_git_head)
        except PolicyError as exc:
            if exc.code == "VEDAOPS_CHANGE_PRECONDITION_FAILED":
                journal.terminal("failed", detail=str(exc))
                raise
            journal.terminal("uncertain", detail=str(exc))
            if exc.code == "VEDAOPS_CHANGE_EFFECT_UNCERTAIN":
                raise
            raise _change_effect_uncertain("file write") from exc
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _change_effect_uncertain("file write") from exc
        journal.terminal("succeeded")
        return FileChangeResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            git_head=expected_git_head,
            path=normalized,
            action="created" if before_raw is None else "written",
            sha256_before=(
                hashlib.sha256(before_raw).hexdigest()
                if before_raw is not None
                else None
            ),
            sha256_after=hashlib.sha256(raw).hexdigest(),
            bytes_after=len(raw),
        )


def project_text_replace(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    path: str,
    expected_sha256: str,
    find: str,
    replacement: str,
) -> FileChangeResult:
    """Replace exactly one text occurrence in one bounded UTF-8 file."""
    if not isinstance(find, str) or not find or "\x00" in find:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "find must be non-empty UTF-8 text")
    if not isinstance(replacement, str) or "\x00" in replacement:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "replacement must be UTF-8 text")
    if find == replacement:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "replacement must change the matched text")
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    expected_digest = _required_sha256(expected_sha256)
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        normalized, _target = _mutation_target(project.root, path, must_exist=True)
        raw, info = read_bounded_file(project.root, normalized, limit_bytes=MAX_FILE_BYTES)
        if info.st_size > MAX_FILE_BYTES or len(raw) != info.st_size:
            raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", "file exceeds the hard limit")
        actual_digest = hashlib.sha256(raw).hexdigest()
        if actual_digest != expected_digest:
            raise PolicyError(
                "VEDAOPS_CHANGE_PRECONDITION_FAILED",
                "file SHA-256 does not match expected_sha256",
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("VEDAOPS_FILE_INVALID_ENCODING", "target is not UTF-8") from exc
        count = text.count(find)
        if count != 1:
            raise PolicyError(
                "VEDAOPS_CHANGE_MATCH_COUNT",
                f"find must occur exactly once; found {count} occurrences",
            )
        updated = text.replace(find, replacement, 1).encode("utf-8")
        if len(updated) > MAX_FILE_BYTES:
            raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", "replacement exceeds the hard limit")
        mode = stat.S_IMODE(info.st_mode)
        parent_guard = _capture_parent_guard(
            project.root,
            normalized,
            authorized_root_identity=project.authorized_root_identity,
            protected_parent_identities=project.protected_parent_identities,
        )
        journal = start_operation(
            registry_path,
            kind="text_replace",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"path": normalized, "expected_sha256": expected_digest},
        )
        recovery_prefix = f".{Path(normalized).name}.vedaops-{journal.operation_id}"
        journal.update(
            recovery_directory=Path(normalized).parent.as_posix(),
            recovery_prefix=recovery_prefix,
        )
        try:
            conditional_write_project_file(
                project.root,
                normalized,
                updated,
                mode,
                expected_sha256=expected_digest,
                operation_id=journal.operation_id,
                authorized_root_identity=project.authorized_root_identity,
                protected_parent_identities=project.protected_parent_identities,
                parent_guard=parent_guard,
            )
            _verify_file(project.root, normalized, updated)
            _require_head(project.root, expected_git_head)
        except PolicyError as exc:
            if exc.code == "VEDAOPS_CHANGE_PRECONDITION_FAILED":
                journal.terminal("failed", detail=str(exc))
                raise
            journal.terminal("uncertain", detail=str(exc))
            if exc.code == "VEDAOPS_CHANGE_EFFECT_UNCERTAIN":
                raise
            raise _change_effect_uncertain("text replacement") from exc
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _change_effect_uncertain("text replacement") from exc
        journal.terminal("succeeded")
        return FileChangeResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            git_head=expected_git_head,
            path=normalized,
            action="replaced",
            sha256_before=actual_digest,
            sha256_after=hashlib.sha256(updated).hexdigest(),
            bytes_after=len(updated),
        )


def project_file_delete(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    path: str,
    expected_sha256: str,
) -> FileChangeResult:
    """Delete one bounded regular file after exact hash verification."""
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    expected_digest = _required_sha256(expected_sha256)
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        normalized, _target = _mutation_target(project.root, path, must_exist=True)
        raw, info = read_bounded_file(project.root, normalized, limit_bytes=MAX_FILE_BYTES)
        if info.st_size > MAX_FILE_BYTES or len(raw) != info.st_size:
            raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", "file exceeds the hard limit")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected_digest:
            raise PolicyError(
                "VEDAOPS_CHANGE_PRECONDITION_FAILED",
                "file SHA-256 does not match expected_sha256",
            )
        parent_guard = _capture_parent_guard(
            project.root,
            normalized,
            authorized_root_identity=project.authorized_root_identity,
            protected_parent_identities=project.protected_parent_identities,
        )
        journal = start_operation(
            registry_path,
            kind="file_delete",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"path": normalized, "expected_sha256": expected_digest},
        )
        recovery_prefix = f".{Path(normalized).name}.vedaops-{journal.operation_id}"
        journal.update(
            recovery_directory=Path(normalized).parent.as_posix(),
            recovery_prefix=recovery_prefix,
        )
        try:
            conditional_delete_project_file(
                project.root,
                normalized,
                expected_sha256=expected_digest,
                operation_id=journal.operation_id,
                authorized_root_identity=project.authorized_root_identity,
                protected_parent_identities=project.protected_parent_identities,
                parent_guard=parent_guard,
            )
            if project_lstat(project.root, normalized) is not None:
                raise PolicyError("VEDAOPS_CHANGE_VERIFY_FAILED", "deleted file still exists")
            _require_head(project.root, expected_git_head)
        except PolicyError as exc:
            if exc.code == "VEDAOPS_CHANGE_PRECONDITION_FAILED":
                journal.terminal("failed", detail=str(exc))
                raise
            journal.terminal("uncertain", detail=str(exc))
            if exc.code == "VEDAOPS_CHANGE_EFFECT_UNCERTAIN":
                raise
            raise _change_effect_uncertain("file deletion") from exc
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _change_effect_uncertain("file deletion") from exc
        journal.terminal("succeeded")
        return FileChangeResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            git_head=expected_git_head,
            path=normalized,
            action="deleted",
            sha256_before=actual,
            sha256_after=None,
            bytes_after=None,
        )


def project_patch_apply(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    patch: str,
) -> PatchApplyResult:
    """Apply one bounded Git-compatible text patch after path validation."""
    if not isinstance(patch, str) or not patch or "\x00" in patch:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "patch must be non-empty UTF-8 text")
    raw = patch.encode("utf-8")
    if len(raw) > MAX_PATCH_BYTES:
        raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", "patch exceeds the hard limit")
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        paths = _validated_patch_paths(project.root, patch)
        run_git_input(
            project.root,
            "apply",
            "--check",
            "--whitespace=nowarn",
            input_bytes=raw,
        )
        journal = start_operation(
            registry_path,
            kind="patch_apply",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"paths": paths},
        )
        try:
            run_git_input(
                project.root,
                "apply",
                "--whitespace=nowarn",
                input_bytes=raw,
            )
            _verify_patch_targets(project.root, paths)
            _require_head(project.root, expected_git_head)
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _change_effect_uncertain("patch application") from exc
        journal.terminal("succeeded")
        return PatchApplyResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            git_head=expected_git_head,
            files_changed=paths,
            applied=True,
        )


def project_git_diff(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    staged: bool = False,
    path: str | None = None,
) -> GitDiffResult:
    """Return one bounded native working-tree or index diff."""
    project = get_authorized_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        capability="read",
    )
    normalized_path: str | None = None
    if path is not None:
        normalized_path = normalize_relative(path)
        reason = protected_reason(normalized_path)
        if reason is not None:
            raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{normalized_path} is a {reason}")
    base_args = ["diff", "--name-only", "-z", "--no-renames"]
    if staged:
        base_args.append("--cached")
    if normalized_path is not None:
        base_args.extend(["--", literal_pathspec(normalized_path)])
    raw_names = run_git_bytes(project.root, *base_args)
    visible: list[str] = []
    excluded = 0
    for raw_name in raw_names.split(b"\x00"):
        if not raw_name:
            continue
        try:
            item = normalize_relative(raw_name.decode("utf-8"))
        except (UnicodeDecodeError, PolicyError):
            excluded += 1
            continue
        if protected_reason(item) is not None:
            excluded += 1
            continue
        visible.append(item)
    if len(visible) > MAX_DIFF_FILES:
        raise PolicyError("VEDAOPS_GIT_OUTPUT_TOO_LARGE", "diff contains too many files")
    if not visible:
        return GitDiffResult(
            project_id=project.id,
            workspace_id=project.workspace_id,
            staged=staged,
            path=normalized_path,
            files=[],
            excluded_count=excluded,
            diff="",
            bytes_returned=0,
            truncated=False,
        )
    args = ["diff", "--no-ext-diff", "--no-renames", "--no-color"]
    if staged:
        args.append("--cached")
    args.extend(["--", *(literal_pathspec(item) for item in visible)])
    raw_diff = run_git_bytes(project.root, *args, limit_bytes=MAX_GIT_RESULT_BYTES)
    try:
        text = raw_diff.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "diff output is not UTF-8") from exc
    return GitDiffResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        staged=staged,
        path=normalized_path,
        files=visible,
        excluded_count=excluded,
        diff=text,
        bytes_returned=len(raw_diff),
        truncated=False,
    )


def project_git_branches(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
) -> BranchListResult:
    """List local branch names and exact local tips."""
    project = get_authorized_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        capability="read",
    )
    current = _current_branch(project.root)
    raw = run_git_text(
        project.root,
        "for-each-ref",
        "--sort=refname",
        "--format=%(refname:short)%09%(objectname)",
        "refs/heads",
    )
    entries: list[BranchEntry] = []
    if raw:
        for line in raw.splitlines():
            name, separator, head = line.partition("\t")
            if not separator or not COMMIT_PATTERN.fullmatch(head):
                raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "branch output was malformed")
            entries.append(BranchEntry(name=name, git_head=head, current=name == current))
    return BranchListResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        branches=entries,
        returned_count=len(entries),
    )


def project_git_commit(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    paths: Sequence[str],
    message: str,
) -> GitCommitResult:
    """Commit exactly named changed paths while refusing pre-existing staged state."""
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    commit_paths = _commit_paths(project.root, paths)
    commit_message = _commit_message(message)
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        branch = _require_current_branch(project.root)
        status_records = _status_records(project.root)
        if any(index_state not in {" ", "?"} for index_state, _work, _path in status_records):
            raise PolicyError(
                "VEDAOPS_GIT_INDEX_DIRTY",
                "pre-existing staged/index changes must be committed or cleared first",
            )
        changed = {item for _index, _work, item in status_records}
        missing = [item for item in commit_paths if item not in changed]
        if missing:
            raise PolicyError(
                "VEDAOPS_COMMIT_PATH_MISMATCH",
                f"requested path {missing[0]!r} has no working-tree change",
            )
        pathspecs = [literal_pathspec(item) for item in commit_paths]
        journal = start_operation(
            registry_path,
            kind="git_commit",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"branch": branch, "paths": commit_paths},
        )
        try:
            run_git_text(project.root, "add", "-A", "--", *pathspecs)
            staged = _commit_staged_paths(project.root)
            if set(staged) != set(commit_paths) or len(staged) != len(commit_paths):
                raise PolicyError(
                    "VEDAOPS_COMMIT_PATH_MISMATCH",
                    "staged path set does not exactly match requested commit paths",
                )
            run_git_text(
                project.root,
                "commit",
                "--no-verify",
                "--no-gpg-sign",
                "-m",
                commit_message,
            )
            new_head = run_git_text(project.root, "rev-parse", "HEAD")
            parent = run_git_text(project.root, "rev-parse", f"{new_head}^")
            committed = _commit_tree_paths(project.root, new_head)
            if parent != expected_git_head or set(committed) != set(commit_paths):
                raise PolicyError(
                    "VEDAOPS_COMMIT_VERIFY_FAILED",
                    "resulting commit does not match the requested parent/path set",
                )
            if _commit_staged_paths(project.root):
                raise PolicyError(
                    "VEDAOPS_COMMIT_VERIFY_FAILED",
                    "index is unexpectedly dirty after the exact commit",
                )
            remaining_status = _status_text(project.root)
        except Exception as exc:
            return _finish_git_commit_attempt(
                project.root,
                journal=journal,
                project_id=project.id,
                workspace_id=project.workspace_id,
                branch=branch,
                expected_git_head=expected_git_head,
                commit_paths=commit_paths,
                commit_message=commit_message,
                exc=exc,
            )
        journal.terminal("succeeded")
        return GitCommitResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            branch=branch,
            git_head_before=expected_git_head,
            git_head=new_head,
            committed_paths=sorted(committed),
            remaining_status=remaining_status,
        )


def project_git_branch_create(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    branch: str,
) -> BranchChangeResult:
    """Create and switch to one new local branch from the exact current HEAD."""
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    branch = _branch_name(branch)
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        previous = _require_current_branch(project.root)
        _require_clean(project.root)
        if _branch_head(project.root, branch) is not None:
            raise PolicyError("VEDAOPS_BRANCH_EXISTS", f"local branch {branch!r} already exists")
        journal = start_operation(
            registry_path,
            kind="git_branch_create",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"branch": branch, "previous_branch": previous},
        )
        try:
            run_git_text(
                project.root,
                "switch",
                "--no-guess",
                "--no-track",
                "-c",
                branch,
                expected_git_head,
            )
            if _require_current_branch(project.root) != branch:
                raise PolicyError("VEDAOPS_GIT_VERIFY_FAILED", "new branch was not selected")
            _require_head(project.root, expected_git_head)
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _git_effect_uncertain("local branch creation/switch") from exc
        journal.terminal("succeeded")
        return BranchChangeResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            action="created_and_switched",
            branch=branch,
            previous_branch=previous,
            previous_head=expected_git_head,
            git_head=expected_git_head,
        )


def project_git_switch(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    expected_current_branch: str,
    branch: str,
) -> BranchChangeResult:
    """Safely switch between existing local branches with no stash or force."""
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    expected_current_branch = _branch_name(expected_current_branch)
    branch = _branch_name(branch)
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        current = _require_current_branch(project.root)
        if current != expected_current_branch:
            raise PolicyError(
                "VEDAOPS_GIT_PRECONDITION_FAILED",
                "current branch does not match expected_current_branch",
            )
        if branch == current:
            raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "target branch is already current")
        target_head = _branch_head(project.root, branch)
        if target_head is None:
            raise PolicyError(
                "VEDAOPS_BRANCH_UNAVAILABLE",
                f"local branch {branch!r} does not exist",
            )
        _require_clean(project.root)
        _require_safe_tree_transition(project.root, expected_git_head, target_head)
        journal = start_operation(
            registry_path,
            kind="git_switch",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"from_branch": current, "to_branch": branch, "to_head": target_head},
        )
        try:
            run_git_text(project.root, "switch", "--no-guess", branch)
            if _require_current_branch(project.root) != branch:
                raise PolicyError("VEDAOPS_GIT_VERIFY_FAILED", "target branch was not selected")
            _require_head(project.root, target_head)
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _git_effect_uncertain("local branch switch") from exc
        journal.terminal("succeeded")
        return BranchChangeResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            action="switched",
            branch=branch,
            previous_branch=current,
            previous_head=expected_git_head,
            git_head=target_head,
        )


def project_git_merge_ff(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    expected_target_branch: str,
    source_branch: str,
    expected_source_head: str,
) -> GitMergeResult:
    """Fast-forward the current local target branch to one exact local source tip."""
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    target = _branch_name(expected_target_branch)
    source = _branch_name(source_branch)
    source_head = _validated_commit(expected_source_head, "expected_source_head")
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        current = _require_current_branch(project.root)
        if current != target:
            raise PolicyError(
                "VEDAOPS_GIT_PRECONDITION_FAILED",
                "current branch does not match expected_target_branch",
            )
        if source == target:
            raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "source and target branches must differ")
        actual_source = _branch_head(project.root, source)
        if actual_source != source_head:
            raise PolicyError(
                "VEDAOPS_GIT_PRECONDITION_FAILED",
                "source branch tip does not match expected_source_head",
            )
        _require_clean(project.root)
        merge_base = run_git_text(project.root, "merge-base", expected_git_head, source_head)
        if merge_base != expected_git_head:
            raise PolicyError(
                "VEDAOPS_NON_FAST_FORWARD",
                "source branch cannot fast-forward the current target",
            )
        _require_safe_tree_transition(project.root, expected_git_head, source_head)
        journal = start_operation(
            registry_path,
            kind="git_merge_ff",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={
                "target_branch": target,
                "source_branch": source,
                "source_head": source_head,
            },
        )
        try:
            run_git_text(project.root, "merge", "--ff-only", "--no-edit", source_head)
            _require_head(project.root, source_head)
            if _require_current_branch(project.root) != target:
                raise PolicyError("VEDAOPS_GIT_VERIFY_FAILED", "target branch changed unexpectedly")
            _require_clean(project.root)
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _git_effect_uncertain("local fast-forward integration") from exc
        journal.terminal("succeeded")
        return GitMergeResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            target_branch=target,
            source_branch=source,
            git_head_before=expected_git_head,
            source_head=source_head,
            git_head=source_head,
            fast_forward=True,
        )


def project_git_branch_delete(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    expected_current_branch: str,
    branch: str,
    expected_branch_head: str,
) -> BranchDeleteResult:
    """Delete one non-current local branch only after Git proves it merged."""
    project = _change_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        expected_git_head=expected_git_head,
    )
    current_expected = _branch_name(expected_current_branch)
    branch = _branch_name(branch)
    branch_head_expected = _validated_commit(expected_branch_head, "expected_branch_head")
    with _project_lock(project.root):
        _require_head(project.root, expected_git_head)
        current = _require_current_branch(project.root)
        if current != current_expected:
            raise PolicyError(
                "VEDAOPS_GIT_PRECONDITION_FAILED",
                "current branch does not match expected_current_branch",
            )
        if branch == current:
            raise PolicyError("VEDAOPS_BRANCH_DELETE_REFUSED", "cannot delete the current branch")
        actual = _branch_head(project.root, branch)
        if actual != branch_head_expected:
            raise PolicyError(
                "VEDAOPS_GIT_PRECONDITION_FAILED",
                "branch tip does not match expected_branch_head",
            )
        _require_clean(project.root)
        merge_base = run_git_text(
            project.root,
            "merge-base",
            branch_head_expected,
            expected_git_head,
        )
        if merge_base != branch_head_expected:
            raise PolicyError(
                "VEDAOPS_BRANCH_DELETE_REFUSED",
                "branch is not merged into the current target",
            )
        journal = start_operation(
            registry_path,
            kind="git_branch_delete",
            project_id=project.id,
            expected_git_head=expected_git_head,
            principal_id=project.principal_id,
            workspace_id=project.workspace_id,
            project_root=project.root,
            subject={"branch": branch, "branch_head": branch_head_expected},
        )
        try:
            run_git_text(project.root, "branch", "-d", "--", branch)
            if _branch_head(project.root, branch) is not None:
                raise PolicyError(
                    "VEDAOPS_GIT_VERIFY_FAILED",
                    "local branch deletion was not verified",
                )
        except Exception as exc:
            journal.terminal("uncertain", detail=str(exc))
            raise _git_effect_uncertain("local branch deletion") from exc
        journal.terminal("succeeded")
        return BranchDeleteResult(
            operation_id=journal.operation_id,
            project_id=project.id,
            workspace_id=project.workspace_id,
            branch=branch,
            deleted_head=branch_head_expected,
            current_branch=current,
            current_head=expected_git_head,
            deleted=True,
        )


def _finish_git_commit_attempt(
    root: Path,
    *,
    journal: OperationJournal,
    project_id: str,
    workspace_id: str,
    branch: str,
    expected_git_head: str,
    commit_paths: Sequence[str],
    commit_message: str,
    exc: BaseException,
) -> GitCommitResult:
    """Classify a failed commit attempt: proven success, restored index, or uncertain."""
    proven = _proven_exact_commit(
        root,
        expected_git_head=expected_git_head,
        branch=branch,
        commit_paths=commit_paths,
        commit_message=commit_message,
    )
    if proven is not None:
        remaining_status = proven[2]
        detail = (
            "recovered after exception; observed matching parent, paths, and commit message"
        )
        if remaining_status == "unavailable":
            detail += "; remaining_status unavailable"
        journal.terminal("succeeded", detail=detail)
        return GitCommitResult(
            operation_id=journal.operation_id,
            project_id=project_id,
            workspace_id=workspace_id,
            branch=branch,
            git_head_before=expected_git_head,
            git_head=proven[0],
            committed_paths=sorted(proven[1]),
            remaining_status=remaining_status,
        )

    restored = False
    try:
        actual_head = run_git_text(root, "rev-parse", "HEAD")
        staged_paths = _commit_staged_paths(root)
        current_branch = _current_branch(root)
        if (
            actual_head == expected_git_head
            and current_branch == branch
            and set(staged_paths) <= set(commit_paths)
        ):
            restored = _restore_own_commit_staging(
                root,
                expected_git_head=expected_git_head,
                branch=branch,
                staged_paths=staged_paths,
            )
    except Exception:
        restored = False

    if restored:
        journal.terminal("failed", detail=str(exc))
        if isinstance(exc, PolicyError) and exc.code != "VEDAOPS_GIT_EFFECT_UNCERTAIN":
            raise exc
        raise PolicyError(
            "VEDAOPS_GIT_UNAVAILABLE",
            "local commit failed; index was restored to the pre-operation state",
        ) from exc

    actual_head, branch_note, staged_paths = _observe_commit_effect_evidence(root)
    journal.terminal("uncertain", detail=str(exc))
    raise _git_commit_effect_uncertain(
        expected_git_head=expected_git_head,
        actual_head=actual_head,
        branch=branch_note,
        staged_paths=staged_paths,
    ) from exc


def _proven_exact_commit(
    root: Path,
    *,
    expected_git_head: str,
    branch: str,
    commit_paths: Sequence[str],
    commit_message: str,
) -> tuple[str, list[str], str] | None:
    """Return HEAD/paths/status when a matching exact-path child commit is observed.

    This does not prove that this invocation created the commit. It only classifies
    an already-present matching parent, path set, and commit message.
    """
    try:
        head = run_git_text(root, "rev-parse", "HEAD")
        if COMMIT_PATTERN.fullmatch(head) is None or head == expected_git_head:
            return None
        if _current_branch(root) != branch:
            return None
        lineage = run_git_text(root, "rev-list", "--parents", "-n", "1", head).split()
        if lineage != [head, expected_git_head]:
            return None
        committed = _commit_tree_paths(root, head)
        if set(committed) != set(commit_paths) or len(committed) != len(commit_paths):
            return None
        observed_message = run_git_text(root, "log", "-1", "--format=%B", head)
        if observed_message != commit_message:
            return None
        if _commit_staged_paths(root):
            return None
    except PolicyError:
        return None
    try:
        remaining_status = _status_text(root)
    except PolicyError:
        remaining_status = "unavailable"
    return head, committed, remaining_status


def _restore_own_commit_staging(
    root: Path,
    *,
    expected_git_head: str,
    branch: str,
    staged_paths: Sequence[str],
) -> bool:
    """Unstage only this attempt's paths when HEAD/branch/index are still proven."""
    try:
        if run_git_text(root, "rev-parse", "HEAD") != expected_git_head:
            return False
        if _current_branch(root) != branch:
            return False
        if staged_paths:
            _unstage_paths(root, staged_paths)
            if run_git_text(root, "rev-parse", "HEAD") != expected_git_head:
                return False
            if _current_branch(root) != branch:
                return False
        if _commit_staged_paths(root):
            return False
        status = _status_records(root)
        if any(index not in {" ", "?"} for index, _work, _path in status):
            return False
        if staged_paths:
            changed = {path for _index, _work, path in status}
            if any(path not in changed for path in staged_paths):
                return False
    except PolicyError:
        return False
    return True


def _observe_commit_effect_evidence(
    root: Path,
) -> tuple[str | None, str, list[str] | None]:
    """Re-read HEAD, branch, and staged paths for a final uncertain-effect report."""
    try:
        actual_head = run_git_text(root, "rev-parse", "HEAD")
    except PolicyError:
        actual_head = None
    try:
        observed_branch = _current_branch(root)
        branch_note = observed_branch or "detached"
    except PolicyError:
        branch_note = "unavailable"
    try:
        staged_paths = _commit_staged_paths(root)
    except PolicyError:
        staged_paths = None
    return actual_head, branch_note, staged_paths


def _git_commit_effect_uncertain(
    *,
    expected_git_head: str,
    actual_head: str | None,
    branch: str,
    staged_paths: Sequence[str] | None,
) -> PolicyError:
    if staged_paths is None:
        staged_note = "unavailable"
    elif not staged_paths:
        staged_note = "none"
    else:
        staged_note = ", ".join(staged_paths)
    return PolicyError(
        "VEDAOPS_GIT_EFFECT_UNCERTAIN",
        "local commit may have changed local Git state; inspect branch, HEAD, index, and working "
        f"tree before retrying; expected HEAD {expected_git_head}; observed HEAD "
        f"{actual_head or 'unavailable'}; branch {branch}; staged {staged_note}",
    )


def _git_effect_uncertain(action: str) -> PolicyError:
    return PolicyError(
        "VEDAOPS_GIT_EFFECT_UNCERTAIN",
        f"{action} may have changed local Git state; inspect branch, HEAD, index, and working "
        "tree before retrying",
    )


def _change_effect_uncertain(action: str) -> PolicyError:
    return PolicyError(
        "VEDAOPS_CHANGE_EFFECT_UNCERTAIN",
        f"{action} could not prove rollback; inspect the exact path before retrying",
    )


def _change_project(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
) -> AuthorizedProject:
    _validated_commit(expected_git_head, "expected_git_head")
    project = get_authorized_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        capability="change",
    )
    if not project.mutable:
        raise AuthorityError(
            "VEDAOPS_PROJECT_IMMUTABLE",
            f"project {project.id!r} is not mutable after policy intersection",
        )
    _require_head(project.root, expected_git_head)
    return project


def _validated_commit(value: str, argument: str) -> str:
    if not isinstance(value, str) or COMMIT_PATTERN.fullmatch(value) is None:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"{argument} must be a lowercase 40-hex commit",
        )
    return value


def _require_head(root: Path, expected: str) -> None:
    expected = _validated_commit(expected, "expected_git_head")
    actual = run_git_text(root, "rev-parse", "HEAD")
    if actual != expected:
        raise PolicyError(
            "VEDAOPS_GIT_PRECONDITION_FAILED",
            "expected_git_head does not match the current project HEAD",
        )


def _optional_sha256(value: str | None) -> str | None:
    return None if value is None else _required_sha256(value)


def _required_sha256(value: str) -> str:
    normalized = value.lower() if isinstance(value, str) else ""
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "expected_sha256 must be a SHA-256 digest")
    return normalized


def _mutation_target(root: Path, path: str, *, must_exist: bool) -> tuple[str, Path]:
    normalized = normalize_relative(path)
    ensure_mutation_path(normalized)
    ensure_not_ignored(root, normalized)
    target = root.joinpath(*PurePosixPath(normalized).parts)
    resolved = resolve_within_root(root, normalized, must_exist=must_exist)
    if resolved != target:
        raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{normalized} resolves through a symlink")
    return normalized, target


def _ensure_parent_directories(root: Path, parent: Path) -> list[Path]:
    missing: list[Path] = []
    cursor = parent
    while cursor != root and not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if cursor != root:
        try:
            if not cursor.is_dir() or cursor.is_symlink():
                raise PolicyError("VEDAOPS_PATH_FORBIDDEN", "file parent is not a real directory")
        except OSError as exc:
            raise PolicyError("VEDAOPS_FILE_UNAVAILABLE", "file parent is unavailable") from exc
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
    return missing


def _remove_empty_directories(directories: Sequence[Path]) -> None:
    for directory in directories:
        try:
            directory.rmdir()
        except OSError:
            continue


def _atomic_write(target: Path, data: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.vedaops.", dir=target.parent)
    temp_path = Path(temporary)
    descriptor_open = True
    try:
        os.fchmod(descriptor, mode & 0o777)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor_open = False
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(target)
    finally:
        if descriptor_open:
            os.close(descriptor)
        temp_path.unlink(missing_ok=True)


def _verify_file(root: Path, path: str, expected: bytes) -> None:
    raw, info = read_bounded_file(root, path, limit_bytes=MAX_FILE_BYTES)
    if info.st_size != len(expected) or raw != expected:
        raise PolicyError(
            "VEDAOPS_CHANGE_VERIFY_FAILED",
            "written file bytes could not be verified",
        )


def _validated_patch_paths(root: Path, patch: str) -> list[str]:
    """Authorize the complete effect set parsed by Git, not a hand-parsed prefix."""
    raw_patch = patch.encode("utf-8")
    summary = run_git_input(
        root,
        "apply",
        "--summary",
        "--whitespace=nowarn",
        input_bytes=raw_patch,
    )
    if summary.strip():
        raise PolicyError(
            "VEDAOPS_PATCH_INVALID",
            "patch structural effects such as create/delete/rename/copy/mode are not allowed",
        )
    numstat = run_git_input(
        root,
        "apply",
        "--numstat",
        "-z",
        "--whitespace=nowarn",
        input_bytes=raw_patch,
    )
    paths: list[str] = []
    for record in numstat.split(b"\x00"):
        if not record:
            continue
        try:
            added, deleted, raw_path = record.split(b"\t", 2)
            path = normalize_relative(raw_path.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, PolicyError) as exc:
            raise PolicyError(
                "VEDAOPS_PATCH_INVALID",
                "Git patch effect output was malformed",
            ) from exc
        if not added.isdigit() or not deleted.isdigit():
            raise PolicyError("VEDAOPS_PATCH_INVALID", "binary patch effects are not allowed")
        try:
            _mutation_target(root, path, must_exist=True)
        except PolicyError as exc:
            raise PolicyError(
                "VEDAOPS_PATCH_INVALID",
                "patch targets a path outside the permitted Change surface",
            ) from exc
        paths.append(path)
    if not paths or len(paths) > MAX_PATCH_FILES or len(paths) != len(set(paths)):
        raise PolicyError("VEDAOPS_PATCH_INVALID", "patch must affect unique bounded files")
    return paths


def _snapshot_path(root: Path, path: str) -> tuple[str, bytes | None, int | None]:
    target = root.joinpath(*PurePosixPath(path).parts)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return path, None, None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{path} is not a regular file")
    raw, read_info = read_bounded_file(root, path, limit_bytes=MAX_PATCH_BYTES)
    if read_info.st_size > MAX_PATCH_BYTES or len(raw) != read_info.st_size:
        raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", f"{path} exceeds the patch snapshot limit")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError("VEDAOPS_FILE_INVALID_ENCODING", f"{path} is not UTF-8 text") from exc
    return path, raw, stat.S_IMODE(read_info.st_mode)


def _verify_patch_targets(root: Path, paths: Sequence[str]) -> None:
    for path in paths:
        _normalized, _target = _mutation_target(root, path, must_exist=True)
        raw, info = read_bounded_file(root, path, limit_bytes=MAX_PATCH_BYTES)
        if info.st_size > MAX_PATCH_BYTES or len(raw) != info.st_size:
            raise PolicyError("VEDAOPS_CHANGE_TOO_LARGE", f"{path} exceeds the patch limit")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError(
                "VEDAOPS_FILE_INVALID_ENCODING",
                f"{path} is not UTF-8 text after patch application",
            ) from exc


def _restore_snapshots(
    root: Path,
    snapshots: Sequence[tuple[str, bytes | None, int | None]],
) -> None:
    for path, raw, mode in snapshots:
        target = root.joinpath(*PurePosixPath(path).parts)
        if raw is None:
            if target.is_file() and not target.is_symlink():
                target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(target, raw, mode or 0o644)


def _commit_paths(root: Path, paths: Sequence[str]) -> tuple[str, ...]:
    if isinstance(paths, (str, bytes)) or not paths or len(paths) > MAX_COMMIT_PATHS:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "paths must contain 1..64 exact files")
    normalized = tuple(normalize_relative(item) for item in paths)
    if len(normalized) != len(set(normalized)):
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "commit paths must be unique")
    for item in normalized:
        ensure_mutation_path(item)
        ensure_not_ignored(root, item)
        target = root.joinpath(*PurePosixPath(item).parts)
        try:
            info = target.lstat()
        except FileNotFoundError:
            tracked = run_git_bytes(
                root,
                "ls-files",
                "--error-unmatch",
                "--",
                literal_pathspec(item),
                allow_exit_1=True,
            )
            if not tracked:
                raise PolicyError(
                    "VEDAOPS_COMMIT_PATH_MISMATCH",
                    f"{item} is neither an existing regular file nor a tracked deletion",
                ) from None
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{item} is not a regular file")
    return normalized


def _commit_message(message: str) -> str:
    if not isinstance(message, str) or not message.strip() or "\x00" in message:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "commit message must be non-empty text")
    if any(ord(character) < 32 and character not in {"\n", "\t"} for character in message):
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "commit message contains control characters")
    normalized = message.strip()
    if len(normalized.encode("utf-8")) > MAX_COMMIT_MESSAGE_BYTES:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "commit message exceeds the hard limit")
    return normalized


def _status_records(root: Path) -> list[tuple[str, str, str]]:
    raw = run_git_bytes(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--no-renames",
        "--untracked-files=all",
    )
    records: list[tuple[str, str, str]] = []
    for record in raw.split(b"\x00"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git status output was malformed")
        try:
            path = normalize_relative(record[3:].decode("utf-8"))
        except (UnicodeDecodeError, PolicyError) as exc:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git status output was malformed") from exc
        records.append((chr(record[0]), chr(record[1]), path))
    return records


def _status_text(root: Path) -> str:
    return "\n".join(f"{index}{work} {path}" for index, work, path in _status_records(root))


def _nul_paths(raw: bytes) -> list[str]:
    try:
        return [normalize_relative(item.decode("utf-8")) for item in raw.split(b"\x00") if item]
    except (UnicodeDecodeError, PolicyError) as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git path output was malformed") from exc


def _commit_staged_paths(root: Path) -> list[str]:
    return _nul_paths(
        run_git_bytes(
            root,
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--no-renames",
        )
    )


def _commit_tree_paths(root: Path, commit: str) -> list[str]:
    return _nul_paths(
        run_git_bytes(
            root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            "--no-renames",
            commit,
        )
    )


def _unstage_paths(root: Path, paths: Sequence[str]) -> None:
    run_git_text(
        root,
        "restore",
        "--staged",
        "--source=HEAD",
        "--",
        *(literal_pathspec(item) for item in paths),
    )


def _branch_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_BRANCH_NAME_BYTES
        or value.startswith("-")
        or "\x00" in value
    ):
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "branch name is invalid")
    try:
        completed = subprocess.run(
            ["git", "check-ref-format", "--branch", value],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env=git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "branch validation failed") from exc
    if completed.returncode != 0:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "branch name is not a valid Git branch")
    return value


def _current_branch(root: Path) -> str | None:
    value = run_git_text(root, "symbolic-ref", "--quiet", "--short", "HEAD", allow_exit_1=True)
    return value or None


def _require_current_branch(root: Path) -> str:
    branch = _current_branch(root)
    if branch is None:
        raise PolicyError("VEDAOPS_DETACHED_HEAD", "local mutation requires an attached branch")
    return branch


def _branch_head(root: Path, branch: str) -> str | None:
    value = run_git_text(
        root,
        "for-each-ref",
        "--format=%(objectname)",
        f"refs/heads/{branch}",
    )
    if not value:
        return None
    if COMMIT_PATTERN.fullmatch(value) is None:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "branch tip output was malformed")
    return value


def _require_safe_tree_transition(root: Path, from_head: str, to_head: str) -> None:
    raw = run_git_bytes(
        root,
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        from_head,
        to_head,
    )
    paths = _nul_paths(raw)
    if len(paths) > MAX_DIFF_FILES:
        raise PolicyError(
            "VEDAOPS_GIT_OUTPUT_TOO_LARGE",
            "branch transition changes too many paths for bounded validation",
        )
    for path in paths:
        ensure_mutation_path(path)

    if paths:
        ignored = _nul_paths(
            run_git_bytes(
                root,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
                "--",
                *(literal_pathspec(path) for path in paths),
            )
        )
        if ignored:
            raise PolicyError(
                "VEDAOPS_WORKTREE_COLLISION",
                f"branch transition would overwrite ignored work at {ignored[0]!r}",
            )

    from_entries = _tree_entries(root, from_head, paths)
    to_entries = _tree_entries(root, to_head, paths)
    for path in paths:
        for entry in (from_entries.get(path), to_entries.get(path)):
            if entry is None:
                continue
            mode, object_type = entry
            if mode not in {"100644", "100755"} or object_type != "blob":
                raise PolicyError(
                    "VEDAOPS_PATH_FORBIDDEN",
                    f"branch transition changes unsupported Git entry {path!r}",
                )


def _tree_entries(root: Path, head: str, paths: Sequence[str]) -> dict[str, tuple[str, str]]:
    if not paths:
        return {}
    raw = run_git_bytes(
        root,
        "ls-tree",
        "-z",
        head,
        "--",
        *(literal_pathspec(path) for path in paths),
    )
    entries: dict[str, tuple[str, str]] = {}
    requested = set(paths)
    for record in raw.split(b"\x00"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git tree output was malformed")
        try:
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = normalize_relative(raw_path.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, PolicyError) as exc:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git tree output was malformed") from exc
        if (
            path not in requested
            or path in entries
            or COMMIT_PATTERN.fullmatch(object_id) is None
        ):
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git tree output was malformed")
        entries[path] = (mode, object_type)
    return entries


def _require_clean(root: Path) -> None:
    if _status_records(root):
        raise PolicyError(
            "VEDAOPS_WORKTREE_DIRTY",
            "branch/ref mutation requires a clean working tree and index",
        )


@contextmanager
def _project_lock(root: Path) -> Iterator[None]:
    lock_root = Path(tempfile.gettempdir()) / f"vedaops-mcp-{os.getuid()}-locks"
    lock_root.mkdir(mode=0o700, exist_ok=True)
    with suppress(OSError):
        lock_root.chmod(0o700)
    digest = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()
    lock_path = lock_root / f"{digest}.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
