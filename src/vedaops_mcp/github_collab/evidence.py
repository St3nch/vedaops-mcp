"""Durable F008 operation evidence outside managed project roots.

The record shape follows the controller journal: a started record is fsynced
before a write is dispatched, and the terminal state is succeeded, failed, or
uncertain. These files are evidence of VedaOps calls. They are not a pull
request database.
"""

from __future__ import annotations

import json
import os
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vedaops_mcp.github_collab.errors import GitHubPolicyError
from vedaops_mcp.github_collab.policy import (
    GitHubPolicy,
    GitHubProject,
    _reject_inside_projects,
    _require_directory,
)

MAX_OPERATION_RECORD_BYTES = 8192


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _journal_directory(policy: GitHubPolicy) -> Path:
    root = policy.journal_directory
    try:
        info = root.lstat()
    except FileNotFoundError:
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise GitHubPolicyError(
                "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
                "F008 operation-record directory could not be created",
            ) from exc
        info = root.lstat()
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "F008 operation-record directory is unavailable",
        ) from exc
    _reject_inside_projects(root, policy.projects, "the F008 journal")
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise GitHubPolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "F008 operation-record directory is insecure",
        )
    _require_directory(root, "the F008 journal", private=True)
    return root


def _write_record(path: Path, payload: dict[str, object]) -> None:
    raw = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_OPERATION_RECORD_BYTES:
        raise GitHubPolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "durable operation evidence exceeded its hard limit",
        )
    parent = path.parent
    descriptor: int | None = None
    parent_descriptor: int | None = None
    temporary: str | None = None
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        temporary = f".operation-{uuid.uuid4().hex}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary = None
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "durable operation evidence could not be written",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None and parent_descriptor is not None:
            with suppress(OSError):
                os.unlink(temporary, dir_fd=parent_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


@dataclass(slots=True)
class GitHubJournal:
    path: Path
    payload: dict[str, object]

    @property
    def operation_id(self) -> str:
        return str(self.payload["operation_id"])

    def update(self, **details: object) -> None:
        if self.payload.get("state") != "started":
            raise ValueError("operation details may only be added while started")
        payload = dict(self.payload)
        payload.update(details)
        _write_record(self.path, payload)
        self.payload = payload

    def mark_dispatched(self) -> None:
        """Fsync the pre-effect record before the provider write is attempted."""
        self.update(effect_dispatched=True, dispatched_at=_timestamp())

    def terminal(self, state: str, **details: object) -> None:
        if state not in {"succeeded", "failed", "uncertain"}:
            raise ValueError("invalid operation terminal state")
        payload = dict(self.payload)
        payload.update(details)
        payload["state"] = state
        payload["terminal_at"] = _timestamp()
        try:
            _write_record(self.path, payload)
        except GitHubPolicyError as exc:
            raise GitHubPolicyError(
                "VEDAOPS_OPERATION_RECORD_UNCERTAIN",
                "operation terminal evidence could not be recorded; "
                f"inspect state for operation {self.operation_id}",
            ) from exc
        self.payload = payload


def start_github_operation(
    policy: GitHubPolicy,
    *,
    kind: str,
    project: GitHubProject,
    principal_id: str,
    github_repository: str,
    target: dict[str, object],
    expected_source_sha: str | None,
    intention_sha256: str,
    authorization_basis: str,
) -> GitHubJournal:
    """Record one F008 operation before its first GitHub write."""
    operation_id = uuid.uuid4().hex
    root = _journal_directory(policy)
    path = root / f"{operation_id}.json"
    payload: dict[str, object] = {
        "schema_version": 1,
        "domain": "f008",
        "operation_id": operation_id,
        "state": "started",
        "started_at": _timestamp(),
        "principal_id": principal_id,
        "project_id": project.id,
        "workspace_root": str(project.root),
        "github_repository": github_repository,
        "kind": kind,
        "target": target,
        "intention_sha256": intention_sha256,
        "authorization_basis": authorization_basis,
        "provider_id": "github-mcp-server",
        "provider_release": policy.release,
        "provider_commit": policy.commit,
        "provider_feature": policy.feature,
        "effect_dispatched": False,
        "may_have_occurred": False,
        "pid": os.getpid(),
    }
    if expected_source_sha is not None:
        payload["expected_source_sha"] = expected_source_sha
    _write_record(path, payload)
    return GitHubJournal(path=path, payload=payload)
