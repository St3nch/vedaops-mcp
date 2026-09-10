"""Minimal durable operation evidence outside managed project roots."""

from __future__ import annotations

import json
import os
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vedaops_mcp.authority import assert_trusted_path_outside_projects, load_registry
from vedaops_mcp.errors import PolicyError

MAX_OPERATION_RECORD_BYTES = 4096


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _operation_root(registry_path: Path) -> Path:
    registry = load_registry(registry_path)
    parent = registry_path.expanduser().resolve().parent
    root = parent / "operations"
    assert_trusted_path_outside_projects(
        root,
        registry.projects,
        label="the trusted operation journal",
    )
    try:
        info = root.lstat()
    except FileNotFoundError:
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise PolicyError(
                "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
                "trusted operation-record directory could not be created",
            ) from exc
        info = root.lstat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "trusted operation-record directory is unavailable",
        ) from exc
    assert_trusted_path_outside_projects(
        root,
        registry.projects,
        label="the trusted operation journal",
    )
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise PolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "trusted operation-record directory is insecure",
        )
    return root


def _write_record(path: Path, payload: dict[str, object]) -> None:
    raw = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_OPERATION_RECORD_BYTES:
        raise PolicyError(
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
        raise PolicyError(
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
class OperationJournal:
    path: Path
    payload: dict[str, object]

    @property
    def operation_id(self) -> str:
        return str(self.payload["operation_id"])

    def update(self, **details: object) -> None:
        """Durably add recovery identifiers before the corresponding effect starts."""
        if self.payload.get("state") != "started":
            raise ValueError("operation details may only be added while started")
        payload = dict(self.payload)
        payload.update(details)
        _write_record(self.path, payload)
        self.payload = payload

    def terminal(self, state: str, *, detail: str | None = None) -> None:
        if state not in {"succeeded", "failed", "uncertain"}:
            raise ValueError("invalid operation terminal state")
        payload = dict(self.payload)
        payload["state"] = state
        payload["terminal_at"] = _timestamp()
        if detail is not None:
            payload["detail"] = detail[:2048]
        try:
            _write_record(self.path, payload)
        except PolicyError as exc:
            raise PolicyError(
                "VEDAOPS_OPERATION_RECORD_UNCERTAIN",
                "operation terminal evidence could not be recorded; "
                f"inspect state for operation {self.operation_id}",
            ) from exc
        self.payload = payload


def start_operation(
    registry_path: Path,
    *,
    kind: str,
    project_id: str,
    expected_git_head: str | None = None,
    principal_id: str | None = None,
    workspace_id: str | None = None,
    project_root: Path | None = None,
    subject: dict[str, object] | None = None,
) -> OperationJournal:
    """Durably record one operation before its first externally visible effect."""
    operation_id = uuid.uuid4().hex
    root = _operation_root(registry_path)
    path = root / f"{operation_id}.json"
    payload: dict[str, object] = {
        "schema_version": 1,
        "operation_id": operation_id,
        "kind": kind,
        "project_id": project_id,
        "state": "started",
        "started_at": _timestamp(),
        "pid": os.getpid(),
    }
    if expected_git_head is not None:
        payload["expected_git_head"] = expected_git_head
    if principal_id is not None:
        payload["principal_id"] = principal_id
    if workspace_id is not None:
        payload["workspace_id"] = workspace_id
    if project_root is not None:
        payload["project_root"] = str(project_root.resolve())
    if subject is not None:
        payload["subject"] = subject
    _write_record(path, payload)
    return OperationJournal(path=path, payload=payload)
