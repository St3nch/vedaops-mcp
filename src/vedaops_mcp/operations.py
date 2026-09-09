"""Minimal durable operation evidence outside managed project roots."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vedaops_mcp.errors import PolicyError


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _operation_root(registry_path: Path) -> Path:
    root = registry_path.resolve().parent / "operations"
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
    parent = path.parent
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".operation-", dir=parent)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path = Path(temporary)
        os.replace(temp_path, path)
        temporary = None
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
            "durable operation evidence could not be written",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(OSError):
                Path(temporary).unlink()


@dataclass(slots=True)
class OperationJournal:
    path: Path
    payload: dict[str, object]

    @property
    def operation_id(self) -> str:
        return str(self.payload["operation_id"])

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
    _write_record(path, payload)
    return OperationJournal(path=path, payload=payload)
