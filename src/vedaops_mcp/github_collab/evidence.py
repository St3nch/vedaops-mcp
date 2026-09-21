"""Durable F008 operation evidence outside managed project roots.

The record shape follows the controller journal: a started record is fsynced
before a write is dispatched, and the terminal state is succeeded, failed, or
uncertain. These files are evidence of VedaOps calls. They are not a pull
request database.
"""

from __future__ import annotations

import hashlib
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
_TERMINAL_DETAIL_BUDGET = 500
CREATE_CANDIDATE_SAMPLE = 3
COMMENT_ID_SAMPLE = 8
RECOVERY_SHA_CHARS = 64
RECOVERY_REF_CHARS = 128
RECOVERY_ID_CHARS = 64


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


def record_bytes(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _max_url() -> str:
    return "https://github.com/" + ("o" * 39) + "/" + ("r" * 100) + "/pull/1000000000"


RECOVERY_URL_CHARS = len(_max_url())


def bound_journal_identifier(value: object) -> str:
    """Keep a native id inside the modeled journal field width."""
    text = str(value)
    if text.isdigit() and 1 <= len(text) <= 20:
        return text
    if len(text) == RECOVERY_ID_CHARS and all(
        character in "0123456789abcdef" for character in text
    ):
        return text
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def bound_journal_url(value: object) -> str:
    """Keep a native URL inside the modeled journal field width."""
    text = value if isinstance(value, str) else str(value)
    if 1 <= len(text) <= RECOVERY_URL_CHARS and "\n" not in text and "\r" not in text:
        return text
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _max_create_candidate() -> dict[str, object]:
    return {
        "number": "f" * RECOVERY_ID_CHARS,
        "html_url": _max_url(),
        "head_ref": "h" * RECOVERY_REF_CHARS,
        "head_sha": "a" * RECOVERY_SHA_CHARS,
        "base_ref": "b" * RECOVERY_REF_CHARS,
        "base_sha": "c" * RECOVERY_SHA_CHARS,
        "expected_head_sha": "d" * RECOVERY_SHA_CHARS,
        "expected_base_sha": "e" * RECOVERY_SHA_CHARS,
        "pre_observed_head_sha": "f" * RECOVERY_SHA_CHARS,
        "pre_observed_base_sha": "a" * RECOVERY_SHA_CHARS,
        "post_observed_head_sha": "b" * RECOVERY_SHA_CHARS,
        "post_observed_base_sha": "c" * RECOVERY_SHA_CHARS,
        "visible_title_matched": True,
        "visible_body_matched": True,
        "draft_matched": True,
        "exact_subject_matched": False,
        "base_drift": True,
        "causality": "unproven",
    }


def _max_create_observed_after() -> dict[str, object]:
    return {
        "discovered_count": 1_000_000,
        "exact_match_count": 1_000_000,
        "nonmatching_count": 1_000_000,
        "candidates_truncated": True,
        "candidate_numbers_sha256": "a" * 64,
        "candidates": [_max_create_candidate() for _ in range(CREATE_CANDIDATE_SAMPLE)],
    }


def _max_comment_observed_after() -> dict[str, object]:
    sample = ["b" * RECOVERY_ID_CHARS for _ in range(COMMENT_ID_SAMPLE)]
    return {
        "matching_comment_count": 500,
        "matching_comment_id_sample": sample,
        "matching_comment_ids_sha256": "b" * 64,
        "matching_comment_ids_truncated": True,
        "comment_scan_complete": False,
        "conflicting": True,
    }


def modeled_terminal_payloads(started: dict[str, object]) -> tuple[dict[str, object], ...]:
    """Largest create-recovery and comment-recovery records for this start."""
    payloads: list[dict[str, object]] = []
    for observed in (_max_create_observed_after(), _max_comment_observed_after()):
        terminal = dict(started)
        terminal.update(
            {
                "state": "uncertain",
                "terminal_at": "2026-09-21T00:00:00Z",
                "dispatched_at": "2026-09-21T00:00:00Z",
                "effect_dispatched": True,
                "may_have_occurred": True,
                "detail": "x" * _TERMINAL_DETAIL_BUDGET,
                "native_id": "f" * RECOVERY_ID_CHARS,
                "native_url": _max_url(),
                "observed_after": observed,
            }
        )
        payloads.append(terminal)
    return tuple(payloads)


def assert_journal_states_fit(started: dict[str, object]) -> None:
    """Reject an operation whose required journal states cannot fit.

    The modeled terminal records are the largest create-recovery and
    comment-recovery shapes this boundary writes. Identity fields stay at
    that width; they are not shortened after a mutation has been accepted.
    """
    for payload in (started, *modeled_terminal_payloads(started)):
        if len(record_bytes(payload)) > MAX_OPERATION_RECORD_BYTES:
            raise GitHubPolicyError(
                "VEDAOPS_OPERATION_RECORD_UNAVAILABLE",
                "durable operation evidence would exceed its record ceiling",
            )


def _write_record(path: Path, payload: dict[str, object]) -> None:
    raw = record_bytes(payload)
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
        detail = payload.get("detail")
        if isinstance(detail, str):
            payload["detail"] = detail[:_TERMINAL_DETAIL_BUDGET]
        if payload.get("native_id") is not None:
            payload["native_id"] = bound_journal_identifier(payload["native_id"])
        if payload.get("native_url") is not None:
            payload["native_url"] = bound_journal_url(payload["native_url"])
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
        "project_root": {
            "declared_path": str(project.root),
            "provenance": "operator_policy",
            "filesystem_verified": False,
        },
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
    assert_journal_states_fit(payload)
    _write_record(path, payload)
    return GitHubJournal(path=path, payload=payload)
