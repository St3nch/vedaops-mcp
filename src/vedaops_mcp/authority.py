"""Operator policy, project-manifest narrowing, and principal grants.

Authority evaluation is the intersection of:

    principal grant
    ∩ operator project ceiling
    ∩ project-manifest narrowing

The operator registry is the ceiling. The untrusted project manifest may only
narrow that ceiling. An absent or invalid manifest narrows every capability to
nothing. Repository content cannot enlarge authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tomllib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from vedaops_mcp.errors import AuthorityError, IdentityError
from vedaops_mcp.settings import validate_principal_id

MANIFEST_RELATIVE_PATH = Path(".vedaops/project.toml")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PROJECT_ID_LENGTH = 128
MAX_CONTEXT_FILES = 16
MAX_CHECKS = 64
MAX_CHECK_ARGV = 32
PROJECT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
ACTIVE_STATUSES = frozenset({"active"})
KNOWN_CAPABILITIES = frozenset({"change", "check", "read"})
WORKSPACE_KIND = "ordinary"


class RegisteredCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        min_length=1,
        max_length=MAX_PROJECT_ID_LENGTH,
        pattern=PROJECT_ID_PATTERN.pattern,
    )
    argv: list[str] = Field(min_length=1, max_length=MAX_CHECK_ARGV)
    timeout_seconds: int = Field(default=120, ge=1, le=120)
    memory_mb: int = Field(default=512, ge=64, le=1024)
    runtime: Literal["system", "project_venv"] = "system"
    substrate: Literal["postgres18"] | None = None

    @field_validator("argv")
    @classmethod
    def argv_is_bounded_and_explicit(cls, value: list[str]) -> list[str]:
        for argument in value:
            if (
                not isinstance(argument, str)
                or not argument
                or len(argument) > 1024
                or "\x00" in argument
                or any(ord(character) < 32 for character in argument)
            ):
                raise ValueError("check argv must contain bounded non-empty strings")
        if not value[0].startswith("/"):
            raise ValueError("check executable must be an absolute sandbox path")
        return value


class RegisteredProject(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(
        min_length=1,
        max_length=MAX_PROJECT_ID_LENGTH,
        pattern=PROJECT_ID_PATTERN.pattern,
    )
    name: str = Field(min_length=1)
    status: str = Field(min_length=1)
    root: Path
    workspace_id: str = Field(
        min_length=1,
        max_length=MAX_PROJECT_ID_LENGTH,
        pattern=PROJECT_ID_PATTERN.pattern,
    )
    mutable: bool = False
    capabilities: list[str] = Field(default_factory=list)
    context_files: list[str] = Field(default_factory=list, max_length=MAX_CONTEXT_FILES)
    checks: list[RegisteredCheck] = Field(default_factory=list, max_length=MAX_CHECKS)

    @field_validator("capabilities")
    @classmethod
    def capabilities_are_known_and_unique(cls, value: list[str]) -> list[str]:
        return _validated_capabilities(value)

    @field_validator("context_files")
    @classmethod
    def context_files_are_normalized_and_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("context_files must be unique")
        for configured_path in value:
            path = PurePosixPath(configured_path)
            if (
                not configured_path
                or path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or "\\" in configured_path
                or path.as_posix() != configured_path
            ):
                raise ValueError("context_files must contain normalized relative paths")
        return value

    @field_validator("checks")
    @classmethod
    def checks_have_unique_ids(cls, value: list[RegisteredCheck]) -> list[RegisteredCheck]:
        ids = [item.id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("check IDs must be unique within a project")
        return value

    @field_validator("root")
    @classmethod
    def root_is_absolute(cls, value: Path) -> Path:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise ValueError("project root must be an absolute path")
        return expanded


class RegisteredPrincipal(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    projects: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def principal_id_is_specific(cls, value: str) -> str:
        return validate_principal_id(value, source="principal id")

    @field_validator("projects")
    @classmethod
    def grants_are_known_and_unique(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if len(value) > 256:
            raise ValueError("a principal may not grant more than 256 projects")
        normalized: dict[str, list[str]] = {}
        for project_id, capabilities in value.items():
            if (
                not isinstance(project_id, str)
                or PROJECT_ID_PATTERN.fullmatch(project_id) is None
                or len(project_id) > MAX_PROJECT_ID_LENGTH
            ):
                raise ValueError("principal project grants must use valid project IDs")
            normalized[project_id] = _validated_capabilities(capabilities)
        return normalized


class RegistryDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    projects: list[RegisteredProject] = Field(default_factory=list, max_length=256)
    principals: list[RegisteredPrincipal] = Field(default_factory=list, max_length=64)


class ProjectManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int
    id: str = Field(
        min_length=1,
        max_length=MAX_PROJECT_ID_LENGTH,
        pattern=PROJECT_ID_PATTERN.pattern,
    )
    name: str = Field(min_length=1)
    mutable: bool = False
    capabilities: list[str] = Field(default_factory=list)

    @field_validator("capabilities")
    @classmethod
    def capabilities_are_known_and_unique(cls, value: list[str]) -> list[str]:
        return _validated_capabilities(value)


class AuthorizedProject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    status: str
    root: Path
    workspace_id: str
    workspace_kind: str
    mutable: bool
    capabilities: frozenset[str]
    context_files: tuple[str, ...]
    principal_id: str


class ProjectSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    status: str
    workspace_id: str
    workspace_kind: str
    root: str
    mutable: bool
    registered: bool
    manifest_valid: bool
    authorized: bool
    registry_capabilities: list[str]
    principal_grant: list[str]
    effective_capabilities: list[str]


class ProjectsListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    projects: list[ProjectSummary]
    returned_count: int
    total_count: int
    next_cursor: str | None
    truncated: bool


class Limitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    detail: str


class GitOrientation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: str
    git_head: str | None
    branch: str | None
    detached: bool | None
    clean: bool | None
    hidden_entries: int | None
    limitations: list[Limitation]


class ProjectDetail(ProjectSummary):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    authority_sources: dict[str, str | list[str]]
    check_ids: list[str]
    git: GitOrientation
    limitations: list[Limitation]


def load_registry(path: Path) -> RegistryDocument:
    """Load and fully validate the trusted operator policy document."""
    return _load_registry(path)


def policy_sha256(path: Path) -> str:
    """Return the SHA-256 digest of the operator policy file bytes."""
    resolved = path.expanduser().resolve()
    return hashlib.sha256(resolved.read_bytes()).hexdigest()


def require_principal(registry: RegistryDocument, principal_id: str) -> RegisteredPrincipal:
    """Return the named principal, or refuse an unknown identity."""
    normalized = validate_principal_id(principal_id, source="principal id")
    principal = next((item for item in registry.principals if item.id == normalized), None)
    if principal is None:
        raise IdentityError(
            "VEDAOPS_PRINCIPAL_UNKNOWN",
            f"principal {normalized!r} is not present in operator policy",
        )
    return principal


def get_authorized_project(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    capability: str,
) -> AuthorizedProject:
    """Resolve one project's effective authority and require one capability."""
    if capability not in KNOWN_CAPABILITIES:
        raise AuthorityError("VEDAOPS_INVALID_ARGUMENT", f"unknown capability {capability!r}")
    entry, principal, manifest, effective, manifest_valid = _evaluate_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
    )
    if entry.status not in ACTIVE_STATUSES:
        raise AuthorityError(
            "VEDAOPS_PROJECT_INACTIVE",
            f"project {entry.id!r} is not in an active lifecycle status",
        )
    if not manifest_valid:
        validate_project_manifest(entry)
    if capability not in effective:
        raise AuthorityError(
            "VEDAOPS_CAPABILITY_DENIED",
            f"project {entry.id!r} does not grant {capability!r} after policy intersection",
        )
    assert manifest is not None
    return AuthorizedProject(
        id=entry.id,
        name=entry.name,
        status=entry.status,
        root=entry.root,
        workspace_id=entry.workspace_id,
        workspace_kind=WORKSPACE_KIND,
        mutable=entry.mutable and manifest.mutable,
        capabilities=effective,
        context_files=tuple(entry.context_files),
        principal_id=principal.id,
    )


def get_authorized_check(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    check_id: str,
) -> tuple[AuthorizedProject, RegisteredCheck]:
    """Resolve one operator-defined check after project capability authorization."""
    project = get_authorized_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        capability="check",
    )
    registry = _load_registry(registry_path)
    entry = next((item for item in registry.projects if item.id == project.id), None)
    if entry is None:
        raise AuthorityError("VEDAOPS_PROJECT_NOT_AUTHORIZED", project.id)
    check = next((item for item in entry.checks if item.id == check_id), None)
    if check is None:
        raise AuthorityError(
            "VEDAOPS_CHECK_NOT_AUTHORIZED",
            f"check {check_id!r} is not operator-approved for project {project.id!r}",
        )
    return project, check


def list_authorized_projects(
    registry_path: Path,
    *,
    principal_id: str,
    cursor: str | None,
    limit: int,
) -> ProjectsListResult:
    """List registered projects this principal has a grant for."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise AuthorityError("VEDAOPS_INVALID_ARGUMENT", "limit must be a positive integer")
    registry = _load_registry(registry_path)
    principal = require_principal(registry, principal_id)
    summaries = [
        _project_summary(entry, principal)
        for entry in registry.projects
        if entry.id in principal.projects
    ]
    summaries.sort(key=lambda item: (item.id, item.root))
    offset = _decode_cursor(cursor)
    if offset > len(summaries):
        raise AuthorityError("VEDAOPS_INVALID_CURSOR", "cursor is beyond the result set")
    page = summaries[offset : offset + limit]
    next_offset = offset + len(page)
    truncated = next_offset < len(summaries)
    return ProjectsListResult(
        principal_id=principal.id,
        projects=page,
        returned_count=len(page),
        total_count=len(summaries),
        next_cursor=_encode_cursor(next_offset) if truncated else None,
        truncated=truncated,
    )


def get_project_detail(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    git_orientation: GitOrientation,
) -> ProjectDetail:
    """Return orientation facts for one granted registered project."""
    registry = _load_registry(registry_path)
    principal = require_principal(registry, principal_id)
    normalized_id = normalize_project_id(project_id)
    if normalized_id not in principal.projects:
        raise AuthorityError(
            "VEDAOPS_PROJECT_NOT_AUTHORIZED",
            f"project {normalized_id!r} is not authorized for this principal",
        )
    entry = next((item for item in registry.projects if item.id == normalized_id), None)
    if entry is None:
        raise AuthorityError(
            "VEDAOPS_PROJECT_NOT_AUTHORIZED",
            f"project {normalized_id!r} is not authorized for this principal",
        )
    summary = _project_summary(entry, principal)
    limitations: list[Limitation] = []
    if not summary.manifest_valid:
        limitations.append(
            Limitation(
                code="VEDAOPS_MANIFEST_UNAVAILABLE",
                detail="project manifest is absent, invalid, or does not match the registry",
            )
        )
    if entry.status not in ACTIVE_STATUSES:
        limitations.append(
            Limitation(
                code="VEDAOPS_PROJECT_INACTIVE",
                detail=f"project status is {entry.status!r}",
            )
        )
    if git_orientation.state != "observed":
        limitations.extend(git_orientation.limitations)
    return ProjectDetail(
        **summary.model_dump(),
        principal_id=principal.id,
        authority_sources={
            "operator_policy": str(registry_path),
            "project_manifest": MANIFEST_RELATIVE_PATH.as_posix(),
            "context_files": list(entry.context_files),
        },
        check_ids=(
            sorted(item.id for item in entry.checks)
            if "check" in summary.effective_capabilities
            else []
        ),
        git=git_orientation,
        limitations=limitations,
    )


def assert_trusted_path_outside_projects(
    trusted_path: Path,
    projects: Iterable[RegisteredProject],
    *,
    label: str,
) -> None:
    """Refuse trusted operator state that a managed project could reach."""
    expanded = trusted_path.expanduser()
    source = expanded.absolute()
    resolved = expanded.resolve()
    for project in projects:
        root = Path(project.root).resolve()
        if any(candidate == root or root in candidate.parents for candidate in (source, resolved)):
            raise AuthorityError(
                "VEDAOPS_TRUSTED_PATH_INSIDE_MANAGED_PROJECT",
                f"{label} must not live inside managed project {project.id!r}",
            )


def _evaluate_project(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
) -> tuple[
    RegisteredProject,
    RegisteredPrincipal,
    ProjectManifest | None,
    frozenset[str],
    bool,
]:
    registry = _load_registry(registry_path)
    principal = require_principal(registry, principal_id)
    normalized_id = normalize_project_id(project_id)
    if normalized_id not in principal.projects:
        raise AuthorityError(
            "VEDAOPS_PROJECT_NOT_AUTHORIZED",
            f"project {normalized_id!r} is not authorized for this principal",
        )
    entry = next((item for item in registry.projects if item.id == normalized_id), None)
    if entry is None:
        raise AuthorityError(
            "VEDAOPS_PROJECT_NOT_AUTHORIZED",
            f"project {normalized_id!r} is not authorized for this principal",
        )
    grant = frozenset(principal.projects.get(entry.id, ()))
    try:
        manifest = validate_project_manifest(entry)
    except AuthorityError:
        return entry, principal, None, frozenset(), False
    effective = frozenset(entry.capabilities) & frozenset(manifest.capabilities) & grant
    return entry, principal, manifest, effective, True


def _project_summary(
    entry: RegisteredProject,
    principal: RegisteredPrincipal,
) -> ProjectSummary:
    grant = sorted(principal.projects.get(entry.id, ()))
    try:
        manifest = validate_project_manifest(entry)
        manifest_valid = True
        effective = sorted(
            frozenset(entry.capabilities) & frozenset(manifest.capabilities) & frozenset(grant)
        )
        mutable = entry.mutable and manifest.mutable
    except AuthorityError:
        manifest_valid = False
        effective = []
        mutable = False
    authorized = entry.status in ACTIVE_STATUSES and manifest_valid and "read" in effective
    return ProjectSummary(
        id=entry.id,
        name=entry.name,
        status=entry.status,
        workspace_id=entry.workspace_id,
        workspace_kind=WORKSPACE_KIND,
        root=str(entry.root),
        mutable=mutable,
        registered=True,
        manifest_valid=manifest_valid,
        authorized=authorized,
        registry_capabilities=sorted(entry.capabilities),
        principal_grant=grant,
        effective_capabilities=effective,
    )


def validate_project_manifest(project: RegisteredProject) -> ProjectManifest:
    """Validate the manifest at one trusted registered project root."""
    root = project.root.resolve()
    manifest_path = root / MANIFEST_RELATIVE_PATH
    try:
        resolved_manifest = manifest_path.resolve(strict=True)
        if root not in resolved_manifest.parents:
            raise AuthorityError("VEDAOPS_MANIFEST_OUTSIDE_PROJECT_ROOT", str(manifest_path))
        if resolved_manifest.stat().st_dev != root.stat().st_dev:
            raise AuthorityError("VEDAOPS_MANIFEST_DEVICE_ESCAPE", str(manifest_path))
    except AuthorityError:
        raise
    except OSError as exc:
        raise AuthorityError(
            "VEDAOPS_MANIFEST_UNAVAILABLE",
            "project manifest is unavailable",
        ) from exc

    manifest = _load_manifest(resolved_manifest)
    if manifest.id != project.id:
        raise AuthorityError(
            "VEDAOPS_PROJECT_ID_COLLISION",
            "manifest ID does not match the registered project ID",
        )
    return manifest


def _load_registry(path: Path) -> RegistryDocument:
    resolved_path = path.expanduser().resolve()
    try:
        info = resolved_path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise AuthorityError("VEDAOPS_REGISTRY_INSECURE", "registry must be a regular file")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise AuthorityError(
                "VEDAOPS_REGISTRY_INSECURE",
                "registry must not be group- or world-writable",
            )
        if info.st_uid != os.getuid():
            raise AuthorityError(
                "VEDAOPS_REGISTRY_INSECURE",
                "registry must be owned by the service user",
            )
        if info.st_size > MAX_MANIFEST_BYTES * 16:
            raise AuthorityError("VEDAOPS_REGISTRY_INVALID", "registry file is too large")
        raw = resolved_path.read_bytes()
    except AuthorityError:
        raise
    except OSError as exc:
        raise AuthorityError("VEDAOPS_REGISTRY_UNAVAILABLE", "registry is unavailable") from exc

    try:
        data = tomllib.loads(raw.decode("utf-8"))
        registry = RegistryDocument.model_validate(data)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise AuthorityError(
            "VEDAOPS_REGISTRY_INVALID",
            "registry is not valid operator policy",
        ) from exc

    if registry.schema_version != 1:
        raise AuthorityError(
            "VEDAOPS_REGISTRY_SCHEMA_UNSUPPORTED",
            f"expected schema_version 1, received {registry.schema_version}",
        )

    for project in registry.projects:
        project.root = _validated_directory(project.root, f"project {project.id!r} root")

    ids = [project.id for project in registry.projects]
    if len(ids) != len(set(ids)):
        raise AuthorityError("VEDAOPS_REGISTRY_INVALID", "project IDs must be unique")
    principal_ids = [principal.id for principal in registry.principals]
    if len(principal_ids) != len(set(principal_ids)):
        raise AuthorityError("VEDAOPS_REGISTRY_INVALID", "principal IDs must be unique")

    registered_ids = set(ids)
    for principal in registry.principals:
        unknown = sorted(set(principal.projects) - registered_ids)
        if unknown:
            raise AuthorityError(
                "VEDAOPS_REGISTRY_INVALID",
                f"principal {principal.id!r} grants unknown project {unknown[0]!r}",
            )

    assert_trusted_path_outside_projects(
        resolved_path,
        registry.projects,
        label="the trusted project registry",
    )
    return registry


def _load_manifest(path: Path) -> ProjectManifest:
    try:
        info = path.stat()
        if info.st_size > MAX_MANIFEST_BYTES:
            raise AuthorityError(
                "VEDAOPS_MANIFEST_TOO_LARGE",
                f"manifest exceeds {MAX_MANIFEST_BYTES} bytes",
            )
        raw = path.read_bytes()
    except AuthorityError:
        raise
    except OSError as exc:
        raise AuthorityError(
            "VEDAOPS_MANIFEST_UNAVAILABLE",
            "project manifest is unavailable",
        ) from exc

    try:
        data = tomllib.loads(raw.decode("utf-8"))
        manifest = ProjectManifest.model_validate(data)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise AuthorityError("VEDAOPS_MANIFEST_INVALID", "project manifest is invalid") from exc
    if manifest.schema_version != 1:
        raise AuthorityError(
            "VEDAOPS_MANIFEST_SCHEMA_UNSUPPORTED",
            f"expected schema_version 1, received {manifest.schema_version}",
        )
    return manifest


def _validated_capabilities(value: list[str]) -> list[str]:
    if len(value) != len(set(value)):
        raise ValueError("capabilities must be unique")
    unknown = sorted(set(value) - KNOWN_CAPABILITIES)
    if unknown:
        raise ValueError(f"unknown capabilities {unknown}")
    return value


def _validated_directory(path: Path, label: str) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise AuthorityError("VEDAOPS_REGISTRY_INVALID", f"{label} must be absolute")
    resolved = expanded.resolve()
    if not resolved.is_dir():
        raise AuthorityError("VEDAOPS_REGISTRY_INVALID", f"{label} is not a directory")
    return resolved


def normalize_project_id(project_id: str) -> str:
    normalized_id = project_id.strip() if isinstance(project_id, str) else ""
    if (
        not normalized_id
        or len(normalized_id) > MAX_PROJECT_ID_LENGTH
        or PROJECT_ID_PATTERN.fullmatch(normalized_id) is None
    ):
        raise AuthorityError(
            "VEDAOPS_INVALID_ARGUMENT",
            "project_id must be a valid VedaOps project ID",
        )
    return normalized_id


def _encode_cursor(offset: int) -> str:
    payload = json.dumps({"offset": offset}, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    if not isinstance(cursor, str) or len(cursor) > 512:
        raise AuthorityError("VEDAOPS_INVALID_CURSOR", "cursor is malformed")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise AuthorityError("VEDAOPS_INVALID_CURSOR", "cursor is malformed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"offset"}
        or not isinstance(payload["offset"], int)
        or isinstance(payload["offset"], bool)
        or payload["offset"] < 0
    ):
        raise AuthorityError("VEDAOPS_INVALID_CURSOR", "cursor does not match this request")
    return payload["offset"]
