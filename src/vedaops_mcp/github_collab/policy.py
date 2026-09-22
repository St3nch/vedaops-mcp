"""Operator-owned F008 grants.

Shadow project policy is not read. A file inside a managed project root
cannot supply or enlarge these grants, and it cannot choose secret paths.
The project path recorded here is operator-declared provenance. F008 does
not open, own, or traverse that directory.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from vedaops_mcp.github_collab.allowlist import (
    DEFAULT_ARTIFACT,
    OPERATION_CLASSES,
    PROVIDER_API_VERSION,
    PROVIDER_COMMIT,
    PROVIDER_FEATURE,
    PROVIDER_RELEASE,
    RELEASE_ARTIFACTS,
)
from vedaops_mcp.github_collab.errors import GitHubAuthorityError, GitHubPolicyError
from vedaops_mcp.settings import validate_principal_id

_PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_GITHUB_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
_GITHUB_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_NUMERIC_ID = re.compile(r"^[0-9]{1,20}$")

_TOP_KEYS = frozenset(
    {"schema_version", "enabled", "provider", "journal", "projects", "principals"}
)
_PROVIDER_KEYS = frozenset(
    {
        "release",
        "commit",
        "artifact",
        "artifact_sha256",
        "api_version",
        "feature",
        "app_id",
        "installation_id",
        "binary_path",
        "executable_sha256",
        "private_key_path",
        "provider_login",
    }
)
_JOURNAL_KEYS = frozenset({"directory"})
_PROJECT_KEYS = frozenset({"id", "root", "github_owner", "github_repo"})
_PRINCIPAL_KEYS = frozenset({"id", "grants"})
_GRANT_KEYS = frozenset({"project", "operations"})

POLICY_ENVIRONMENT_VARIABLE = "VEDAOPS_GITHUB_POLICY"
PRINCIPAL_ENVIRONMENT_VARIABLE = "VEDAOPS_GITHUB_PRINCIPAL"


@dataclass(frozen=True, slots=True)
class RuntimeIdentity:
    """Unix identity that must not be able to rewrite trusted F008 files."""

    uid: int
    gids: frozenset[int]


def current_runtime_identity() -> RuntimeIdentity:
    """Identity of this process. Production runs as ``vedaops-github``."""
    return RuntimeIdentity(
        uid=os.geteuid(),
        gids=frozenset(os.getgroups()) | {os.getegid()},
    )


@dataclass(frozen=True, slots=True)
class GitHubProject:
    """Operator mapping from one VedaOps project id to one GitHub repository.

    ``root`` is the absolute path the operator declared for that project.
    It is provenance in evidence and a lexical containment boundary for
    trusted F008 files. The runtime does not stat it.
    """

    id: str
    root: Path
    owner: str
    repo: str

    @property
    def repository(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True, slots=True)
class GitHubGrant:
    principal_id: str
    project_id: str
    operations: frozenset[str]


@dataclass(frozen=True, slots=True)
class GitHubPolicy:
    path: Path
    sha256: str
    enabled: bool
    release: str
    commit: str
    artifact: str
    artifact_sha256: str
    api_version: str
    feature: str
    app_id: str
    installation_id: str
    binary_path: Path | None
    executable_sha256: str | None
    private_key_path: Path | None
    provider_login: str | None
    journal_directory: Path
    projects: tuple[GitHubProject, ...]
    grants: tuple[GitHubGrant, ...]

    def project(self, project_id: str) -> GitHubProject:
        for item in self.projects:
            if item.id == project_id:
                return item
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_PROJECT_DENIED",
            f"project {project_id!r} is not an F008 project",
        )

    def operations_for(self, principal_id: str, project_id: str) -> frozenset[str]:
        for grant in self.grants:
            if grant.principal_id == principal_id and grant.project_id == project_id:
                return grant.operations
        return frozenset()


def principal_from_environ(environ: Mapping[str, str]) -> str:
    """Resolve the F008 principal. Shadow's agent id is not accepted."""
    if PRINCIPAL_ENVIRONMENT_VARIABLE not in environ:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_IDENTITY_UNAVAILABLE",
            f"{PRINCIPAL_ENVIRONMENT_VARIABLE} must name the F008 principal",
        )
    return validate_principal_id(
        environ[PRINCIPAL_ENVIRONMENT_VARIABLE],
        source=PRINCIPAL_ENVIRONMENT_VARIABLE,
    )


def load_policy(path: Path, *, require_runtime_paths: bool = True) -> GitHubPolicy:
    """Load one operator policy file from outside every project it names."""
    resolved = _policy_file(path)
    try:
        raw = resolved.read_bytes()
        data = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "F008 policy is not valid TOML",
        ) from exc
    if not isinstance(data, dict):
        raise GitHubPolicyError("VEDAOPS_GITHUB_POLICY_INVALID", "F008 policy must be a table")
    _exact_keys(data, _TOP_KEYS, "F008 policy")
    if data.get("schema_version") != 1:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "F008 policy schema_version must be 1",
        )
    if not isinstance(data.get("enabled"), bool):
        raise GitHubPolicyError("VEDAOPS_GITHUB_POLICY_INVALID", "enabled must be a boolean")
    provider = _table(data.get("provider"), "provider")
    journal = _table(data.get("journal"), "journal")
    _exact_keys(provider, _PROVIDER_KEYS, "provider")
    _exact_keys(journal, _JOURNAL_KEYS, "journal")
    _require_pin(provider, "release", PROVIDER_RELEASE)
    _require_pin(provider, "commit", PROVIDER_COMMIT)
    _require_pin(provider, "api_version", PROVIDER_API_VERSION)
    _require_pin(provider, "feature", PROVIDER_FEATURE)
    artifact = provider.get("artifact", DEFAULT_ARTIFACT)
    if artifact not in RELEASE_ARTIFACTS:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "provider artifact is not a pinned F008 release asset",
        )
    digest = provider.get("artifact_sha256")
    if (
        not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != RELEASE_ARTIFACTS[artifact]
    ):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "provider artifact digest does not match the pinned release",
        )
    app_id = _numeric(provider.get("app_id"), "app_id")
    installation_id = _numeric(provider.get("installation_id"), "installation_id")
    login = provider.get("provider_login")
    if login is not None and (not isinstance(login, str) or _LOGIN.fullmatch(login) is None):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "provider_login must be a GitHub login",
        )
    projects = _projects(data.get("projects"))
    grants = _grants(data.get("principals"), projects)
    journal_directory = _absolute(journal.get("directory"), "journal directory")
    binary_path = _optional_absolute(provider.get("binary_path"), "binary_path")
    private_key_path = _optional_absolute(provider.get("private_key_path"), "private_key_path")
    executable_sha256 = _executable_digest(provider.get("executable_sha256"), binary_path)
    policy = GitHubPolicy(
        path=resolved,
        sha256=hashlib.sha256(raw).hexdigest(),
        enabled=bool(data["enabled"]),
        release=PROVIDER_RELEASE,
        commit=PROVIDER_COMMIT,
        artifact=str(artifact),
        artifact_sha256=str(digest),
        api_version=PROVIDER_API_VERSION,
        feature=PROVIDER_FEATURE,
        app_id=app_id,
        installation_id=installation_id,
        binary_path=binary_path,
        executable_sha256=executable_sha256,
        private_key_path=private_key_path,
        provider_login=login if isinstance(login, str) else None,
        journal_directory=journal_directory,
        projects=projects,
        grants=grants,
    )
    _reject_inside_projects(resolved, projects, "the F008 policy file")
    _reject_inside_projects(journal_directory, projects, "the F008 journal")
    if binary_path is not None:
        _reject_inside_projects(binary_path, projects, "the GitHub MCP Server binary")
        _reject_inside_directory(
            binary_path,
            journal_directory,
            "the GitHub MCP Server binary",
        )
    if private_key_path is not None:
        _reject_inside_projects(private_key_path, projects, "the GitHub App private key")
        _reject_inside_directory(
            private_key_path,
            journal_directory,
            "the GitHub App private key",
        )
    _reject_inside_directory(resolved, journal_directory, "the F008 policy file")
    _require_not_runtime_replaceable(resolved, "the F008 policy file")
    if require_runtime_paths and binary_path is not None and executable_sha256 is not None:
        verify_installed_executable(binary_path, executable_sha256)
    if require_runtime_paths and private_key_path is not None:
        _require_secret_file(private_key_path)
    if require_runtime_paths and policy.enabled:
        _require_directory(journal_directory, "the F008 journal", private=True)
    return policy


def authorize(
    policy: GitHubPolicy,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    operation: str,
) -> GitHubProject:
    """Return the granted project or refuse before any provider call."""
    if not policy.enabled:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_DISABLED",
            "F008 GitHub collaboration is disabled",
        )
    if operation not in OPERATION_CLASSES:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_OPERATION_DENIED",
            f"operation {operation!r} is not an F008 collaboration class",
        )
    try:
        validate_principal_id(principal_id, source="F008 principal")
    except ValueError as exc:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_PROJECT_DENIED",
            "F008 principal is not valid",
        ) from exc
    if not isinstance(project_id, str) or _PROJECT_ID.fullmatch(project_id) is None:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_PROJECT_DENIED",
            "F008 project id is not valid",
        )
    project = policy.project(project_id)
    repository = _repository_name(github_repository)
    if repository.casefold() != project.repository.casefold():
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_REPOSITORY_DENIED",
            f"repository {github_repository!r} is not granted for project {project.id!r}",
        )
    granted = policy.operations_for(principal_id, project.id)
    if operation not in granted:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_OPERATION_DENIED",
            f"operation {operation!r} is not granted for this principal and project",
        )
    return project


def _repository_name(value: object) -> str:
    if not isinstance(value, str) or value.count("/") != 1:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_REPOSITORY_DENIED",
            "github_repository must be owner/repo",
        )
    owner, repo = value.split("/", 1)
    if _GITHUB_OWNER.fullmatch(owner) is None or _GITHUB_REPO.fullmatch(repo) is None:
        raise GitHubAuthorityError(
            "VEDAOPS_GITHUB_REPOSITORY_DENIED",
            "github_repository must name one GitHub repository",
        )
    return f"{owner}/{repo}"


def _projects(value: object) -> tuple[GitHubProject, ...]:
    if not isinstance(value, list) or not value:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "projects must be a non-empty array",
        )
    projects: list[GitHubProject] = []
    seen: set[str] = set()
    repositories: set[str] = set()
    for item in value:
        table = _table(item, "project")
        _exact_keys(table, _PROJECT_KEYS, "project")
        project_id = table.get("id")
        if not isinstance(project_id, str) or _PROJECT_ID.fullmatch(project_id) is None:
            raise GitHubPolicyError("VEDAOPS_GITHUB_POLICY_INVALID", "project id is invalid")
        if project_id in seen:
            raise GitHubPolicyError("VEDAOPS_GITHUB_POLICY_INVALID", "project ids must be unique")
        seen.add(project_id)
        owner = table.get("github_owner")
        repo = table.get("github_repo")
        if (
            not isinstance(owner, str)
            or not isinstance(repo, str)
            or _GITHUB_OWNER.fullmatch(owner) is None
            or _GITHUB_REPO.fullmatch(repo) is None
        ):
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INVALID",
                "project github_owner and github_repo must be GitHub names",
            )
        repository = f"{owner}/{repo}".casefold()
        if repository in repositories:
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INVALID",
                "each GitHub repository may belong to only one F008 project",
            )
        repositories.add(repository)
        root = _declared_project_root(table.get("root"), f"project {project_id} root")
        projects.append(GitHubProject(id=project_id, root=root, owner=owner, repo=repo))
    return tuple(projects)


def _grants(value: object, projects: tuple[GitHubProject, ...]) -> tuple[GitHubGrant, ...]:
    if not isinstance(value, list) or not value:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "principals must be a non-empty array",
        )
    known = {project.id for project in projects}
    grants: list[GitHubGrant] = []
    seen: set[tuple[str, str]] = set()
    principal_ids: set[str] = set()
    for item in value:
        table = _table(item, "principal")
        _exact_keys(table, _PRINCIPAL_KEYS, "principal")
        try:
            principal_id = validate_principal_id(table.get("id"), source="principal id")
        except ValueError as exc:
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INVALID",
                "principal id is invalid",
            ) from exc
        if principal_id in principal_ids:
            raise GitHubPolicyError("VEDAOPS_GITHUB_POLICY_INVALID", "principal ids must be unique")
        principal_ids.add(principal_id)
        entries = table.get("grants")
        if not isinstance(entries, list) or not entries:
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INVALID",
                "each principal needs at least one grant",
            )
        for entry in entries:
            grant = _table(entry, "grant")
            _exact_keys(grant, _GRANT_KEYS, "grant")
            project_id = grant.get("project")
            if not isinstance(project_id, str) or project_id not in known:
                raise GitHubPolicyError(
                    "VEDAOPS_GITHUB_POLICY_INVALID",
                    "a grant names a project that is not defined",
                )
            pair = (principal_id, project_id)
            if pair in seen:
                raise GitHubPolicyError(
                    "VEDAOPS_GITHUB_POLICY_INVALID",
                    "a principal has two grants for one project",
                )
            seen.add(pair)
            operations = grant.get("operations")
            if not isinstance(operations, list) or not operations:
                raise GitHubPolicyError(
                    "VEDAOPS_GITHUB_POLICY_INVALID",
                    "grant operations must be a non-empty array",
                )
            if len(operations) != len(set(operations)):
                raise GitHubPolicyError(
                    "VEDAOPS_GITHUB_POLICY_INVALID",
                    "grant operations must be unique",
                )
            if any(operation not in OPERATION_CLASSES for operation in operations):
                raise GitHubPolicyError(
                    "VEDAOPS_GITHUB_POLICY_INVALID",
                    "grant operations contain an unknown or prohibited class",
                )
            grants.append(
                GitHubGrant(
                    principal_id=principal_id,
                    project_id=project_id,
                    operations=frozenset(str(operation) for operation in operations),
                )
            )
    return tuple(grants)


def _require_pin(table: Mapping[str, object], key: str, expected: str) -> None:
    value = table.get(key)
    if not isinstance(value, str) or value != expected:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            f"provider {key} must match the pinned GitHub MCP Server {expected}",
        )
    if key == "commit" and _COMMIT.fullmatch(value) is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "provider commit must be a 40-character commit SHA",
        )


def _numeric(value: object, label: str) -> str:
    if not isinstance(value, str) or _NUMERIC_ID.fullmatch(value) is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            f"{label} must be a decimal GitHub id",
        )
    return value


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GitHubPolicyError("VEDAOPS_GITHUB_POLICY_INVALID", f"{label} must be a table")
    return value


def _exact_keys(table: Mapping[str, object], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(table) - allowed)
    missing = sorted(key for key in allowed if key not in table and key not in {
        "binary_path",
        "executable_sha256",
        "private_key_path",
        "provider_login",
        "artifact",
    })
    if unknown:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            f"{label} contains unknown fields {unknown}",
        )
    if missing:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            f"{label} is missing {missing}",
        )


def _absolute(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            f"{label} must be an absolute path",
        )
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            f"{label} must be an absolute path",
        )
    return path


def _optional_absolute(value: object, label: str) -> Path | None:
    if value is None:
        return None
    return _absolute(value, label)


def _declared_project_root(value: object, label: str) -> Path:
    """Normalize an operator-declared project path without touching it."""
    return _lexical_absolute(_absolute(value, label))


def _lexical_absolute(path: Path) -> Path:
    absolute = path.expanduser()
    if not absolute.is_absolute():
        absolute = absolute.absolute()
    return Path(os.path.normpath(str(absolute)))


def _reject_inside_projects(
    candidate: Path,
    projects: tuple[GitHubProject, ...],
    label: str,
) -> None:
    """Refuse a trusted path that the declared project path would contain.

    Project paths are not resolved. Resolving them would require the runtime
    to traverse operator home directories that ``ProtectHome=yes`` hides.
    """
    trusted = [_lexical_absolute(candidate)]
    try:
        trusted.append(_lexical_absolute(candidate.expanduser().resolve()))
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            f"{label} is unavailable",
        ) from exc
    for project in projects:
        declared = _lexical_absolute(project.root)
        for child in trusted:
            if child == declared or declared in child.parents:
                raise GitHubPolicyError(
                    "VEDAOPS_GITHUB_TRUSTED_PATH_INSIDE_PROJECT",
                    f"{label} must not live inside managed project {project.id!r}",
                )


def _policy_file(path: Path) -> Path:
    try:
        expanded = path.expanduser()
        info = expanded.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INSECURE",
                "the F008 policy must not be a symbolic link",
            )
        resolved = expanded.resolve(strict=True)
        info = resolved.stat()
    except GitHubPolicyError:
        raise
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            "the F008 policy file is unavailable",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the F008 policy file must be a regular file",
        )
    if not os.access(resolved, os.R_OK):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the F008 policy file must be readable by the runtime identity",
        )
    return resolved


def _require_directory(path: Path, label: str, *, private: bool) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            f"{label} is unavailable",
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            f"{label} must be a real directory",
        )
    if info.st_uid != os.getuid():
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            f"{label} must be owned by the service user",
        )
    if private:
        if info.st_mode & 0o077:
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INSECURE",
                f"{label} must not be group- or world-accessible",
            )
    elif info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            f"{label} must not be group- or world-writable",
        )


def _require_secret_file(path: Path) -> None:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INSECURE",
                "the GitHub App private key must not be a symbolic link",
            )
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except GitHubPolicyError:
        raise
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            "the GitHub App private key is unavailable",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the GitHub App private key must be a regular file",
        )
    if info.st_mode & (stat.S_IRWXO | stat.S_IWGRP):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the GitHub App private key must not be world-accessible or group-writable",
        )
    if not os.access(path, os.R_OK):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the GitHub App private key must be readable by the runtime identity",
        )
    _require_not_runtime_replaceable(path, "the GitHub App private key")


def sha256_file(path: Path) -> str:
    """Hash file bytes. This does not identify a release archive by itself."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_installed_executable(path: Path, expected_sha256: str) -> str:
    """Hash the executable about to be launched and require the operator digest.

    ``expected_sha256`` is locally derived installation evidence. GitHub
    publishes the release archive digest, not this executable digest.
    """
    if _SHA256.fullmatch(expected_sha256) is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "executable_sha256 must be a 64-character sha256 digest",
        )
    _require_unwritable_executable(path)
    try:
        actual = sha256_file(path)
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            "the GitHub MCP Server binary is unreadable",
        ) from exc
    if actual != expected_sha256:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_EXECUTABLE_MISMATCH",
            "installed executable digest does not match executable_sha256; "
            "that value is the locally derived file digest, not the release archive digest",
        )
    return actual


def _executable_digest(value: object, binary_path: Path | None) -> str | None:
    if binary_path is None and value is None:
        return None
    if binary_path is None or not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "binary_path and executable_sha256 must both name the installed executable",
        )
    return value


def _reject_inside_directory(candidate: Path, container: Path, label: str) -> None:
    contained = container.expanduser().resolve()
    for child in (candidate.expanduser().absolute(), candidate.expanduser().resolve()):
        if child == contained or contained in child.parents:
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INSECURE",
                f"{label} must not live inside the writable F008 journal",
            )


def runtime_can_rewrite_trusted_chain(
    chain: Sequence[os.stat_result],
    identity: RuntimeIdentity,
) -> bool:
    """Return whether ``identity`` can replace the last path component.

    Owning a file or directory counts even when its write bit is clear,
    because that uid can chmod it. A sticky directory does not let the
    identity replace a child owned by someone else.
    """
    if not chain:
        return True
    for index, info in enumerate(chain):
        if index == len(chain) - 1:
            if _identity_can_rewrite_file(info, identity):
                return True
            continue
        if _directory_can_replace_child(info, chain[index + 1], identity):
            return True
    return False


def _require_not_runtime_replaceable(path: Path, label: str) -> None:
    chain = _trusted_file_chain(path, label)
    if not stat.S_ISREG(chain[-1].st_mode):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            f"{label} must be a regular file",
        )
    if runtime_can_rewrite_trusted_chain(chain, current_runtime_identity()):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            f"{label} must not be writable by the F008 runtime identity",
        )


def _trusted_file_chain(path: Path, label: str) -> list[os.stat_result]:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    chain: list[os.stat_result] = []
    try:
        info = current.lstat()
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            f"{label} is unavailable",
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            f"{label} must not be a symbolic link",
        )
    chain.append(info)
    if absolute == current:
        return chain
    for part in absolute.relative_to(current).parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
                f"{label} is unavailable",
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise GitHubPolicyError(
                "VEDAOPS_GITHUB_POLICY_INSECURE",
                f"{label} must not be reached through a symbolic link",
            )
        chain.append(info)
    return chain


def _identity_can_rewrite_file(info: os.stat_result, identity: RuntimeIdentity) -> bool:
    if info.st_uid == identity.uid:
        return True
    if info.st_mode & stat.S_IWOTH:
        return True
    return bool(info.st_mode & stat.S_IWGRP and info.st_gid in identity.gids)


def _directory_can_replace_child(
    directory: os.stat_result,
    child: os.stat_result,
    identity: RuntimeIdentity,
) -> bool:
    if directory.st_uid == identity.uid:
        return True
    other_writable = bool(directory.st_mode & stat.S_IWOTH)
    group_writable = bool(directory.st_mode & stat.S_IWGRP and directory.st_gid in identity.gids)
    if not other_writable and not group_writable:
        return False
    sticky = bool(directory.st_mode & stat.S_ISVTX)
    return not sticky or child.st_uid == identity.uid


def _require_unwritable_executable(path: Path) -> None:
    chain = _trusted_file_chain(path, "the GitHub MCP Server binary")
    info = chain[-1]
    if not stat.S_ISREG(info.st_mode):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the GitHub MCP Server binary must be a regular file",
        )
    if runtime_can_rewrite_trusted_chain(chain, current_runtime_identity()):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the GitHub MCP Server binary must not be writable by the F008 runtime identity",
        )
    if not os.access(path, os.X_OK):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INSECURE",
            "the GitHub MCP Server binary must be executable by the runtime identity",
        )


