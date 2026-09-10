"""FastMCP server for the MCP-04 repository/change/check plane."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
import uuid
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from mcp.shared.version import LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
from pydantic import BaseModel, ConfigDict

from vedaops_mcp import __version__
from vedaops_mcp.authority import (
    Limitation,
    ProjectDetail,
    ProjectsListResult,
    list_authorized_projects,
    load_registry_snapshot,
    project_summaries_from_registry,
    require_principal,
)
from vedaops_mcp.change import (
    BranchChangeResult,
    BranchDeleteResult,
    BranchListResult,
    FileChangeResult,
    GitCommitResult,
    GitDiffResult,
    GitMergeResult,
    PatchApplyResult,
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
from vedaops_mcp.checks import CheckRunResult, project_check_run
from vedaops_mcp.errors import VedaOpsError
from vedaops_mcp.inspect import (
    GitCompareResult,
    GitStatusResult,
    ProjectContextResult,
    ProjectFileResult,
    ProjectSearchResult,
    ProjectTreeResult,
    orient_project,
    project_context_get,
    project_file_read,
    project_git_compare,
    project_git_status,
    project_search,
    project_tree,
)
from vedaops_mcp.postgres import PostgresCheckRunResult, project_postgres_check_run
from vedaops_mcp.settings import Settings

SERVER_NAME = "vedaops-mcp"
TOOL_CATALOG = (
    "vedaops_server_info",
    "projects_list",
    "project_get",
    "project_context_get",
    "project_tree",
    "project_file_read",
    "project_search",
    "project_git_status",
    "project_git_compare",
    "project_git_diff",
    "project_git_branches",
    "project_file_write",
    "project_text_replace",
    "project_patch_apply",
    "project_file_delete",
    "project_git_commit",
    "project_git_branch_create",
    "project_git_switch",
    "project_git_merge_ff",
    "project_git_branch_delete",
    "project_check_run",
    "project_postgres_check_run",
)
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
CHECK_EXECUTION = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False,
}
CHANGE_MUTATION = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": False,
}


class EffectiveGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    effective_capabilities: list[str]
    authorized: bool


class ControllerArtifactIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    state: str
    root: str | None
    sha256: str | None
    files: int
    bytes: int


class PythonRuntimeIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: str
    executable: str
    sha256: str | None
    version: str


class ServerInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_name: str
    server_version: str
    source_revision: str | None
    source_revision_state: str
    instance_id: str
    started_at: str
    process_id: int
    controller_artifact: ControllerArtifactIdentity
    python_runtime: PythonRuntimeIdentity
    protocol_version: str
    transport: str
    config_source: list[str]
    policy_path: str
    policy_sha256: str | None
    policy_state: str
    tool_catalog: list[str]
    tool_catalog_sha256: str
    principal_id: str
    effective_grants: list[EffectiveGrant]
    limitations: list[Limitation]


def package_version() -> str:
    try:
        return version("vedaops-mcp")
    except PackageNotFoundError:
        return __version__


def tool_catalog_sha256(tools: list[object]) -> tuple[list[str], str]:
    """Digest the exact MCP tool contracts the FastMCP server advertises."""
    advertised: list[dict[str, object]] = []
    names: list[str] = []
    for tool in tools:
        mcp_tool = tool.to_mcp_tool()
        payload = mcp_tool.model_dump(mode="json", by_alias=True, exclude_none=False)
        advertised.append(payload)
        names.append(mcp_tool.name)
    raw = json.dumps(advertised, separators=(",", ":"), sort_keys=True).encode()
    return names, hashlib.sha256(raw).hexdigest()


def controller_artifact_identity() -> ControllerArtifactIdentity:
    """Digest the loaded controller package tree without claiming build attestation."""
    root = Path(__file__).parent
    try:
        root_info = root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise OSError("controller package root is not a real directory")
        digest = hashlib.sha256()
        files = 0
        total = 0
        for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(item for item in directories if item != "__pycache__")
            filenames.sort()
            for directory in directories:
                info = (current_path / directory).lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise OSError("controller package contains an aliased directory")
            for filename in filenames:
                if filename.endswith((".pyc", ".pyo")):
                    continue
                path = current_path / filename
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise OSError("controller package contains an unsupported entry")
                raw = path.read_bytes()
                relative = path.relative_to(root).as_posix().encode("utf-8")
                files += 1
                total += len(raw)
                if files > 512 or total > 16 * 1024 * 1024:
                    raise OSError("controller package exceeds identity bounds")
                digest.update(len(relative).to_bytes(4, "big"))
                digest.update(relative)
                digest.update(len(raw).to_bytes(8, "big"))
                digest.update(raw)
        return ControllerArtifactIdentity(
            kind="loaded_package_tree",
            state="observed",
            root=str(root.resolve()),
            sha256=digest.hexdigest(),
            files=files,
            bytes=total,
        )
    except OSError:
        return ControllerArtifactIdentity(
            kind="loaded_package_tree",
            state="unavailable",
            root=None,
            sha256=None,
            files=0,
            bytes=0,
        )


def python_runtime_identity() -> PythonRuntimeIdentity:
    """Observe the Python executable actually hosting this controller process."""
    executable = Path(sys.executable)
    try:
        resolved = executable.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
            raise OSError("Python executable is unavailable")
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return PythonRuntimeIdentity(
            state="observed",
            executable=str(resolved),
            sha256=digest.hexdigest(),
            version=sys.version.split()[0],
        )
    except OSError:
        return PythonRuntimeIdentity(
            state="unavailable",
            executable=str(executable),
            sha256=None,
            version=sys.version.split()[0],
        )


def controller_source_revision() -> tuple[str | None, str]:
    """Observe nearby checkout HEAD; this is not installed-artifact attestation."""
    from vedaops_mcp.errors import PolicyError
    from vedaops_mcp.policy import run_git_text

    current = Path(__file__).resolve().parent
    for candidate in (current, *current.parents):
        git_dir = candidate / ".git"
        if git_dir.is_dir():
            try:
                revision = run_git_text(candidate, "rev-parse", "HEAD")
            except (PolicyError, OSError):
                return None, "unavailable"
            return revision, "observed"
        if git_dir.exists():
            return None, "unavailable"
    return None, "unavailable"


def build_server(settings: Settings) -> FastMCP:
    """Build one stdio MCP server bound to a declared principal and operator policy."""
    instance_id = uuid.uuid4().hex
    started_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_revision, source_revision_state = controller_source_revision()
    artifact_identity = controller_artifact_identity()
    python_identity = python_runtime_identity()

    mcp = FastMCP(
        name=SERVER_NAME,
        version=package_version(),
        instructions=(
            "VedaOps MCP-04 governed repository/change/check plane. The trusted launcher binds "
            "this process to a configured principal via VEDAOPS_AGENT_ID. Use bounded reads, "
            "preconditioned local file/Git mutations, and operator-approved isolated checks. "
            "Local branch creation/switching, exact commits, and fast-forward-only integration "
            "preserve native Git semantics. Remote publication is not exposed: push remains an "
            "explicit operator action. Approved PostgreSQL checks may receive one disposable "
            "PostgreSQL 18 Unix socket. This server does not expose Docker control, a general "
            "shell, arbitrary Git argv, remote Git writes, or Product authority."
        ),
    )

    @mcp.tool(name="vedaops_server_info", annotations=READ_ONLY)
    async def vedaops_server_info_tool(ctx: Context) -> ServerInfo:
        """Report instance, policy, tool catalog, and launcher-configured principal grants."""
        client_params = ctx.session.client_params
        requested_version = str(client_params.protocolVersion) if client_params else None
        protocol_value = (
            requested_version
            if requested_version in SUPPORTED_PROTOCOL_VERSIONS
            else LATEST_PROTOCOL_VERSION
        )
        catalog, catalog_digest = tool_catalog_sha256(await mcp.list_tools())
        return await asyncio.to_thread(
            _server_info,
            settings,
            instance_id=instance_id,
            started_at=started_at,
            source_revision=source_revision,
            source_revision_state=source_revision_state,
            process_id=os.getpid(),
            artifact_identity=artifact_identity,
            python_identity=python_identity,
            protocol_version=protocol_value,
            transport=ctx.transport or "in-memory",
            catalog=catalog,
            catalog_digest=catalog_digest,
        )

    @mcp.tool(name="projects_list", annotations=READ_ONLY)
    async def projects_list_tool(
        cursor: str | None = None,
        limit: int | None = None,
    ) -> ProjectsListResult:
        """List registered projects this principal has a grant for."""
        page_size = settings.default_page_size if limit is None else limit
        if (
            not isinstance(page_size, int)
            or isinstance(page_size, bool)
            or page_size < 1
            or page_size > settings.maximum_page_size
        ):
            raise ToolError(
                "VEDAOPS_INVALID_ARGUMENT: "
                f"limit must be between 1 and {settings.maximum_page_size}"
            )
        with _stable_errors():
            return await asyncio.to_thread(
                list_authorized_projects,
                settings.registry_path,
                principal_id=settings.principal_id,
                cursor=cursor,
                limit=page_size,
            )

    @mcp.tool(name="project_get", annotations=READ_ONLY)
    async def project_get_tool(project_id: str) -> ProjectDetail:
        """Orient to one granted project/workspace, permissions, and observed Git state."""
        with _stable_errors():
            return await asyncio.to_thread(
                orient_project,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
            )

    @mcp.tool(name="project_context_get", annotations=READ_ONLY)
    async def project_context_get_tool(project_id: str) -> ProjectContextResult:
        """Return operator-selected bounded context documents for one project."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_context_get,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
            )

    @mcp.tool(name="project_tree", annotations=READ_ONLY)
    async def project_tree_tool(
        project_id: str,
        path: str = "",
        max_entries: int = 500,
    ) -> ProjectTreeResult:
        """Return a bounded tracked and unignored project tree."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_tree,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                path=path,
                max_entries=max_entries,
            )

    @mcp.tool(name="project_file_read", annotations=READ_ONLY)
    async def project_file_read_tool(
        project_id: str,
        path: str,
        offset_bytes: int = 0,
        max_bytes: int = 65536,
    ) -> ProjectFileResult:
        """Read one bounded UTF-8 project file."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_file_read,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                path=path,
                offset_bytes=offset_bytes,
                max_bytes=max_bytes,
            )

    @mcp.tool(name="project_search", annotations=READ_ONLY)
    async def project_search_tool(
        project_id: str,
        query: str,
        path: str = "",
        file_pattern: str = "*",
        max_results: int = 100,
    ) -> ProjectSearchResult:
        """Search bounded project files for the exact literal query text."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_search,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                query=query,
                path=path,
                file_pattern=file_pattern,
                max_results=max_results,
            )

    @mcp.tool(name="project_git_status", annotations=READ_ONLY)
    async def project_git_status_tool(project_id: str) -> GitStatusResult:
        """Return the current branch, HEAD, dirtiness, and non-protected porcelain status."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_status,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
            )

    @mcp.tool(name="project_git_compare", annotations=READ_ONLY)
    async def project_git_compare_tool(
        project_id: str,
        base_commit: str,
        head_commit: str,
        path: str | None = None,
    ) -> GitCompareResult:
        """Return a bounded comparison of two exact Git commit object IDs."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_compare,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                base_commit=base_commit,
                head_commit=head_commit,
                path=path,
            )

    @mcp.tool(name="project_git_diff", annotations=READ_ONLY)
    async def project_git_diff_tool(
        project_id: str,
        staged: bool = False,
        path: str | None = None,
    ) -> GitDiffResult:
        """Return one bounded native working-tree or staged Git diff."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_diff,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                staged=staged,
                path=path,
            )

    @mcp.tool(name="project_git_branches", annotations=READ_ONLY)
    async def project_git_branches_tool(project_id: str) -> BranchListResult:
        """List local branches and exact local tip commits."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_branches,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
            )

    @mcp.tool(name="project_file_write", annotations=CHANGE_MUTATION)
    async def project_file_write_tool(
        project_id: str,
        expected_git_head: str,
        path: str,
        content: str,
        expected_sha256: str | None = None,
    ) -> FileChangeResult:
        """Create or replace one bounded UTF-8 file under exact preconditions."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_file_write,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                path=path,
                content=content,
                expected_sha256=expected_sha256,
            )

    @mcp.tool(name="project_text_replace", annotations=CHANGE_MUTATION)
    async def project_text_replace_tool(
        project_id: str,
        expected_git_head: str,
        path: str,
        expected_sha256: str,
        find: str,
        replacement: str,
    ) -> FileChangeResult:
        """Replace exactly one text occurrence with file-hash protection."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_text_replace,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                path=path,
                expected_sha256=expected_sha256,
                find=find,
                replacement=replacement,
            )

    @mcp.tool(name="project_patch_apply", annotations=CHANGE_MUTATION)
    async def project_patch_apply_tool(
        project_id: str,
        expected_git_head: str,
        patch: str,
    ) -> PatchApplyResult:
        """Apply one bounded Git-compatible text patch after path validation."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_patch_apply,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                patch=patch,
            )

    @mcp.tool(name="project_file_delete", annotations=CHANGE_MUTATION)
    async def project_file_delete_tool(
        project_id: str,
        expected_git_head: str,
        path: str,
        expected_sha256: str,
    ) -> FileChangeResult:
        """Delete one bounded regular file after exact hash verification."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_file_delete,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                path=path,
                expected_sha256=expected_sha256,
            )

    @mcp.tool(name="project_git_commit", annotations=CHANGE_MUTATION)
    async def project_git_commit_tool(
        project_id: str,
        expected_git_head: str,
        paths: list[str],
        message: str,
    ) -> GitCommitResult:
        """Commit exactly named changed files and refuse pre-existing staged state."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_commit,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                paths=paths,
                message=message,
            )

    @mcp.tool(name="project_git_branch_create", annotations=CHANGE_MUTATION)
    async def project_git_branch_create_tool(
        project_id: str,
        expected_git_head: str,
        branch: str,
    ) -> BranchChangeResult:
        """Create and switch to one new local branch from exact current HEAD."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_branch_create,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                branch=branch,
            )

    @mcp.tool(name="project_git_switch", annotations=CHANGE_MUTATION)
    async def project_git_switch_tool(
        project_id: str,
        expected_git_head: str,
        expected_current_branch: str,
        branch: str,
    ) -> BranchChangeResult:
        """Safely switch between existing local branches with no implicit stash."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_switch,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                expected_current_branch=expected_current_branch,
                branch=branch,
            )

    @mcp.tool(name="project_git_merge_ff", annotations=CHANGE_MUTATION)
    async def project_git_merge_ff_tool(
        project_id: str,
        expected_git_head: str,
        expected_target_branch: str,
        source_branch: str,
        expected_source_head: str,
    ) -> GitMergeResult:
        """Fast-forward the current local target to one exact local source branch tip."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_merge_ff,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                expected_target_branch=expected_target_branch,
                source_branch=source_branch,
                expected_source_head=expected_source_head,
            )

    @mcp.tool(name="project_git_branch_delete", annotations=CHANGE_MUTATION)
    async def project_git_branch_delete_tool(
        project_id: str,
        expected_git_head: str,
        expected_current_branch: str,
        branch: str,
        expected_branch_head: str,
    ) -> BranchDeleteResult:
        """Delete one non-current local branch only after Git proves it merged."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_git_branch_delete,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                expected_current_branch=expected_current_branch,
                branch=branch,
                expected_branch_head=expected_branch_head,
            )

    @mcp.tool(name="project_check_run", annotations=CHECK_EXECUTION)
    async def project_check_run_tool(
        project_id: str,
        expected_git_head: str,
        check_id: str,
        timeout_seconds: int | None = None,
    ) -> CheckRunResult:
        """Run one operator-approved check in the restricted commit-derived sandbox."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_check_run,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                check_id=check_id,
                timeout_seconds=timeout_seconds,
            )

    @mcp.tool(name="project_postgres_check_run", annotations=CHECK_EXECUTION)
    async def project_postgres_check_run_tool(
        project_id: str,
        expected_git_head: str,
        check_id: str,
        timeout_seconds: int | None = None,
    ) -> PostgresCheckRunResult:
        """Run one approved check against the disposable PostgreSQL 18 substrate."""
        with _stable_errors():
            return await asyncio.to_thread(
                project_postgres_check_run,
                settings.registry_path,
                principal_id=settings.principal_id,
                project_id=project_id,
                expected_git_head=expected_git_head,
                check_id=check_id,
                timeout_seconds=timeout_seconds,
            )

    return mcp


def _server_info(
    settings: Settings,
    *,
    instance_id: str,
    started_at: str,
    source_revision: str | None,
    source_revision_state: str,
    process_id: int,
    artifact_identity: ControllerArtifactIdentity,
    python_identity: PythonRuntimeIdentity,
    protocol_version: str,
    transport: str,
    catalog: list[str],
    catalog_digest: str,
) -> ServerInfo:
    limitations: list[Limitation] = []
    grants: list[EffectiveGrant] = []
    digest: str | None = None
    policy_state = "unavailable"
    try:
        registry, digest = load_registry_snapshot(settings.registry_path)
        require_principal(registry, settings.principal_id)
        policy_state = "observed"
        summaries = project_summaries_from_registry(
            registry,
            principal_id=settings.principal_id,
        )
        visible = summaries[: settings.maximum_page_size]
        grants = [
            EffectiveGrant(
                project_id=item.id,
                workspace_id=item.workspace_id,
                effective_capabilities=item.effective_capabilities,
                authorized=item.authorized,
            )
            for item in visible
        ]
        if len(summaries) > len(visible):
            limitations.append(
                Limitation(
                    code="VEDAOPS_RESULT_TRUNCATED",
                    detail="effective grant list exceeded the server-info page bound",
                )
            )
    except VedaOpsError as exc:
        limitations.append(Limitation(code=exc.code, detail=exc.detail))
    return ServerInfo(
        server_name=SERVER_NAME,
        server_version=package_version(),
        source_revision=source_revision,
        source_revision_state=source_revision_state,
        instance_id=instance_id,
        started_at=started_at,
        process_id=process_id,
        controller_artifact=artifact_identity,
        python_runtime=python_identity,
        protocol_version=protocol_version,
        transport=transport,
        config_source=list(settings.config_source),
        policy_path=str(settings.registry_path),
        policy_sha256=digest,
        policy_state=policy_state,
        tool_catalog=catalog,
        tool_catalog_sha256=catalog_digest,
        principal_id=settings.principal_id,
        effective_grants=grants,
        limitations=limitations,
    )


class _stable_errors:
    """Normalize every governed failure into one scrubbed stable-code ToolError."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if exc is None:
            return False
        if isinstance(exc, VedaOpsError):
            raise ToolError(f"{exc.code}: {exc.detail}") from exc
        return False
