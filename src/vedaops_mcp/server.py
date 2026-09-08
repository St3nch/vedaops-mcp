"""FastMCP server for the MCP-01 read/orientation plane."""

from __future__ import annotations

import asyncio
import hashlib
import json
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
    load_registry,
    policy_sha256,
    require_principal,
)
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
)
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


class EffectiveGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    effective_capabilities: list[str]
    authorized: bool


class ServerInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_name: str
    server_version: str
    source_revision: str | None
    source_revision_state: str
    instance_id: str
    started_at: str
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


def tool_catalog_sha256() -> str:
    payload = json.dumps(list(TOOL_CATALOG), separators=(",", ":"), sort_keys=False).encode()
    return hashlib.sha256(payload).hexdigest()


def controller_source_revision() -> tuple[str | None, str]:
    """Observe this controller's Git HEAD when running from a real checkout."""
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
    catalog_digest = tool_catalog_sha256()

    mcp = FastMCP(
        name=SERVER_NAME,
        version=package_version(),
        instructions=(
            "VedaOps MCP-01 read/orientation plane. The trusted launcher binds "
            "this process to a configured principal via VEDAOPS_AGENT_ID. Identify "
            "that principal, registered project/workspace, effective permissions, "
            "and bounded repository/Git facts. This server does not independently "
            "cryptographically authenticate the human or model behind the launcher, "
            "execute project code, run a general shell, or perform mutations."
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
        return await asyncio.to_thread(
            _server_info,
            settings,
            instance_id=instance_id,
            started_at=started_at,
            source_revision=source_revision,
            source_revision_state=source_revision_state,
            protocol_version=protocol_value,
            transport=ctx.transport or "in-memory",
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

    return mcp


def _server_info(
    settings: Settings,
    *,
    instance_id: str,
    started_at: str,
    source_revision: str | None,
    source_revision_state: str,
    protocol_version: str,
    transport: str,
    catalog_digest: str,
) -> ServerInfo:
    limitations: list[Limitation] = []
    grants: list[EffectiveGrant] = []
    digest: str | None = None
    policy_state = "unavailable"
    try:
        registry = load_registry(settings.registry_path)
        require_principal(registry, settings.principal_id)
        digest = policy_sha256(settings.registry_path)
        policy_state = "observed"
        listed = list_authorized_projects(
            settings.registry_path,
            principal_id=settings.principal_id,
            cursor=None,
            limit=settings.maximum_page_size,
        )
        grants = [
            EffectiveGrant(
                project_id=item.id,
                workspace_id=item.workspace_id,
                effective_capabilities=item.effective_capabilities,
                authorized=item.authorized,
            )
            for item in listed.projects
        ]
        if listed.truncated:
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
        protocol_version=protocol_version,
        transport=transport,
        config_source=list(settings.config_source),
        policy_path=str(settings.registry_path),
        policy_sha256=digest,
        policy_state=policy_state,
        tool_catalog=list(TOOL_CATALOG),
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
