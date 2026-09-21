"""Stdio MCP boundary for F008.

ChatGPT connects to this process, not to Shadow and not directly to the
official GitHub MCP Server. Tool results are observations or operation
evidence. They are not Product acceptance.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from vedaops_mcp.github_collab.allowlist import (
    PROHIBITED_TOOLS,
    PROVIDER_COMMIT,
    PROVIDER_FEATURE,
    PROVIDER_RELEASE,
    PROVIDER_TOOLS,
    catalog_fingerprint,
)
from vedaops_mcp.github_collab.operations import (
    add_pull_request_comment,
    create_pull_request,
    read_actions,
    read_commit,
    read_identity,
    read_pull_request,
    request_reviewers,
    update_pull_request_body,
    update_pull_request_title,
)
from vedaops_mcp.github_collab.permissions import (
    ACCEPTED_REPOSITORY_PERMISSIONS,
    EXCLUDED_REPOSITORY_PERMISSIONS,
    ISSUE_COMMENT_PERMISSION,
)
from vedaops_mcp.github_collab.policy import GitHubPolicy
from vedaops_mcp.github_collab.provider import GitHubProvider

SERVER_NAME = "vedaops-github"
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}
COLLABORATION_WRITE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}
INFO_TOOL = "github_server_info"
COLLABORATION_TOOLS = (
    "github_identity_get",
    "github_commit_get",
    "github_pull_request_read",
    "github_actions_list",
    "github_pull_request_create",
    "github_pull_request_update_title",
    "github_pull_request_update_body",
    "github_pull_request_comment",
    "github_pull_request_request_reviewers",
)


def tool_catalog(policy: GitHubPolicy) -> tuple[str, ...]:
    if not policy.enabled:
        return (INFO_TOOL,)
    return (INFO_TOOL, *COLLABORATION_TOOLS)


def build_github_server(
    policy: GitHubPolicy,
    principal_id: str,
    provider: GitHubProvider | None,
) -> FastMCP:
    """Build the F008 server. A disabled policy exposes only server info."""
    instructions = (
        "VedaOps F008 GitHub collaboration boundary. This is a separate authority "
        "domain from VedaOps MCP Shadow. Use it for authorized repository reads and "
        "ordinary pull request collaboration. It does not push, merge, change Git "
        "refs, write repository files, dispatch workflows, submit reviews, or decide "
        "Product acceptance. A review or comment from the provider identity is not "
        "independent review."
    )
    mcp = FastMCP(name=SERVER_NAME, version="0.1.0", instructions=instructions)

    @mcp.tool(name=INFO_TOOL, annotations=READ_ONLY)
    def github_server_info() -> dict[str, Any]:
        """Report the pinned provider, allowlist, and whether collaboration is enabled."""
        return _server_info(policy, principal_id)

    if not policy.enabled or provider is None:
        return mcp

    @mcp.tool(name="github_identity_get", annotations=READ_ONLY)
    def github_identity_get(project_id: str, github_repository: str) -> dict[str, Any]:
        """Read the configured GitHub App identity and, when available, get_me."""
        return read_identity(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
        )

    @mcp.tool(name="github_commit_get", annotations=READ_ONLY)
    def github_commit_get(
        project_id: str,
        github_repository: str,
        ref: str,
    ) -> dict[str, Any]:
        """Read one live commit or branch tip from GitHub. This does not read local refs."""
        return read_commit(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            ref=ref,
        )

    @mcp.tool(name="github_pull_request_read", annotations=READ_ONLY)
    def github_pull_request_read(
        project_id: str,
        github_repository: str,
        number: int,
        method: str,
        page: int = 1,
        per_page: int = 30,
    ) -> dict[str, Any]:
        """Read one pull request fact from the pinned read-method set."""
        return read_pull_request(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            number=number,
            method=method,
            page=page,
            per_page=per_page,
        )

    @mcp.tool(name="github_actions_list", annotations=READ_ONLY)
    def github_actions_list(
        project_id: str,
        github_repository: str,
        method: str,
        resource_id: str | None = None,
        page: int = 1,
        per_page: int = 30,
    ) -> dict[str, Any]:
        """List workflows, workflow runs, or jobs. Dispatch and artifacts are excluded."""
        return read_actions(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            method=method,
            resource_id=resource_id,
            page=page,
            per_page=per_page,
        )

    @mcp.tool(name="github_pull_request_create", annotations=COLLABORATION_WRITE)
    def github_pull_request_create(
        project_id: str,
        github_repository: str,
        head: str,
        base: str,
        expected_head_sha: str,
        title: str,
        body: str = "",
        draft: bool = False,
        expected_base_sha: str | None = None,
    ) -> dict[str, Any]:
        """Create a pull request after the live head SHA matches expected_head_sha."""
        return create_pull_request(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            head=head,
            base=base,
            expected_head_sha=expected_head_sha,
            title=title,
            body=body,
            draft=draft,
            expected_base_sha=expected_base_sha,
        )

    @mcp.tool(name="github_pull_request_update_title", annotations=COLLABORATION_WRITE)
    def github_pull_request_update_title(
        project_id: str,
        github_repository: str,
        number: int,
        title: str,
    ) -> dict[str, Any]:
        """Replace a pull request title and re-read it. Base and state stay unchanged."""
        return update_pull_request_title(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            number=number,
            title=title,
        )

    @mcp.tool(name="github_pull_request_update_body", annotations=COLLABORATION_WRITE)
    def github_pull_request_update_body(
        project_id: str,
        github_repository: str,
        number: int,
        body: str,
    ) -> dict[str, Any]:
        """Replace a pull request body and re-read the pull request."""
        return update_pull_request_body(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            number=number,
            body=body,
        )

    @mcp.tool(name="github_pull_request_comment", annotations=COLLABORATION_WRITE)
    def github_pull_request_comment(
        project_id: str,
        github_repository: str,
        number: int,
        body: str,
    ) -> dict[str, Any]:
        """Add one ordinary pull request conversation comment. This does not submit a review."""
        return add_pull_request_comment(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            number=number,
            body=body,
        )

    @mcp.tool(name="github_pull_request_request_reviewers", annotations=COLLABORATION_WRITE)
    def github_pull_request_request_reviewers(
        project_id: str,
        github_repository: str,
        number: int,
        reviewers: list[str],
    ) -> dict[str, Any]:
        """Request reviewers. This does not approve, request changes, or comment as a review."""
        return request_reviewers(
            policy,
            provider,
            principal_id=principal_id,
            project_id=project_id,
            github_repository=github_repository,
            number=number,
            reviewers=reviewers,
        )

    return mcp


def _server_info(policy: GitHubPolicy, principal_id: str) -> dict[str, Any]:
    return {
        "server_name": SERVER_NAME,
        "enabled": policy.enabled,
        "principal_id": principal_id,
        "policy_sha256": policy.sha256,
        "provider_id": "github-mcp-server",
        "provider_release": PROVIDER_RELEASE,
        "provider_commit": PROVIDER_COMMIT,
        "provider_feature": PROVIDER_FEATURE,
        "provider_tools": list(PROVIDER_TOOLS),
        "prohibited_tools": sorted(PROHIBITED_TOOLS),
        "catalog_fingerprint": catalog_fingerprint(),
        "tool_catalog": list(tool_catalog(policy)),
        "accepted_permissions": [
            {"permission": name, "access": access}
            for name, access in ACCEPTED_REPOSITORY_PERMISSIONS
        ],
        "excluded_permissions": list(EXCLUDED_REPOSITORY_PERMISSIONS),
        "issue_comment_permission": {
            "status": ISSUE_COMMENT_PERMISSION["status"],
            "accepted_design_includes_issues_write": False,
            "endpoint": ISSUE_COMMENT_PERMISSION["endpoint"],
        },
        "shadow_coupled": False,
        "product_acceptance": False,
        "webhooks": False,
    }
