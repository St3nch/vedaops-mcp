"""Pinned official GitHub MCP Server surface for F008.

The pin is the accepted provider identity. A future upgrade is detectable
because policy, launch arguments, and the advertised catalog must match
these constants exactly.
"""

from __future__ import annotations

import hashlib
import json

PROVIDER_ID = "github-mcp-server"
PROVIDER_REPOSITORY = "github/github-mcp-server"
PROVIDER_RELEASE = "v1.12.2"
PROVIDER_COMMIT = "85598ba6e1256f7ebf4867b95d63b833c4549264"
PROVIDER_API_VERSION = "2022-11-28"
PROVIDER_FEATURE = "pull_requests_granular"
ACCEPTED_PROVIDER_VERSIONS = frozenset({PROVIDER_RELEASE, "1.12.2"})

# Release asset digests published with v1.12.2. These identify the tarball,
# not the extracted binary.
RELEASE_ARTIFACTS = {
    "github-mcp-server_Linux_x86_64.tar.gz": (
        "95843162759da2c31dde082dd145be35db82164594796c294414b69790c2290e"
    ),
    "github-mcp-server_Linux_arm64.tar.gz": (
        "2b30f9fcc061b57456cbe38ddc0f13c88863bad49557508a9196f2d1c4cb17a5"
    ),
}
DEFAULT_ARTIFACT = "github-mcp-server_Linux_x86_64.tar.gz"

# Exact child-process tool catalog. Empty toolsets plus this list is the
# upstream rule that avoids the default catalog. Order is launch order.
PROVIDER_TOOLS = (
    "actions_list",
    "add_issue_comment",
    "create_pull_request",
    "get_commit",
    "get_me",
    "list_pull_requests",
    "pull_request_read",
    "request_pull_request_reviewers",
    "update_pull_request_body",
    "update_pull_request_title",
)

# Names that must not appear even as an extra. The catalog check also
# rejects every other name, so this set is the explicit prohibited contract.
PROHIBITED_TOOLS = frozenset(
    {
        "actions_run_trigger",
        "add_pull_request_review_comment",
        "create_branch",
        "create_or_update_file",
        "create_pull_request_review",
        "delete_file",
        "get_file_contents",
        "issue_write",
        "merge_pull_request",
        "pull_request_review_write",
        "push_files",
        "search_code",
        "search_repositories",
        "submit_pending_pull_request_review",
        "update_pull_request",
        "update_pull_request_branch",
        "update_pull_request_draft_state",
        "update_pull_request_state",
    }
)

PULL_REQUEST_READ_METHODS = frozenset(
    {
        "get",
        "get_diff",
        "get_status",
        "get_files",
        "get_commits",
        "get_review_comments",
        "get_reviews",
        "get_comments",
        "get_check_runs",
    }
)

# actions_list can also list artifacts. VedaOps rejects that method before
# dispatch. The child still exposes one tool, so the method gate is mandatory.
ACTIONS_LIST_METHODS = frozenset(
    {
        "list_workflows",
        "list_workflow_runs",
        "list_workflow_jobs",
    }
)

OPERATION_CLASSES = frozenset(
    {
        "read",
        "pr_create",
        "pr_update_title",
        "pr_update_body",
        "pr_comment",
        "pr_request_reviewers",
    }
)

# Launch must not enable these. They change write behavior or widen the catalog.
PROHIBITED_FEATURES = frozenset(
    {
        "insiders",
        "issues_granular",
        "remote_mcp_ui_apps",
        "mcp_apps_disable_form_deferral",
        "thread_resolution_reason",
    }
)


def catalog_fingerprint() -> str:
    """Return the identity of the accepted provider surface."""
    payload = {
        "api_version": PROVIDER_API_VERSION,
        "commit": PROVIDER_COMMIT,
        "feature": PROVIDER_FEATURE,
        "prohibited_tools": sorted(PROHIBITED_TOOLS),
        "release": PROVIDER_RELEASE,
        "tools": list(PROVIDER_TOOLS),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def catalog_rejection(advertised: list[str]) -> str | None:
    """Return why an advertised catalog is unacceptable, or None."""
    names = list(advertised)
    if any(not isinstance(name, str) or not name for name in names):
        return "advertised catalog contains an empty tool name"
    if len(names) != len(set(names)):
        return "advertised catalog contains duplicate tool names"
    advertised_set = set(names)
    missing = [name for name in PROVIDER_TOOLS if name not in advertised_set]
    if missing:
        return "narrow provider tools are unavailable: " + ", ".join(missing)
    prohibited = sorted(advertised_set & PROHIBITED_TOOLS)
    if prohibited:
        return "prohibited provider tools are advertised: " + ", ".join(prohibited)
    extra = sorted(advertised_set - set(PROVIDER_TOOLS))
    if extra:
        return "unexpected provider tools are advertised: " + ", ".join(extra)
    return None
