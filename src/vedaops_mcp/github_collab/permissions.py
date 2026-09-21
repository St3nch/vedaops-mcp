"""GitHub App permission target for the pinned provider surface.

Accepted permissions are the smallest set verified against the current
GitHub Apps permission table for the endpoints the pinned tools call.
Issues write is deliberately absent. See ``ISSUE_COMMENT_PERMISSION``.
"""

from __future__ import annotations

# (permission, access). Metadata read is the App baseline.
ACCEPTED_REPOSITORY_PERMISSIONS = (
    ("metadata", "read"),
    ("contents", "read"),
    ("pull_requests", "write"),
    ("actions", "read"),
    ("checks", "read"),
    ("commit_statuses", "read"),
)

# Permissions that must not be requested for this slice.
EXCLUDED_REPOSITORY_PERMISSIONS = (
    "administration",
    "contents:write",
    "checks:write",
    "commit_statuses:write",
    "deployments",
    "issues:write",
    "secrets",
    "single_file",
    "variables",
    "workflows:write",
    "webhooks",
)

# Official permission table, retrieved 2026-09-21:
# https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps
# POST /repos/{owner}/{repo}/issues/{issue_number}/comments is listed under both
# repository "Issues" write and repository "Pull requests" write. Each row says
# multiple permissions may be required, or a different permission may be used.
# The pinned tool add_issue_comment calls Issues.CreateComment, which is that
# endpoint. Ordinary conversation comments have no narrower upstream tool.
ISSUE_COMMENT_PERMISSION = {
    "status": "unresolved",
    "accepted_design_includes_issues_write": False,
    "tool": "add_issue_comment",
    "endpoint": "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
    "documented_rows": ("issues:write", "pull_requests:write"),
    "documentation": (
        "https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps"
    ),
    "reason": (
        "The pinned GitHub MCP Server posts an ordinary pull request conversation "
        "comment with add_issue_comment, which calls the issue-comment endpoint. "
        "GitHub lists that endpoint under both Issues write and Pull requests write "
        "and says multiple permissions may be required or a different permission may "
        "be used. F008 does not add Issues write to the accepted App design."
    ),
}
