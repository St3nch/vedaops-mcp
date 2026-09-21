"""GitHub App permission target for the pinned provider surface.

Accepted permissions are the smallest set verified against current GitHub
documentation for the endpoints the pinned tools call. Issues write stays
excluded. Pull requests write satisfies ordinary timeline comments.
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

# Create an issue comment, retrieved 2026-09-21:
# https://docs.github.com/en/rest/issues/comments#create-an-issue-comment
# GitHub App installation tokens need at least one of Issues write or
# Pull requests write. F008 already grants Pull requests write and still
# comments only after the number is observed to be a pull request.
ISSUE_COMMENT_PERMISSION = {
    "status": "satisfied_by_pull_requests_write",
    "accepted_design_includes_issues_write": False,
    "tool": "add_issue_comment",
    "endpoint": "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
    "satisfies_endpoint": "pull_requests:write",
    "documentation": "https://docs.github.com/en/rest/issues/comments#create-an-issue-comment",
    "reason": (
        "Timeline comments use the issue-comment endpoint. Current GitHub "
        "documentation says an installation token needs at least one of Issues "
        "write or Pull requests write. Pull requests write satisfies that "
        "requirement. Issues write is not granted, and the comment is sent only "
        "after the number is observed to be a pull request."
    ),
}
