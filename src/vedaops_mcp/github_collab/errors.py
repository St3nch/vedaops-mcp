"""Stable errors for the F008 GitHub collaboration boundary."""

from __future__ import annotations

from vedaops_mcp.errors import VedaOpsError


class GitHubCollabError(VedaOpsError):
    """Base class for F008 failures that are not an uncertain effect."""


class GitHubPolicyError(GitHubCollabError):
    """The operator policy is missing, insecure, or internally inconsistent."""


class GitHubAuthorityError(GitHubCollabError):
    """A principal, project, repository, or operation is not granted."""


class GitHubProviderError(GitHubCollabError):
    """The official provider is unavailable or its catalog is not acceptable."""
