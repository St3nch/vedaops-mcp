"""Launch plan for the pinned official GitHub MCP Server.

The child environment is constructed. It does not inherit the parent process
environment, so a Shadow token or a toolset override cannot widen the child.
The private key is passed by path, never by value.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from vedaops_mcp.github_collab.allowlist import (
    PROVIDER_FEATURE,
    PROVIDER_TOOLS,
    RELEASE_ARTIFACTS,
)
from vedaops_mcp.github_collab.errors import GitHubPolicyError
from vedaops_mcp.github_collab.policy import GitHubPolicy

CHILD_ENV_KEYS = (
    "GITHUB_APP_ID",
    "GITHUB_APP_INSTALLATION_ID",
    "GITHUB_APP_PRIVATE_KEY_PATH",
    "GITHUB_FEATURES",
    "GITHUB_TOOLS",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
)


@dataclass(frozen=True, slots=True)
class LaunchPlan:
    argv: tuple[str, ...]
    env: dict[str, str]

    def public_view(self) -> dict[str, object]:
        """Operator view of the launch plan. It does not read the key file."""
        return {
            "argv": list(self.argv),
            "env": dict(self.env),
            "env_keys": sorted(self.env),
        }


def launch_plan(policy: GitHubPolicy) -> LaunchPlan:
    """Build the only argv and environment the child provider may receive."""
    if not policy.enabled:
        raise GitHubPolicyError("VEDAOPS_GITHUB_DISABLED", "F008 GitHub collaboration is disabled")
    if policy.binary_path is None or policy.private_key_path is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_PROVIDER_UNAVAILABLE",
            "binary_path and private_key_path are required to launch the provider",
        )
    tools = ",".join(PROVIDER_TOOLS)
    argv = (
        str(policy.binary_path),
        "stdio",
        f"--tools={tools}",
        f"--features={PROVIDER_FEATURE}",
        f"--app-id={policy.app_id}",
        f"--app-installation-id={policy.installation_id}",
        f"--app-private-key-path={policy.private_key_path}",
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(policy.journal_directory.parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GITHUB_APP_ID": policy.app_id,
        "GITHUB_APP_INSTALLATION_ID": policy.installation_id,
        "GITHUB_APP_PRIVATE_KEY_PATH": str(policy.private_key_path),
        "GITHUB_FEATURES": PROVIDER_FEATURE,
        "GITHUB_TOOLS": tools,
    }
    if tuple(env) != CHILD_ENV_KEYS and set(env) != set(CHILD_ENV_KEYS):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "child environment does not match the F008 allowlist",
        )
    forbidden = {
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "GITHUB_READ_ONLY",
        "GITHUB_TOKEN",
        "GITHUB_TOOLSETS",
        "GITHUB_INSIDERS",
    }
    if forbidden & set(env):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "child environment contains a forbidden provider variable",
        )
    return LaunchPlan(argv=argv, env=env)


def artifact_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_artifact(path: Path, artifact_name: str) -> str:
    """Hash a release tarball and require the pinned digest."""
    expected = RELEASE_ARTIFACTS.get(artifact_name)
    if expected is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_INVALID",
            "artifact name is not a pinned F008 release asset",
        )
    try:
        actual = artifact_sha256(path)
    except OSError as exc:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_POLICY_UNAVAILABLE",
            "release artifact is unreadable",
        ) from exc
    if actual != expected:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_CATALOG_REJECTED",
            "release artifact digest does not match the pinned GitHub MCP Server release",
        )
    return actual
