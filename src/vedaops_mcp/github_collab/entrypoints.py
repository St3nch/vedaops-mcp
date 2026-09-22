"""Operator entrypoint for the F008 GitHub collaboration boundary."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from vedaops_mcp.errors import VedaOpsError
from vedaops_mcp.github_collab.allowlist import catalog_rejection
from vedaops_mcp.github_collab.launcher import launch_plan, validate_artifact
from vedaops_mcp.github_collab.mcp_client import StdioGitHubProvider
from vedaops_mcp.github_collab.policy import (
    POLICY_ENVIRONMENT_VARIABLE,
    GitHubPolicy,
    load_policy,
    principal_from_environ,
    sha256_file,
)
from vedaops_mcp.github_collab.server import build_github_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vedaops-github")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("stdio", help="serve the F008 boundary over standard input/output")
    policy = subparsers.add_parser(
        "validate-policy",
        help="load operator policy without calling GitHub",
    )
    policy.add_argument("--policy", type=Path, required=True)
    catalog = subparsers.add_parser(
        "validate-catalog",
        help="require an advertised tools/list to match the pinned allowlist",
    )
    catalog.add_argument("catalog", type=Path)
    artifact = subparsers.add_parser(
        "validate-artifact",
        help="require a release tarball to match the pinned digest",
    )
    artifact.add_argument("artifact", type=Path)
    artifact.add_argument("--name", required=True)
    installed = subparsers.add_parser(
        "hash-executable",
        help="print the locally derived SHA-256 of an installed provider executable",
    )
    installed.add_argument("executable", type=Path)
    launch = subparsers.add_parser(
        "render-launch",
        help="print the child argv and environment keys without reading the private key",
    )
    launch.add_argument("--policy", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        if args.command == "validate-catalog":
            reason = catalog_rejection(_advertised_names(args.catalog))
            if reason is not None:
                print(f"VEDAOPS_GITHUB_CATALOG_REJECTED: {reason}", file=sys.stderr)
                return 2
            print("catalog matches the pinned F008 allowlist")
            return 0
        if args.command == "validate-artifact":
            digest = validate_artifact(args.artifact, args.name)
            print(digest)
            return 0
        if args.command == "hash-executable":
            digest = sha256_file(args.executable)
            print(digest)
            print(
                "locally derived installed-executable digest; "
                "not the published release-archive digest",
                file=sys.stderr,
            )
            return 0
        if args.command == "validate-policy":
            policy = load_policy(args.policy)
            print(_policy_summary(policy))
            return 0
        if args.command == "render-launch":
            policy = load_policy(args.policy)
            print(json.dumps(launch_plan(policy).public_view(), indent=2, sort_keys=True))
            return 0
        if args.command == "stdio":
            return _stdio(environment)
    except VedaOpsError as exc:
        print(f"{exc.code}: {exc.detail}", file=sys.stderr)
        return 2
    print("VEDAOPS_INVALID_ARGUMENT: unknown command", file=sys.stderr)
    return 2


def _stdio(environment: Mapping[str, str]) -> int:
    raw_policy = environment.get(POLICY_ENVIRONMENT_VARIABLE)
    if not raw_policy:
        print(
            f"VEDAOPS_GITHUB_POLICY_UNAVAILABLE: {POLICY_ENVIRONMENT_VARIABLE} is required",
            file=sys.stderr,
        )
        return 2
    policy = load_policy(Path(raw_policy))
    principal = principal_from_environ(environment)
    provider: StdioGitHubProvider | None = None
    if policy.enabled:
        provider = StdioGitHubProvider(policy)
    try:
        build_github_server(policy, principal, provider).run(transport="stdio", show_banner=False)
    finally:
        if provider is not None:
            provider.close()
    return 0


def _advertised_names(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VedaOpsError("VEDAOPS_GITHUB_CATALOG_REJECTED", "catalog file is not JSON") from exc
    if isinstance(data, list):
        names = data
    elif isinstance(data, dict) and isinstance(data.get("tools"), list):
        names = [
            item.get("name") if isinstance(item, dict) else item for item in data["tools"]
        ]
    else:
        raise VedaOpsError(
            "VEDAOPS_GITHUB_CATALOG_REJECTED",
            "catalog file must be a list of names or a tools/list result",
        )
    if not all(isinstance(name, str) for name in names):
        raise VedaOpsError("VEDAOPS_GITHUB_CATALOG_REJECTED", "catalog tool names must be strings")
    return list(names)


def _policy_summary(policy: GitHubPolicy) -> str:
    return json.dumps(
        {
            "enabled": policy.enabled,
            "policy_sha256": policy.sha256,
            "projects": [project.id for project in policy.projects],
            "provider_commit": policy.commit,
            "provider_release": policy.release,
            "secret_configured": policy.private_key_path is not None,
        },
        sort_keys=True,
    )
