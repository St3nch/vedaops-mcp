"""Stdio entrypoint and fail-closed startup checks."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from vedaops_mcp.authority import load_registry, require_principal
from vedaops_mcp.errors import VedaOpsError
from vedaops_mcp.server import build_server
from vedaops_mcp.settings import Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vedaops-mcp")
    subparsers = parser.add_subparsers(dest="transport")
    subparsers.add_parser("stdio", help="run over standard input/output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    transport = args.transport or "stdio"
    if transport != "stdio":
        print(f"VEDAOPS_INVALID_ARGUMENT: unsupported transport {transport!r}", file=sys.stderr)
        return 2
    try:
        settings = Settings.load()
        registry = load_registry(settings.registry_path)
        require_principal(registry, settings.principal_id)
    except VedaOpsError as exc:
        print(f"{exc.code}: {exc.detail}", file=sys.stderr)
        return 2
    build_server(settings).run(transport="stdio", show_banner=False)
    return 0
