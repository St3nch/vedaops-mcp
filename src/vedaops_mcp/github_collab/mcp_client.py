"""Minimal stdio MCP client for the pinned GitHub MCP Server.

This speaks only initialize, tools/list, and tools/call. It is not a general
shell and it does not forward the upstream catalog to the caller.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import threading
import time
from collections.abc import Mapping
from typing import Any

from vedaops_mcp.github_collab.allowlist import (
    ACCEPTED_PROVIDER_VERSIONS,
    catalog_rejection,
)
from vedaops_mcp.github_collab.errors import GitHubProviderError
from vedaops_mcp.github_collab.launcher import LaunchPlan, launch_plan
from vedaops_mcp.github_collab.policy import GitHubPolicy
from vedaops_mcp.github_collab.provider import (
    CommentView,
    CommitView,
    IdentityView,
    ProviderCallError,
    ProviderTransportError,
    PullView,
    ReviewView,
    WriteView,
    parse_comments,
    parse_commit,
    parse_identity,
    parse_pull,
    parse_reviews,
    parse_write,
)
from vedaops_mcp.github_collab.sanitize import scrub_text

_CALL_DEADLINE_SECONDS = 30
_MAX_STDERR_BYTES = 4096
_MAX_LINE_BYTES = 65_536
_MAX_FRAME_BYTES = 1_048_576
_MAX_HEADER_LINES = 32
_MAX_UNRELATED_MESSAGES = 32


class StdioGitHubProvider:
    """Child process bound to one validated launch plan."""

    def __init__(self, policy: GitHubPolicy, plan: LaunchPlan | None = None) -> None:
        self._plan = plan or launch_plan(policy)
        self._next_id = 1
        self._lock = threading.Lock()
        self._stderr = bytearray()
        self._process = subprocess.Popen(
            self._plan.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._plan.env,
            cwd=self._plan.env["HOME"],
        )
        if self._process.stdout is not None:
            os.set_blocking(self._process.stdout.fileno(), False)
        self._stdout_buffer = bytearray()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()
        try:
            result = self._request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "vedaops-github", "version": "0.1.0"},
                },
            )
            self._notify("notifications/initialized", {})
            server_info = result.get("serverInfo") if isinstance(result, dict) else None
            version = ""
            if isinstance(server_info, dict) and isinstance(server_info.get("version"), str):
                version = server_info["version"]
            self._version = version
            names: list[str] = []
            cursor: str | None = None
            for _page in range(5):
                params: dict[str, Any] = {}
                if cursor is not None:
                    params["cursor"] = cursor
                listed = self._request("tools/list", params)
                tools = listed.get("tools") if isinstance(listed, dict) else None
                if not isinstance(tools, list):
                    raise ProviderCallError(
                        "tools/list did not return tools",
                        effect_uncertain=False,
                    )
                for tool in tools:
                    if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                        names.append(tool["name"])
                cursor = listed.get("nextCursor") if isinstance(listed, dict) else None
                if not isinstance(cursor, str) or not cursor:
                    break
            else:
                raise ProviderCallError("tools/list did not finish", effect_uncertain=False)
            self._catalog = tuple(names)
            reason = catalog_rejection(names)
            if self._version not in ACCEPTED_PROVIDER_VERSIONS or reason is not None:
                detail = reason or f"provider version {self._version!r} is not pinned"
                raise GitHubProviderError("VEDAOPS_GITHUB_CATALOG_REJECTED", detail)
        except Exception:
            self.close()
            raise

    def catalog(self) -> tuple[str, ...]:
        return self._catalog

    def provider_version(self) -> str:
        return self._version

    def close(self) -> None:
        process = self._process
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    def get_identity(self) -> IdentityView:
        return parse_identity(self._tool("get_me", {}))

    def get_commit(self, owner: str, repo: str, ref: str) -> CommitView:
        return parse_commit(
            self._tool(
                "get_commit",
                {"owner": owner, "repo": repo, "sha": ref, "detail": "none"},
            )
        )

    def get_pull_request(self, owner: str, repo: str, number: int) -> PullView:
        payload = self._tool(
            "pull_request_read",
            {"method": "get", "owner": owner, "repo": repo, "pullNumber": number},
        )
        return parse_pull(payload)

    def read_pull_request(
        self,
        owner: str,
        repo: str,
        number: int,
        method: str,
        page: int = 1,
        per_page: int = 30,
        after: str | None = None,
    ) -> object:
        return self._tool(
            "pull_request_read",
            pull_request_read_arguments(
                owner,
                repo,
                number,
                method,
                page,
                per_page,
                after,
            ),
        )

    def list_pull_requests(
        self,
        owner: str,
        repo: str,
        *,
        head: str,
        base: str,
        state: str,
    ) -> list[PullView]:
        payload = self._tool(
            "list_pull_requests",
            {"owner": owner, "repo": repo, "head": head, "base": base, "state": state},
        )
        if not isinstance(payload, list):
            raise ProviderCallError("pull request list was not a list", effect_uncertain=True)
        return [parse_pull(item) for item in payload]

    def list_comments(
        self,
        owner: str,
        repo: str,
        number: int,
        page: int = 1,
        per_page: int = 100,
    ) -> list[CommentView]:
        payload = self._tool(
            "pull_request_read",
            pull_request_read_arguments(
                owner,
                repo,
                number,
                "get_comments",
                page,
                per_page,
                None,
            ),
        )
        return parse_comments(payload)

    def list_reviews(
        self,
        owner: str,
        repo: str,
        number: int,
        page: int = 1,
        per_page: int = 30,
    ) -> list[ReviewView]:
        payload = self._tool(
            "pull_request_read",
            pull_request_read_arguments(
                owner,
                repo,
                number,
                "get_reviews",
                page,
                per_page,
                None,
            ),
        )
        return parse_reviews(payload)

    def list_actions(
        self,
        owner: str,
        repo: str,
        method: str,
        resource_id: str | None,
        page: int = 1,
        per_page: int = 30,
    ) -> object:
        arguments: dict[str, Any] = {
            "method": method,
            "owner": owner,
            "repo": repo,
            "page": page,
            "perPage": per_page,
        }
        if resource_id is not None:
            arguments["resource_id"] = resource_id
        return self._tool("actions_list", arguments)

    def create_pull_request(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool,
    ) -> WriteView:
        arguments: dict[str, Any] = {
            "owner": owner,
            "repo": repo,
            "title": title,
            "head": head,
            "base": base,
            "draft": draft,
        }
        if body:
            arguments["body"] = body
        return parse_write(self._tool("create_pull_request", arguments))

    def update_pull_request_title(
        self, owner: str, repo: str, number: int, title: str
    ) -> WriteView:
        return parse_write(
            self._tool(
                "update_pull_request_title",
                {"owner": owner, "repo": repo, "pullNumber": number, "title": title},
            )
        )

    def update_pull_request_body(
        self, owner: str, repo: str, number: int, body: str
    ) -> WriteView:
        return parse_write(
            self._tool(
                "update_pull_request_body",
                {"owner": owner, "repo": repo, "pullNumber": number, "body": body},
            )
        )

    def add_pull_request_comment(
        self, owner: str, repo: str, number: int, body: str
    ) -> WriteView:
        return parse_write(
            self._tool(
                "add_issue_comment",
                {"owner": owner, "repo": repo, "issue_number": number, "body": body},
            )
        )

    def request_reviewers(
        self, owner: str, repo: str, number: int, reviewers: list[str]
    ) -> WriteView:
        return parse_write(
            self._tool(
                "request_pull_request_reviewers",
                {"owner": owner, "repo": repo, "pullNumber": number, "reviewers": reviewers},
            )
        )

    def _tool(self, name: str, arguments: Mapping[str, Any]) -> object:
        try:
            result = self._request("tools/call", {"name": name, "arguments": dict(arguments)})
        except ProviderTransportError:
            raise
        except ProviderCallError:
            raise
        except (OSError, json.JSONDecodeError, UnicodeError, ValueError) as exc:
            raise ProviderTransportError(
                "provider transport failed",
                effect_possible=True,
            ) from exc
        if not isinstance(result, dict):
            raise ProviderCallError("provider tool result was not an object", effect_uncertain=True)
        text = _content_text(result)
        if result.get("isError") is True:
            raise ProviderCallError(
                _safe(text or "provider tool failed"),
                effect_uncertain=not _explicit_no_effect(text),
            )
        if not text:
            raise ProviderCallError("provider tool result was empty", effect_uncertain=True)
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ProviderTransportError(
                    "provider tool result was not valid JSON",
                    effect_possible=True,
                ) from exc
        return text

    def _request(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + _CALL_DEADLINE_SECONDS
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": dict(params),
                }
            )
            skipped = 0
            while True:
                message = self._read_message(deadline)
                if message.get("id") != request_id:
                    skipped += 1
                    if skipped > _MAX_UNRELATED_MESSAGES:
                        raise ProviderTransportError(
                            "provider sent too many unrelated messages",
                            effect_possible=True,
                        )
                    continue
                if "error" in message:
                    raise ProviderCallError(
                        _safe(json.dumps(message["error"])),
                        effect_uncertain=True,
                    )
                result = message.get("result")
                if not isinstance(result, dict):
                    raise ProviderCallError(
                        "provider response omitted a result object",
                        effect_uncertain=True,
                    )
                return result

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        with self._lock:
            self._send({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def _send(self, message: Mapping[str, Any]) -> None:
        stdin = self._process.stdin
        if stdin is None or self._process.poll() is not None:
            raise ProviderTransportError(
                "provider process is not running",
                effect_possible=False,
            )
        try:
            stdin.write(json.dumps(message).encode() + b"\n")
            stdin.flush()
        except BrokenPipeError as exc:
            raise ProviderTransportError(
                "provider pipe closed during request",
                effect_possible=True,
            ) from exc
        except OSError as exc:
            raise ProviderTransportError(
                "provider pipe failed during request",
                effect_possible=True,
            ) from exc

    def _read_message(self, deadline: float) -> dict[str, Any]:
        try:
            line = self._readline(deadline)
        except (OSError, ValueError) as exc:
            raise ProviderTransportError(
                "provider frame failed",
                effect_possible=True,
            ) from exc
        if line.lower().startswith(b"content-length:"):
            length = _content_length(line)
            headers = 0
            while True:
                header = self._readline(deadline)
                headers += 1
                if headers > _MAX_HEADER_LINES:
                    raise ProviderTransportError(
                        "provider frame header is too large",
                        effect_possible=True,
                    )
                if header in {b"\n", b"\r\n"}:
                    break
            payload = self._read_exact(length, deadline)
            try:
                message = json.loads(payload)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise ProviderTransportError(
                    "provider frame was not valid JSON",
                    effect_possible=True,
                ) from exc
        else:
            try:
                message = json.loads(line)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise ProviderTransportError(
                    "provider message was not valid JSON",
                    effect_possible=True,
                ) from exc
        if not isinstance(message, dict):
            raise ProviderTransportError(
                "provider message was not an object",
                effect_possible=True,
            )
        return message

    def _readline(self, deadline: float) -> bytes:
        while True:
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                if newline > _MAX_LINE_BYTES:
                    raise ProviderTransportError(
                        "provider line exceeded the size limit",
                        effect_possible=True,
                    )
                line = bytes(self._stdout_buffer[: newline + 1])
                del self._stdout_buffer[: newline + 1]
                return line
            if len(self._stdout_buffer) > _MAX_LINE_BYTES:
                raise ProviderTransportError(
                    "provider line exceeded the size limit",
                    effect_possible=True,
                )
            chunk = self._read_available(deadline)
            self._stdout_buffer.extend(chunk)

    def _read_exact(self, length: int, deadline: float) -> bytes:
        while len(self._stdout_buffer) < length:
            self._stdout_buffer.extend(self._read_available(deadline))
        payload = bytes(self._stdout_buffer[:length])
        del self._stdout_buffer[:length]
        return payload

    def _read_available(self, deadline: float) -> bytes:
        stdout = self._process.stdout
        if stdout is None:
            raise ProviderTransportError("provider stdout closed", effect_possible=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderTransportError("provider timed out", effect_possible=True)
        ready, _, _ = select.select([stdout], [], [], remaining)
        if not ready:
            raise ProviderTransportError("provider timed out", effect_possible=True)
        try:
            chunk = os.read(stdout.fileno(), 65536)
        except BlockingIOError:
            return b""
        if not chunk:
            raise ProviderTransportError("provider stdout closed", effect_possible=True)
        return chunk

    def _drain_stderr(self) -> None:
        stderr = self._process.stderr
        if stderr is None:
            return
        while True:
            chunk = stderr.read(1024)
            if not chunk:
                return
            self._stderr.extend(chunk[: _MAX_STDERR_BYTES - len(self._stderr)])


def pull_request_read_arguments(
    owner: str,
    repo: str,
    number: int,
    method: str,
    page: int,
    per_page: int,
    after: str | None,
) -> dict[str, Any]:
    """Build upstream arguments without pretending page offsets review threads."""
    arguments: dict[str, Any] = {
        "method": method,
        "owner": owner,
        "repo": repo,
        "pullNumber": number,
        "perPage": per_page,
    }
    if method == "get_review_comments":
        if after:
            arguments["after"] = after
        return arguments
    arguments["page"] = page
    return arguments


def _content_text(result: Mapping[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(item["text"])
        elif isinstance(item, str):
            parts.append(item)
    return "\n".join(parts)


def _content_length(line: bytes) -> int:
    try:
        raw = line.split(b":", 1)[1].strip()
        if not raw or raw != raw.strip() or not raw.isdigit():
            raise ValueError
        length = int(raw)
    except (IndexError, ValueError) as exc:
        raise ProviderTransportError(
            "provider content-length is malformed",
            effect_possible=True,
        ) from exc
    if length < 0 or length > _MAX_FRAME_BYTES:
        raise ProviderTransportError(
            "provider frame exceeds the size limit",
            effect_possible=True,
        )
    return length


def _explicit_no_effect(text: str) -> bool:
    """True only for an explicit structured rejection, not a status substring."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return payload.get("effect") == "none" and payload.get("status") in {401, 403, 404, 422}


def _safe(value: str) -> str:
    text, _redacted = scrub_text(value)
    return text[:500]
