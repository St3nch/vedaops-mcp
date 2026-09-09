"""MCP-04 tool catalog, refusals, and server identity contract."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from support import init_project, write_registry

from vedaops_mcp.server import TOOL_CATALOG, build_server
from vedaops_mcp.settings import Settings

FORBIDDEN_TOOLS = {
    "host_command_run",
    "project_command_run",
    "project_task_run",
    "project_review_run",
    "project_health",
    "project_checkpoint_create",
    "host_runtime_status",
    "host_service_inventory",
    "project_desk_verify",
    "project_desk_report",
    "project_desk_walkback",
    "project_git_push",
    "project_git_fetch",
    "project_git_pull",
}
CHECK_TOOLS = {"project_check_run", "project_postgres_check_run"}
CHANGE_TOOLS = {
    "project_file_write",
    "project_text_replace",
    "project_patch_apply",
    "project_file_delete",
    "project_git_commit",
    "project_git_branch_create",
    "project_git_switch",
    "project_git_merge_ff",
    "project_git_branch_delete",
}


def _settings(tmp_path: Path) -> Settings:
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        context_files=("README.md",),
    )
    return Settings(principal_id="test-agent", registry_path=registry.resolve())


@pytest.mark.asyncio
async def test_tool_catalog_is_exactly_the_mcp04_core_plane(tmp_path: Path):
    async with Client(build_server(_settings(tmp_path))) as client:
        tools = await client.list_tools()
        names = [tool.name for tool in tools]
        assert names == list(TOOL_CATALOG)
        assert FORBIDDEN_TOOLS.isdisjoint(names)
        by_name = {tool.name: tool for tool in tools}
        for name, tool in by_name.items():
            assert tool.annotations.openWorldHint is False
            if name in CHECK_TOOLS:
                assert tool.annotations.readOnlyHint is False
                assert tool.annotations.destructiveHint is False
                assert tool.annotations.idempotentHint is False
            elif name in CHANGE_TOOLS:
                assert tool.annotations.readOnlyHint is False
                assert tool.annotations.destructiveHint is True
                assert tool.annotations.idempotentHint is False
            else:
                assert tool.annotations.readOnlyHint is True
                assert tool.annotations.destructiveHint is False
                assert tool.annotations.idempotentHint is True


@pytest.mark.asyncio
async def test_server_info_reports_principal_policy_and_catalog(tmp_path: Path):
    settings = _settings(tmp_path)
    async with Client(build_server(settings)) as client:
        info = (await client.call_tool("vedaops_server_info", {})).structured_content

    assert info["server_name"] == "vedaops-mcp"
    assert info["principal_id"] == "test-agent"
    assert info["policy_state"] == "observed"
    assert info["policy_sha256"]
    assert info["tool_catalog"] == list(TOOL_CATALOG)
    assert info["instance_id"]
    assert info["started_at"]
    assert info["process_id"] > 0
    artifact = info["controller_artifact"]
    assert artifact["state"] == "observed"
    assert artifact["kind"] == "loaded_package_tree"
    assert artifact["sha256"] and len(artifact["sha256"]) == 64
    assert artifact["files"] > 0
    assert artifact["bytes"] > 0
    runtime = info["python_runtime"]
    assert runtime["state"] == "observed"
    assert runtime["sha256"] and len(runtime["sha256"]) == 64
    assert runtime["executable"]
    assert runtime["version"]
    grants = {item["project_id"]: item for item in info["effective_grants"]}
    assert grants["example"]["workspace_id"] == "primary"
    assert grants["example"]["authorized"] is True
    assert grants["example"]["effective_capabilities"] == ["read"]


@pytest.mark.asyncio
async def test_unauthorized_project_is_a_stable_refusal(tmp_path: Path):
    async with Client(build_server(_settings(tmp_path))) as client:
        with pytest.raises(ToolError, match="VEDAOPS_PROJECT_NOT_AUTHORIZED"):
            await client.call_tool("project_get", {"project_id": "missing"})
        with pytest.raises(ToolError, match="VEDAOPS_PATH_FORBIDDEN"):
            await client.call_tool(
                "project_file_read",
                {"project_id": "example", "path": ".env"},
            )


@pytest.mark.asyncio
async def test_orientation_and_reads_round_trip(tmp_path: Path):
    async with Client(build_server(_settings(tmp_path))) as client:
        listed = (await client.call_tool("projects_list", {})).structured_content
        assert listed["projects"][0]["id"] == "example"
        detail = (
            await client.call_tool("project_get", {"project_id": "example"})
        ).structured_content
        assert detail["workspace_id"] == "primary"
        assert detail["git"]["state"] == "observed"
        tree = (
            await client.call_tool("project_tree", {"project_id": "example"})
        ).structured_content
        assert tree["returned_count"] > 0
        read = (
            await client.call_tool(
                "project_file_read",
                {"project_id": "example", "path": "README.md"},
            )
        ).structured_content
        assert "hello world" in read["content"]
        status = (
            await client.call_tool("project_git_status", {"project_id": "example"})
        ).structured_content
        assert status["clean"] is True
        assert status["git_head"] == detail["git"]["git_head"]
