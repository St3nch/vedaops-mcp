"""MCP-02 restricted development-check execution."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from support import init_project, write_registry

from vedaops_mcp.checks import project_check_run
from vedaops_mcp.errors import AuthorityError, PolicyError

RUNNER_AVAILABLE = Path("/usr/bin/bwrap").is_file() and Path("/usr/bin/prlimit").is_file()


def _registry_with_check(
    tmp_path: Path,
    root: Path,
    *,
    check_id: str = "isolation",
    argv: tuple[str, ...] = ("/usr/bin/python3", "check.py"),
    timeout_seconds: int = 10,
    memory_mb: int = 512,
) -> Path:
    argv_toml = ", ".join(repr(item) for item in argv)
    checks = (
        "\n[[projects.checks]]\n"
        f"id = {check_id!r}\n"
        f"argv = [{argv_toml}]\n"
        f"timeout_seconds = {timeout_seconds}\n"
        f"memory_mb = {memory_mb}\n"
    )
    return write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read", "check"),
        principal_capabilities=("read", "check"),
        checks_toml=checks,
    )


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_check_runner_isolates_home_credentials_other_projects_network_and_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    operator_home = tmp_path / "operator-home"
    operator_home.mkdir()
    (operator_home / "controller-policy.toml").write_text("secret\n")
    other_project = tmp_path / "other-project"
    other_project.mkdir()
    (other_project / "secret.txt").write_text("other project\n")
    script = f"""import os
import pathlib
import resource
import socket

assert os.environ["HOME"] == "/home/worker"
assert "SSH_AUTH_SOCK" not in os.environ
assert "VEDAOPS_AGENT_ID" not in os.environ
assert not pathlib.Path({str(operator_home)!r}).exists()
assert not pathlib.Path({str(other_project)!r}).exists()
assert not pathlib.Path("/var/run/docker.sock").exists()
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
assert soft == 512 * 1024 * 1024
sock = socket.socket()
try:
    assert sock.connect_ex(("1.1.1.1", 53)) != 0
finally:
    sock.close()
print("sandbox-ok")
"""
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={"check.py": script},
    )
    registry = _registry_with_check(tmp_path, root)
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "agent.sock"))
    monkeypatch.setenv("VEDAOPS_AGENT_ID", "controller-agent")

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="isolation",
    )

    assert result.outcome == "passed", result.stderr
    assert result.exit_code == 0
    assert result.stdout.strip() == "sandbox-ok"
    assert result.subject_kind == "exact_commit_snapshot"
    assert result.captured_commit == head
    assert len(result.captured_input_sha256) == 64
    assert len(result.check_definition_sha256) == 64
    assert result.runner_profile == "linux-bwrap-v1"
    assert result.cleanup == "removed"
    assert result.uncertain_effects is False
    assert "working_tree_and_untracked_changes" in result.exclusions


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_check_executes_commit_snapshot_not_dirty_working_tree(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={"check.py": 'print("committed")\n'},
    )
    registry = _registry_with_check(tmp_path, root)
    (root / "check.py").write_text('print("dirty")\n')

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="isolation",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "committed"
    assert "dirty" not in result.stdout


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_commit_capture_ignores_git_archive_export_attributes(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={
            "check.py": 'print("$Format:%H$")\n',
            ".gitattributes": "check.py export-ignore export-subst\n",
        },
    )
    registry = _registry_with_check(tmp_path, root)

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="isolation",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "$Format:%H$"
    assert result.subject_kind == "exact_commit_snapshot"


def test_caller_cannot_select_an_unapproved_check(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    registry = _registry_with_check(tmp_path, root, check_id="approved")

    with pytest.raises(AuthorityError, match="VEDAOPS_CHECK_NOT_AUTHORIZED"):
        project_check_run(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            check_id="caller-selected-command",
        )


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_caller_timeout_can_only_narrow_operator_limit(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    registry = _registry_with_check(
        tmp_path,
        root,
        check_id="sleep",
        argv=("/usr/bin/python3", "-c", "import time; time.sleep(5)"),
        timeout_seconds=5,
    )

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="sleep",
        timeout_seconds=1,
    )
    assert result.outcome == "timed_out", result.stderr

    with pytest.raises(PolicyError, match="approved limit 5"):
        project_check_run(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            check_id="sleep",
            timeout_seconds=6,
        )


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_check_output_is_bounded_and_truncation_is_explicit(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    registry = _registry_with_check(
        tmp_path,
        root,
        check_id="output",
        argv=("/usr/bin/python3", "-c", "print('x' * 200000)"),
        timeout_seconds=5,
    )

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="output",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 128 * 1024
    assert result.cleanup == "removed"


def test_runner_availability_is_host_specific():
    assert shutil.which("bwrap") is not None or not RUNNER_AVAILABLE
