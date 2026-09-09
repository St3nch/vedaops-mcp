"""MCP-02 restricted development-check execution."""

from __future__ import annotations

import shutil
import venv
from pathlib import Path

import pytest
from support import git, init_project, write_registry

import vedaops_mcp.checks as checks_module
from vedaops_mcp.authority import RegisteredCheck
from vedaops_mcp.checks import project_check_run
from vedaops_mcp.errors import AuthorityError, PolicyError
from vedaops_mcp.runtime import capture_project_runtime

RUNNER_AVAILABLE = all(
    path.is_file()
    for path in (
        Path("/usr/bin/bwrap"),
        Path("/usr/bin/prlimit"),
        Path("/usr/bin/systemd-run"),
    )
)


def _registry_with_check(
    tmp_path: Path,
    root: Path,
    *,
    check_id: str = "isolation",
    argv: tuple[str, ...] = ("/usr/bin/python3", "check.py"),
    timeout_seconds: int = 10,
    memory_mb: int = 512,
    runtime: str = "system",
) -> Path:
    argv_toml = ", ".join(repr(item) for item in argv)
    checks = (
        "\n[[projects.checks]]\n"
        f"id = {check_id!r}\n"
        f"argv = [{argv_toml}]\n"
        f"timeout_seconds = {timeout_seconds}\n"
        f"memory_mb = {memory_mb}\n"
        f"runtime = {runtime!r}\n"
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
    assert result.runner_profile == "linux-bwrap-systemd-v2"
    assert len(result.aggregate_limiter_sha256) == 64
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
def test_check_workspace_is_writable_but_disposable(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={
            "check.py": (
                "from pathlib import Path\n"
                "path = Path('.tool-cache')\n"
                "path.write_text('cache-ok')\n"
                "print(path.read_text())\n"
            )
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
    assert result.stdout.strip() == "cache-ok"
    assert not (root / ".tool-cache").exists()
    assert result.cleanup == "removed"


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


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_commit_capture_ignores_git_replace_refs(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={
            "check.py": 'print("MALICIOUS")\n',
            "clean.py": 'print("CLEAN")\n',
        },
    )
    malicious_blob = git(root, "rev-parse", f"{head}:check.py")
    clean_blob = git(root, "rev-parse", f"{head}:clean.py")
    git(root, "replace", malicious_blob, clean_blob)
    registry = _registry_with_check(tmp_path, root)

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="isolation",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "MALICIOUS"
    assert result.subject_kind == "exact_commit_snapshot"
    assert result.captured_commit == head


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_sandbox_allows_normal_child_process_creation(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    registry = _registry_with_check(
        tmp_path,
        root,
        check_id="spawn",
        argv=(
            "/usr/bin/python3",
            "-c",
            "import subprocess; subprocess.run(['/usr/bin/python3','-c','print(42)'], check=True)",
        ),
    )

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="spawn",
    )
    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "42"


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


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_ordinary_check_can_use_sanitized_project_venv(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    venv.EnvBuilder(with_pip=False).create(root / ".venv")
    sites = sorted((root / ".venv" / "lib").glob("python*/site-packages"))
    assert len(sites) == 1
    (sites[0] / "runtime_marker.py").write_text("VALUE = 'captured-runtime'\n")
    registry = _registry_with_check(
        tmp_path,
        root,
        check_id="runtime",
        argv=(
            "/workspace/.venv/bin/python",
            "-c",
            "import runtime_marker; print(runtime_marker.VALUE)",
        ),
        runtime="project_venv",
    )

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="runtime",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "captured-runtime"
    assert result.runtime is not None
    assert result.runtime.kind == "project_venv_sanitized"
    assert len(result.runtime.sha256) == 64


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_ordinary_check_preserves_editable_project_install_outside_workspace_cwd(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={"src/editable_demo/__init__.py": "VALUE = 'editable-runtime'\n"},
    )
    venv.EnvBuilder(with_pip=False).create(root / ".venv")
    sites = sorted((root / ".venv" / "lib").glob("python*/site-packages"))
    assert len(sites) == 1
    (sites[0] / "editable-demo.pth").write_text(str(root / "src") + "\n")
    registry = _registry_with_check(
        tmp_path,
        root,
        check_id="editable-runtime",
        argv=(
            "/workspace/.venv/bin/python",
            "-c",
            "import os; os.chdir('/tmp'); import editable_demo; print(editable_demo.VALUE)",
        ),
        runtime="project_venv",
    )

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="editable-runtime",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "editable-runtime"
    assert result.runtime is not None


@pytest.mark.skipif(not RUNNER_AVAILABLE, reason="Linux MCP-02 runner is unavailable")
def test_ordinary_check_can_use_captured_venv_console_executable(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    venv.EnvBuilder(with_pip=False).create(root / ".venv")
    sites = sorted((root / ".venv" / "lib").glob("python*/site-packages"))
    assert len(sites) == 1
    (sites[0] / "runtime_marker.py").write_text("VALUE = 'console-runtime'\n")
    tool = root / ".venv" / "bin" / "runtime-tool"
    tool.write_text(
        f"#!{root / '.venv' / 'bin' / 'python'}\n"
        "from runtime_marker import VALUE\n"
        "print(VALUE)\n"
    )
    tool.chmod(0o755)
    registry = _registry_with_check(
        tmp_path,
        root,
        check_id="runtime-tool",
        argv=("/workspace/.venv/bin/runtime-tool",),
        runtime="project_venv",
    )

    result = project_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="runtime-tool",
    )

    assert result.outcome == "passed", result.stderr
    assert result.stdout.strip() == "console-runtime"
    assert result.runtime is not None


def test_runtime_builder_ignores_repo_local_venv_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root = tmp_path / "project"
    root.mkdir()
    venv.EnvBuilder(with_pip=False).create(root / ".venv")
    marker = tmp_path / "controller-executed.txt"
    (root / "venv.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
    )
    destination = tmp_path / "runtime"
    uv_copy = tmp_path / "uv"
    monkeypatch.chdir(root)

    identity = capture_project_runtime(root, destination, uv_copy)

    assert identity.kind == "project_venv_sanitized"
    assert not marker.exists()


def test_sandbox_argv_wraps_worker_in_aggregate_systemd_scope(tmp_path: Path):
    check = RegisteredCheck(
        id="limits",
        argv=["/usr/bin/true"],
        timeout_seconds=5,
        memory_mb=256,
    )
    argv = checks_module._sandbox_argv(
        bwrap=Path("/usr/bin/bwrap"),
        prlimit=Path("/usr/bin/prlimit"),
        systemd_run=Path("/usr/bin/systemd-run"),
        snapshot_dir=tmp_path,
        check=check,
        timeout_seconds=5,
    )

    assert argv[:4] == ["/usr/bin/systemd-run", "--user", "--scope", "--quiet"]
    assert "--property=MemoryMax=268435456" in argv
    assert "--property=MemorySwapMax=0" in argv
    assert f"--property=TasksMax={checks_module.MAX_WORKER_TASKS}" in argv
    assert "/usr/bin/bwrap" in argv


def test_check_admission_refuses_when_global_capacity_is_exhausted(tmp_path: Path):
    root = tmp_path / "project"
    head = init_project(root, capabilities=("read", "check"))
    registry = _registry_with_check(tmp_path, root)
    acquired = 0
    try:
        for _ in range(checks_module.MAX_CONCURRENT_CHECKS):
            assert checks_module._CHECK_ADMISSION.acquire(blocking=False)
            acquired += 1
        with pytest.raises(PolicyError, match="VEDAOPS_CHECK_CAPACITY_REACHED"):
            project_check_run(
                registry,
                principal_id="test-agent",
                project_id="example",
                expected_git_head=head,
                check_id="isolation",
            )
    finally:
        for _ in range(acquired):
            checks_module._CHECK_ADMISSION.release()


def test_runner_availability_is_host_specific():
    assert shutil.which("bwrap") is not None or not RUNNER_AVAILABLE
