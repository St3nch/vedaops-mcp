"""MCP-03 disposable PostgreSQL 18 substrate."""

from __future__ import annotations

import json
import subprocess
import venv
from pathlib import Path

import pytest
from support import init_project, write_registry

import vedaops_mcp.postgres as postgres_module
from vedaops_mcp.checks import project_check_run
from vedaops_mcp.errors import PolicyError
from vedaops_mcp.postgres import POSTGRES_IMAGE, project_postgres_check_run

DOCKER = Path("/usr/bin/docker")


def _postgres_image_available() -> bool:
    if not DOCKER.is_file():
        return False
    completed = subprocess.run(
        [str(DOCKER), "image", "inspect", POSTGRES_IMAGE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
    )
    return completed.returncode == 0


POSTGRES_AVAILABLE = _postgres_image_available()


def _project_with_postgres_check(
    tmp_path: Path,
    *,
    script: str,
    timeout_seconds: int = 10,
) -> tuple[Path, Path, str]:
    root = tmp_path / "project"
    head = init_project(
        root,
        capabilities=("read", "check"),
        files={"check.py": script},
        gitignore=".env\nignored.txt\n.venv\n",
    )
    venv.EnvBuilder(with_pip=False, symlinks=True).create(root / ".venv")
    checks = (
        "\n[[projects.checks]]\n"
        "id = 'postgres'\n"
        "argv = ['/workspace/.venv/bin/python', 'check.py']\n"
        f"timeout_seconds = {timeout_seconds}\n"
        "memory_mb = 512\n"
        "runtime = 'project_venv'\n"
        "substrate = 'postgres18'\n"
    )
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read", "check"),
        principal_capabilities=("read", "check"),
        checks_toml=checks,
    )
    return root, registry, head


@pytest.mark.skipif(not POSTGRES_AVAILABLE, reason="local PostgreSQL 18 image unavailable")
def test_postgres_check_uses_only_unix_socket_and_cleans_up(tmp_path: Path):
    script = """import json
import os
import pathlib
import socket
from urllib.parse import urlsplit

assert not pathlib.Path('/var/run/docker.sock').exists()
assert not pathlib.Path('/var/run/postgresql/.s.PGSQL.5432').exists()
socket_path = pathlib.Path('/run/vedaops-pg/.s.PGSQL.5432')
assert socket_path.exists()
sock = socket.socket(socket.AF_UNIX)
sock.connect(str(socket_path))
sock.close()
internet = socket.socket()
try:
    assert internet.connect_ex(('1.1.1.1', 53)) != 0
finally:
    internet.close()
url = os.environ['VEDAOPS_POSTGRES_URL']
assert url.startswith('postgresql://vedaops:')
assert '@%2Frun%2Fvedaops-pg:5432/vedaops' in url
secret = urlsplit(url).password
assert secret
print(json.dumps({'socket': True, 'network_denied': True, 'dsn': url, 'password': secret}))
"""
    _root, registry, head = _project_with_postgres_check(tmp_path, script=script)

    result = project_postgres_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="postgres",
    )

    assert result.outcome == "passed", result.stderr
    assert json.loads(result.stdout) == {
        "socket": True,
        "network_denied": True,
        "dsn": "[REDACTED_POSTGRES_DSN]",
        "password": "[REDACTED_SECRET]",
    }
    assert result.postgres_server_version_num // 10000 == 18
    assert result.postgres_readiness == "accepting"
    assert result.postgres_connectivity == "unix_socket"
    assert result.postgres_storage == "read_only_root_tmpfs_memory_cgroup"
    assert result.postgres_socket_storage == "host_tmpfs_container_memory_cgroup"
    assert result.postgres_cleanup == "removed"
    assert result.cleanup == "removed"
    assert result.uncertain_effects is False
    assert not list(
        Path("/dev/shm").glob(f"vedaops-pg-socket-{result.operation_id[:12]}-*")
    )
    assert result.postgres_image == POSTGRES_IMAGE
    assert result.postgres_image_id.startswith("sha256:")
    assert len(result.runtime.sha256) == 64
    assert result.runtime.kind == "project_venv_sanitized"
    serialized = result.model_dump_json()
    assert "POSTGRES_PASSWORD" not in serialized
    assert "VEDAOPS_POSTGRES_URL" not in serialized
    assert "postgresql://vedaops@/vedaops" not in serialized


@pytest.mark.skipif(not POSTGRES_AVAILABLE, reason="local PostgreSQL 18 image unavailable")
def test_postgres_container_is_removed_after_check_failure(tmp_path: Path):
    _root, registry, head = _project_with_postgres_check(
        tmp_path,
        script="raise SystemExit(7)\n",
    )

    result = project_postgres_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="postgres",
    )

    assert result.outcome == "failed"
    assert result.exit_code == 7
    assert result.postgres_cleanup == "removed"
    assert result.cleanup == "removed"


@pytest.mark.skipif(not POSTGRES_AVAILABLE, reason="local PostgreSQL 18 image unavailable")
def test_postgres_container_is_removed_after_timeout(tmp_path: Path):
    _root, registry, head = _project_with_postgres_check(
        tmp_path,
        script="import time; time.sleep(5)\n",
        timeout_seconds=5,
    )

    result = project_postgres_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="postgres",
        timeout_seconds=1,
    )

    assert result.outcome == "timed_out"
    assert result.postgres_cleanup == "removed"
    assert result.cleanup == "removed"


@pytest.mark.skipif(not POSTGRES_AVAILABLE, reason="local PostgreSQL 18 image unavailable")
def test_postgres_cleanup_failure_returns_structured_uncertainty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _root, registry, head = _project_with_postgres_check(
        tmp_path,
        script="print('done')\n",
    )
    original_remove = postgres_module._remove_container

    def remove_then_fail(docker: Path, name: str) -> bool:
        assert original_remove(docker, name) is True
        raise PolicyError("TEST_CLEANUP_FAILURE", "simulated post-removal verification failure")

    monkeypatch.setattr(postgres_module, "_remove_container", remove_then_fail)
    result = project_postgres_check_run(
        registry,
        principal_id="test-agent",
        project_id="example",
        expected_git_head=head,
        check_id="postgres",
    )

    assert result.outcome == "passed"
    assert result.postgres_cleanup == "uncertain"
    assert result.uncertain_effects is True
    assert any(
        item.code == "VEDAOPS_POSTGRES_CLEANUP_UNCERTAIN" for item in result.limitations
    )


def test_postgres_start_contract_bounds_server_writable_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[tuple[str, ...]] = []
    image_id = "sha256:" + "a" * 64
    socket_dir = tmp_path / "socket"
    socket_dir.mkdir()
    env_file = tmp_path / "postgres.env"
    env_file.write_text("POSTGRES_USER=vedaops\n")

    def fake_docker(
        docker: Path,
        *args: str,
        timeout_seconds: int = 10,
    ) -> subprocess.CompletedProcess[str]:
        del docker, timeout_seconds
        calls.append(args)
        if args[0] == "run":
            return subprocess.CompletedProcess(args, 0, "container\n", "")
        if args[0] == "inspect":
            expected = (
                f"none|{postgres_module.POSTGRES_IMAGE}|{image_id}|"
                f"{postgres_module.POSTGRES_CONTAINER_USER}|true|"
                f"{postgres_module.POSTGRES_CONTAINER_MEMORY_BYTES}|"
                f"{postgres_module.POSTGRES_CONTAINER_MEMORY_BYTES}|"
                f"{postgres_module.POSTGRES_CONTAINER_PIDS}\n"
            )
            return subprocess.CompletedProcess(args, 0, expected, "")
        raise AssertionError(args)

    monkeypatch.setattr(postgres_module, "_docker", fake_docker)
    postgres_module._start_postgres(
        DOCKER,
        name="bounded-postgres",
        socket_dir=socket_dir,
        env_file=env_file,
        image_id=image_id,
        operation_id="0123456789abcdef0123456789abcdef",
    )

    run = calls[0]
    assert "--read-only" in run
    assert "no-new-privileges:true" in run
    assert run[run.index("--user") + 1] == postgres_module.POSTGRES_CONTAINER_USER
    assert run[run.index("--memory") + 1] == postgres_module.POSTGRES_CONTAINER_MEMORY
    assert run[run.index("--memory-swap") + 1] == postgres_module.POSTGRES_CONTAINER_SWAP
    assert run[run.index("--pids-limit") + 1] == postgres_module.POSTGRES_CONTAINER_PIDS
    tmpfs_specs = [run[index + 1] for index, item in enumerate(run) if item == "--tmpfs"]
    assert any(
        spec.startswith("/var/lib/postgresql:") and "size=512m" in spec
        for spec in tmpfs_specs
    )
    assert any(spec.startswith("/tmp:") and "size=64m" in spec for spec in tmpfs_specs)
    assert any(spec.startswith("/var/tmp:") and "size=64m" in spec for spec in tmpfs_specs)
    assert any(
        item == f"type=bind,src={socket_dir},dst={postgres_module.POSTGRES_SOCKET_CONTAINER}"
        for item in run
    )


def test_ordinary_check_runner_refuses_postgres_bound_check(tmp_path: Path):
    _root, registry, head = _project_with_postgres_check(
        tmp_path,
        script="print('not reached')\n",
    )

    with pytest.raises(PolicyError, match="VEDAOPS_CHECK_PROFILE_MISMATCH"):
        project_check_run(
            registry,
            principal_id="test-agent",
            project_id="example",
            expected_git_head=head,
            check_id="postgres",
        )
