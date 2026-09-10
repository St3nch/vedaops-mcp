"""Disposable PostgreSQL 18 substrate for operator-approved project checks.

MCP-03 keeps Docker authority in the controller. Project code receives only a
temporary PostgreSQL Unix-domain socket mounted into the existing restricted
Bubblewrap worker; it receives neither Docker control nor network access.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from pydantic import ConfigDict

from vedaops_mcp.authority import Limitation, get_authorized_check
from vedaops_mcp.checks import (
    BWRAP_PATH,
    MAX_TREE_LIST_BYTES,
    PRLIMIT_PATH,
    SYSTEMD_RUN_PATH,
    CheckRunResult,
    _append_termination_limitation,
    _check_definition_sha256,
    _effective_timeout,
    _materialize_snapshot,
    _read_output,
    _required_executable,
    _sandbox_argv,
    _sha256_file,
    _terminate_process,
    _validated_commit,
    admitted_check,
)
from vedaops_mcp.errors import AuthorityError, PolicyError
from vedaops_mcp.operations import start_operation
from vedaops_mcp.policy import run_git_bytes, run_git_text
from vedaops_mcp.runtime import RUNTIME_VENV_RELATIVE, RuntimeIdentity, capture_project_runtime

DOCKER_PATH = Path("/usr/bin/docker")
POSTGRES_IMAGE = "postgres:18-alpine"
POSTGRES_USER = "vedaops"
POSTGRES_DB = "vedaops"
POSTGRES_SOCKET_CONTAINER = "/var/run/postgresql"
POSTGRES_SOCKET_SANDBOX = "/run/vedaops-pg"
POSTGRES_SOCKET_URI_HOST = "%2Frun%2Fvedaops-pg"
POSTGRES_PORT = 5432
POSTGRES_START_TIMEOUT_SECONDS = 60
POSTGRES_CONTAINER_MEMORY = "512m"
POSTGRES_CONTAINER_PIDS = "128"
class PostgresCheckRunResult(CheckRunResult):
    model_config = ConfigDict(extra="forbid")

    substrate_kind: str
    postgres_image: str
    postgres_image_id: str
    postgres_server_version_num: int
    postgres_readiness: str
    postgres_connectivity: str
    postgres_cleanup: str
    runtime: RuntimeIdentity


@admitted_check
def project_postgres_check_run(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    check_id: str,
    timeout_seconds: int | None = None,
) -> PostgresCheckRunResult:
    """Run one approved check against one disposable PostgreSQL 18 substrate."""
    project, check = get_authorized_check(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        check_id=check_id,
    )
    if check.substrate != "postgres18":
        raise PolicyError(
            "VEDAOPS_CHECK_PROFILE_MISMATCH",
            "this check is not approved for the PostgreSQL 18 substrate",
        )
    if check.runtime != "project_venv":
        raise PolicyError(
            "VEDAOPS_CHECK_PROFILE_MISMATCH",
            "PostgreSQL checks currently require the project_venv runtime",
        )

    expected = _validated_commit(project.root, expected_git_head)
    current = run_git_text(project.root, "rev-parse", "HEAD")
    if current != expected:
        raise AuthorityError(
            "VEDAOPS_GIT_PRECONDITION_FAILED",
            "expected_git_head does not match the current project HEAD",
        )
    effective_timeout = _effective_timeout(check, timeout_seconds)
    bwrap = _required_executable(BWRAP_PATH, "bubblewrap")
    prlimit = _required_executable(PRLIMIT_PATH, "prlimit")
    systemd_run = _required_executable(SYSTEMD_RUN_PATH, "systemd-run")
    docker = _required_executable(DOCKER_PATH, "Docker")
    image_id = _local_image_id(docker)

    tree_listing = run_git_bytes(
        project.root,
        "ls-tree",
        "-rz",
        "--full-tree",
        expected,
        limit_bytes=MAX_TREE_LIST_BYTES,
        timeout_seconds=30,
    )
    tree = run_git_text(project.root, "rev-parse", f"{expected}^{{tree}}")
    check_digest = _check_definition_sha256(check)
    journal = start_operation(
        registry_path,
        kind="postgres_check_run",
        project_id=project.id,
        expected_git_head=expected,
        principal_id=project.principal_id,
        workspace_id=project.workspace_id,
        project_root=project.root,
        subject={
            "check_id": check.id,
            "check_definition_sha256": check_digest,
            "captured_commit": expected,
            "captured_tree": tree,
        },
    )
    operation_id = journal.operation_id
    root: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    container_name: str | None = None
    cleanup = "removed"
    postgres_cleanup = "not_started"
    limitations: list[Limitation] = []
    uncertain_effects = False
    outcome = "failed"
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    stdout_truncated = False
    stderr_truncated = False
    duration_ms = 0
    server_version_num = 0
    readiness = "unavailable"
    runtime_identity: RuntimeIdentity | None = None
    failure: Exception | None = None

    try:
        root = Path(tempfile.gettempdir()) / f"vedaops-pg-check-{operation_id}"
        journal.update(disposable_root=str(root))
        root.mkdir(mode=0o700)
        snapshot_dir = root / "snapshot"
        runtime_dir = root / "runtime-venv"
        socket_dir = root / "socket"
        uv_copy = root / "uv"
        env_file = root / "postgres.env"
        snapshot_dir.mkdir(mode=0o700)
        socket_dir.mkdir(mode=0o777)
        socket_dir.chmod(0o777)
        captured_digest, excluded_count, exclusions = _materialize_snapshot(
            project.root,
            tree_listing,
            snapshot_dir,
        )
        if (snapshot_dir / RUNTIME_VENV_RELATIVE).exists():
            raise PolicyError(
                "VEDAOPS_CHECK_RUNTIME_CONFLICT",
                "the committed subject already contains the reserved .venv runtime path",
            )
        runtime_identity = capture_project_runtime(project.root, runtime_dir, uv_copy)
        (snapshot_dir / RUNTIME_VENV_RELATIVE).mkdir(mode=0o700)

        password = secrets.token_hex(24)
        _write_private_env_file(env_file, password)
        container_name = f"vedaops-pg18-{os.getpid()}-{operation_id[:12]}"
        journal.update(postgres_container=container_name)
        _start_postgres(
            docker,
            name=container_name,
            socket_dir=socket_dir,
            env_file=env_file,
            image_id=image_id,
            operation_id=operation_id,
        )
        postgres_cleanup = "pending"
        readiness, server_version_num = _wait_for_postgres(docker, container_name)

        database_url = (
            f"postgresql://{POSTGRES_USER}:{password}@{POSTGRES_SOCKET_URI_HOST}:"
            f"{POSTGRES_PORT}/{POSTGRES_DB}"
        )
        argv = _sandbox_argv(
            bwrap=bwrap,
            prlimit=prlimit,
            systemd_run=systemd_run,
            snapshot_dir=snapshot_dir,
            check=check,
            timeout_seconds=effective_timeout,
            extra_dirs=["/runtime", "/runtime/bin", "/run", POSTGRES_SOCKET_SANDBOX],
            extra_ro_binds=[
                (uv_copy, "/runtime/bin/uv"),
                (socket_dir, POSTGRES_SOCKET_SANDBOX),
            ],
            extra_env={
                "PATH": "/runtime/bin:/workspace/.venv/bin:/usr/bin:/bin",
                "VEDAOPS_POSTGRES_URL": database_url,
            },
            runtime_source=runtime_dir,
        )
        started = time.monotonic()
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                process = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd="/",
                    env={
                        "PATH": "/usr/bin:/bin",
                        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
                    },
                    start_new_session=True,
                )
            except OSError as exc:
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNNER_UNAVAILABLE",
                    "restricted PostgreSQL check worker could not start",
                ) from exc
            timed_out = False
            try:
                exit_code = process.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                if not _terminate_process(process):
                    uncertain_effects = True
                    _append_termination_limitation(limitations)
                exit_code = process.returncode
            duration_ms = max(0, int((time.monotonic() - started) * 1000))
            stdout, stdout_truncated = _read_output(stdout_file)
            stderr, stderr_truncated = _read_output(stderr_file)
            stdout = _scrub_postgres_output(
                stdout,
                database_url=database_url,
                password=password,
            )
            stderr = _scrub_postgres_output(
                stderr,
                database_url=database_url,
                password=password,
            )

        if timed_out:
            outcome = "timed_out"
        elif exit_code == 0:
            outcome = "passed"
        else:
            outcome = "failed"
    except Exception as exc:
        failure = exc
    finally:
        if process is not None and process.poll() is None and not _terminate_process(process):
            uncertain_effects = True
            _append_termination_limitation(limitations)
        if container_name is not None:
            try:
                removed = _remove_container(docker, container_name)
            except Exception:
                removed = False
            postgres_cleanup = "removed" if removed else "uncertain"
            if postgres_cleanup != "removed":
                uncertain_effects = True
                limitations.append(
                    Limitation(
                        code="VEDAOPS_POSTGRES_CLEANUP_UNCERTAIN",
                        detail="disposable PostgreSQL container removal could not be verified",
                    )
                )
        if root is not None and root.exists():
            try:
                shutil.rmtree(root)
            except OSError:
                cleanup = "uncertain"
                uncertain_effects = True
                limitations.append(
                    Limitation(
                        code="VEDAOPS_CHECK_CLEANUP_UNCERTAIN",
                        detail="disposable PostgreSQL check workspace could not be fully removed",
                    )
                )

    if failure is not None:
        if uncertain_effects or cleanup != "removed" or postgres_cleanup == "uncertain":
            journal.terminal("uncertain", detail=str(failure))
            raise PolicyError(
                "VEDAOPS_CHECK_EFFECT_UNCERTAIN",
                f"operation {operation_id} failed with uncertain cleanup/effects; "
                "inspect before retrying",
            ) from failure
        journal.terminal("failed", detail=str(failure))
        raise failure
    if runtime_identity is None:
        journal.terminal("uncertain", detail="runtime identity unavailable after check execution")
        raise PolicyError(
            "VEDAOPS_CHECK_EFFECT_UNCERTAIN",
            f"operation {operation_id} completed without runtime identity; inspect before retrying",
        )
    journal.terminal("uncertain" if uncertain_effects else "succeeded")
    return PostgresCheckRunResult(
        operation_id=operation_id,
        principal_id=project.principal_id,
        project_id=project.id,
        workspace_id=project.workspace_id,
        requested_git_head=expected,
        captured_commit=expected,
        captured_tree=tree,
        subject_kind=(
            "commit_snapshot_with_exclusions" if excluded_count else "exact_commit_snapshot"
        ),
        captured_input_sha256=captured_digest,
        excluded_count=excluded_count,
        exclusions=exclusions,
        check_id=check.id,
        check_definition_sha256=check_digest,
        runner_profile="linux-bwrap-systemd-tmpfs-postgres18-v3",
        runner_sha256=_sha256_file(bwrap),
        limiter_sha256=_sha256_file(prlimit),
        aggregate_limiter_sha256=_sha256_file(systemd_run),
        aggregate_memory_limit_bytes=check.memory_mb * 1024 * 1024,
        scratch_storage="tmpfs_memory_cgroup",
        outcome=outcome,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        cleanup=cleanup,
        limitations=limitations,
        uncertain_effects=uncertain_effects,
        substrate_kind="postgres18",
        postgres_image=POSTGRES_IMAGE,
        postgres_image_id=image_id,
        postgres_server_version_num=server_version_num,
        postgres_readiness=readiness,
        postgres_connectivity="unix_socket",
        postgres_cleanup=postgres_cleanup,
        runtime=runtime_identity,
    )


def _local_image_id(docker: Path) -> str:
    result = _docker(docker, "image", "inspect", POSTGRES_IMAGE, "--format", "{{.Id}}")
    image_id = result.stdout.strip()
    if result.returncode != 0 or not image_id.startswith("sha256:") or len(image_id) != 71:
        raise PolicyError(
            "VEDAOPS_POSTGRES_IMAGE_UNAVAILABLE",
            "the fixed PostgreSQL 18 image is not already available locally",
        )
    return image_id


def _scrub_postgres_output(text: str, *, database_url: str, password: str) -> str:
    return text.replace(database_url, "[REDACTED_POSTGRES_DSN]").replace(
        password,
        "[REDACTED_SECRET]",
    )


def _write_private_env_file(path: Path, password: str) -> None:
    path.write_text(
        f"POSTGRES_USER={POSTGRES_USER}\nPOSTGRES_PASSWORD={password}\nPOSTGRES_DB={POSTGRES_DB}\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _start_postgres(
    docker: Path,
    *,
    name: str,
    socket_dir: Path,
    env_file: Path,
    image_id: str,
    operation_id: str,
) -> None:
    run = _docker(
        docker,
        "run",
        "-d",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--tmpfs",
        "/var/lib/postgresql:rw,nosuid,nodev,size=512m",
        "--memory",
        POSTGRES_CONTAINER_MEMORY,
        "--pids-limit",
        POSTGRES_CONTAINER_PIDS,
        "--stop-timeout",
        "2",
        "--name",
        name,
        "--label",
        f"vedaops.mcp.operation={operation_id}",
        "--env-file",
        str(env_file),
        "--mount",
        f"type=bind,src={socket_dir},dst={POSTGRES_SOCKET_CONTAINER}",
        POSTGRES_IMAGE,
        "-c",
        "listen_addresses=",
        "-c",
        "unix_socket_permissions=0777",
        timeout_seconds=30,
    )
    if run.returncode != 0:
        raise PolicyError(
            "VEDAOPS_POSTGRES_START_FAILED",
            "PostgreSQL 18 container failed to start",
        )
    inspect = _docker(
        docker,
        "inspect",
        "--format",
        "{{.HostConfig.NetworkMode}}|{{.Config.Image}}|{{.Image}}",
        name,
    )
    expected = f"none|{POSTGRES_IMAGE}|{image_id}"
    if inspect.returncode != 0 or inspect.stdout.strip() != expected:
        raise PolicyError(
            "VEDAOPS_POSTGRES_SUBSTRATE_INVALID",
            "started PostgreSQL container does not match the fixed substrate contract",
        )


def _wait_for_postgres(docker: Path, name: str) -> tuple[str, int]:
    deadline = time.monotonic() + POSTGRES_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        pid_one = _docker(docker, "exec", name, "sh", "-c", "cat /proc/1/comm")
        if pid_one.returncode == 0 and pid_one.stdout.strip() == "postgres":
            ready = _docker(
                docker,
                "exec",
                name,
                "pg_isready",
                "-q",
                "-h",
                POSTGRES_SOCKET_CONTAINER,
                "-U",
                POSTGRES_USER,
                "-d",
                POSTGRES_DB,
            )
            if ready.returncode == 0:
                break
            if ready.returncode == 3:
                raise PolicyError(
                    "VEDAOPS_POSTGRES_READINESS_INVALID",
                    "pg_isready rejected the fixed readiness parameters",
                )
        time.sleep(0.2)
    else:
        raise PolicyError("VEDAOPS_POSTGRES_START_FAILED", "PostgreSQL 18 did not become ready")

    version = _docker(
        docker,
        "exec",
        name,
        "psql",
        "-h",
        POSTGRES_SOCKET_CONTAINER,
        "-U",
        POSTGRES_USER,
        "-d",
        POSTGRES_DB,
        "-Atqc",
        "SHOW server_version_num",
    )
    try:
        version_num = int(version.stdout.strip())
    except ValueError as exc:
        raise PolicyError(
            "VEDAOPS_POSTGRES_VERSION_INVALID",
            "PostgreSQL did not report a numeric server version",
        ) from exc
    if version.returncode != 0 or version_num // 10000 != 18:
        raise PolicyError(
            "VEDAOPS_POSTGRES_VERSION_INVALID",
            "connected PostgreSQL server is not major version 18",
        )
    return "accepting", version_num


def _remove_container(docker: Path, name: str) -> bool:
    stopped = _docker(docker, "stop", "--time", "2", name, timeout_seconds=10)
    if stopped.returncode != 0:
        _docker(docker, "rm", "-f", name, timeout_seconds=15)
    remaining = _docker(
        docker,
        "ps",
        "-a",
        "--filter",
        f"name=^/{name}$",
        "--format",
        "{{.Names}}",
        timeout_seconds=10,
    )
    return remaining.returncode == 0 and not remaining.stdout.strip()


def _docker(
    docker: Path,
    *args: str,
    timeout_seconds: int = 10,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [str(docker), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(
            "VEDAOPS_POSTGRES_SUBSTRATE_UNAVAILABLE",
            "Docker operation failed",
        ) from exc
