"""Restricted execution of operator-approved project checks.

MCP-02 executes only commit-derived snapshots and only operator-defined argv.
Project code runs inside a Linux bubblewrap namespace with no operator home,
controller configuration, other projects, Docker socket, SSH agent, or network.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import suppress
from functools import wraps
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vedaops_mcp.authority import Limitation, RegisteredCheck, get_authorized_check
from vedaops_mcp.errors import AuthorityError, PolicyError
from vedaops_mcp.operations import start_operation
from vedaops_mcp.policy import (
    normalize_relative,
    protected_reason,
    read_git_blobs_batch,
    run_git_bytes,
    run_git_text,
)
from vedaops_mcp.runtime import RUNTIME_VENV_RELATIVE, RuntimeIdentity, capture_project_runtime

RUNNER_PROFILE = "linux-bwrap-systemd-v2"
BWRAP_PATH = Path("/usr/bin/bwrap")
PRLIMIT_PATH = Path("/usr/bin/prlimit")
SYSTEMD_RUN_PATH = Path("/usr/bin/systemd-run")
MAX_CONCURRENT_CHECKS = 2
MAX_WORKER_TASKS = 128
_CHECK_ADMISSION = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_TREE_LIST_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_FILES = 5000
MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_RETURN_BYTES = 128 * 1024
MAX_FILE_SIZE_LIMIT = 32 * 1024 * 1024
PROCESS_GRACE_SECONDS = 2.0
SUBJECT_CAPTURE_TIMEOUT_SECONDS = 30


class CheckRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    principal_id: str
    project_id: str
    workspace_id: str
    requested_git_head: str
    captured_commit: str
    captured_tree: str
    subject_kind: str
    captured_input_sha256: str
    excluded_count: int
    exclusions: list[str]
    check_id: str
    check_definition_sha256: str
    runner_profile: str
    runner_sha256: str
    limiter_sha256: str
    aggregate_limiter_sha256: str
    outcome: str
    exit_code: int | None
    duration_ms: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    cleanup: str
    limitations: list[Limitation]
    uncertain_effects: bool
    runtime: RuntimeIdentity | None = None


def admitted_check(function):
    """Bound concurrent hostile check workloads across ordinary and PostgreSQL runners."""
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not _CHECK_ADMISSION.acquire(blocking=False):
            raise PolicyError(
                "VEDAOPS_CHECK_CAPACITY_REACHED",
                "the bounded concurrent-check limit is already in use",
            )
        try:
            return function(*args, **kwargs)
        finally:
            _CHECK_ADMISSION.release()

    return wrapper


@admitted_check
def project_check_run(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    check_id: str,
    timeout_seconds: int | None = None,
) -> CheckRunResult:
    """Run one operator-approved check against one bounded commit-derived snapshot."""
    project, check = get_authorized_check(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        check_id=check_id,
    )
    if check.substrate is not None:
        raise PolicyError(
            "VEDAOPS_CHECK_PROFILE_MISMATCH",
            "this check requires its configured substrate-specific runner",
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
        kind="check_run",
        project_id=project.id,
        expected_git_head=expected,
    )
    operation_id = journal.operation_id
    root: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    cleanup = "removed"
    limitations: list[Limitation] = []
    uncertain_effects = False
    runtime_identity: RuntimeIdentity | None = None
    failure: Exception | None = None
    try:
        root = Path(tempfile.mkdtemp(prefix="vedaops-check-"))
        snapshot_dir = root / "snapshot"
        runtime_dir = root / "runtime-venv"
        uv_copy = root / "uv"
        snapshot_dir.mkdir(mode=0o700)
        captured_digest, excluded_count, exclusions = _materialize_snapshot(
            project.root,
            tree_listing,
            snapshot_dir,
        )
        extra_dirs: list[str] = []
        extra_ro_binds: list[tuple[Path, str]] = []
        extra_env: dict[str, str] = {}
        if check.runtime == "project_venv":
            if (snapshot_dir / RUNTIME_VENV_RELATIVE).exists():
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_CONFLICT",
                    "the committed subject already contains the reserved .venv runtime path",
                )
            runtime_identity = capture_project_runtime(project.root, runtime_dir, uv_copy)
            (snapshot_dir / RUNTIME_VENV_RELATIVE).mkdir(mode=0o700)
            extra_dirs = ["/runtime", "/runtime/bin"]
            extra_ro_binds = [
                (runtime_dir, "/workspace/.venv"),
                (uv_copy, "/runtime/bin/uv"),
            ]
            extra_env = {"PATH": "/runtime/bin:/workspace/.venv/bin:/usr/bin:/bin"}
        argv = _sandbox_argv(
            bwrap=bwrap,
            prlimit=prlimit,
            systemd_run=systemd_run,
            snapshot_dir=snapshot_dir,
            check=check,
            timeout_seconds=effective_timeout,
            extra_dirs=extra_dirs,
            extra_ro_binds=extra_ro_binds,
            extra_env=extra_env,
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
                    "restricted check runner could not start",
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
        if root is not None:
            try:
                shutil.rmtree(root)
            except OSError:
                cleanup = "uncertain"
                uncertain_effects = True
                limitations.append(
                    Limitation(
                        code="VEDAOPS_CHECK_CLEANUP_UNCERTAIN",
                        detail="disposable check workspace could not be fully removed",
                    )
                )

    if failure is not None:
        if uncertain_effects or cleanup != "removed":
            journal.terminal("uncertain", detail=str(failure))
            raise PolicyError(
                "VEDAOPS_CHECK_EFFECT_UNCERTAIN",
                f"operation {operation_id} failed with uncertain cleanup/effects; "
                "inspect before retrying",
            ) from failure
        journal.terminal("failed", detail=str(failure))
        raise failure
    journal.terminal("uncertain" if uncertain_effects else "succeeded")

    return CheckRunResult(
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
        runner_profile=RUNNER_PROFILE,
        runner_sha256=_sha256_file(bwrap),
        limiter_sha256=_sha256_file(prlimit),
        aggregate_limiter_sha256=_sha256_file(systemd_run),
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
        runtime=runtime_identity,
    )


def _validated_commit(root: Path, value: str) -> str:
    if not isinstance(value, str) or COMMIT_PATTERN.fullmatch(value) is None:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            "expected_git_head must be a full lowercase hexadecimal Git commit object ID",
        )
    try:
        actual = run_git_text(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    except PolicyError as exc:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            "expected_git_head must name an existing commit object",
        ) from exc
    if actual != value:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            "expected_git_head must identify a commit object directly",
        )
    return actual


def _effective_timeout(check: RegisteredCheck, requested: int | None) -> int:
    if requested is None:
        return check.timeout_seconds
    if (
        isinstance(requested, bool)
        or not isinstance(requested, int)
        or requested < 1
        or requested > check.timeout_seconds
    ):
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"timeout_seconds must be between 1 and the approved limit {check.timeout_seconds}",
        )
    return requested


def _required_executable(path: Path, label: str) -> Path:
    try:
        info = path.stat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNNER_UNAVAILABLE",
            f"{label} is unavailable",
        ) from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise PolicyError(
            "VEDAOPS_CHECK_RUNNER_UNAVAILABLE",
            f"{label} is unavailable",
        )
    return path


def _check_definition_sha256(check: RegisteredCheck) -> str:
    payload = json.dumps(check.model_dump(), separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _tree_entries(tree_listing: bytes) -> list[tuple[str, str, str, bytes]]:
    entries: list[tuple[str, str, str, bytes]] = []
    try:
        records = tree_listing.split(b"\x00")
        for record in records:
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            entries.append((mode, object_type, object_id, raw_path))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_SUBJECT_UNAVAILABLE",
            "Git tree listing was malformed",
        ) from exc
    return entries


def _materialize_snapshot(
    root: Path,
    tree_listing: bytes,
    destination: Path,
) -> tuple[str, int, list[str]]:
    digest = hashlib.sha256()
    total_bytes = 0
    excluded = 0
    exclusion_kinds: set[str] = {"working_tree_and_untracked_changes"}
    materialized: list[tuple[str, str, str]] = []
    for mode, object_type, object_id, raw_path in _tree_entries(tree_listing):
        if len(materialized) >= MAX_SNAPSHOT_FILES:
            raise PolicyError(
                "VEDAOPS_CHECK_SUBJECT_TOO_LARGE",
                f"check snapshot exceeds {MAX_SNAPSHOT_FILES} files",
            )
        try:
            relative = normalize_relative(raw_path.decode("utf-8"))
        except (UnicodeDecodeError, PolicyError):
            excluded += 1
            exclusion_kinds.add("unsupported_paths")
            continue
        if protected_reason(relative) is not None:
            excluded += 1
            exclusion_kinds.add("protected_paths")
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            excluded += 1
            if mode == "120000":
                exclusion_kinds.add("symlinks")
            elif mode == "160000":
                exclusion_kinds.add("gitlinks")
            else:
                exclusion_kinds.add("unsupported_git_entries")
            continue
        materialized.append((relative, mode, object_id))

    try:
        blobs = read_git_blobs_batch(
            root,
            [object_id for _relative, _mode, object_id in materialized],
            max_blob_bytes=MAX_SNAPSHOT_FILE_BYTES,
            max_batch_bytes=MAX_SNAPSHOT_TOTAL_BYTES,
            timeout_seconds=SUBJECT_CAPTURE_TIMEOUT_SECONDS,
        )
    except PolicyError as exc:
        if exc.code == "VEDAOPS_GIT_OUTPUT_TOO_LARGE":
            raise PolicyError("VEDAOPS_CHECK_SUBJECT_TOO_LARGE", exc.detail) from exc
        raise

    for relative, mode, object_id in materialized:
        content = blobs[object_id]
        total_bytes += len(content)
        if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES:
            raise PolicyError(
                "VEDAOPS_CHECK_SUBJECT_TOO_LARGE",
                "check snapshot exceeds the total materialized byte bound",
            )
        target = destination.joinpath(*Path(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o755 if mode == "100755" else 0o644)
        path_bytes = relative.encode("utf-8")
        mode_bytes = mode.encode("ascii")
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(len(mode_bytes).to_bytes(1, "big"))
        digest.update(mode_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest(), excluded, sorted(exclusion_kinds)


def _sandbox_argv(
    *,
    bwrap: Path,
    prlimit: Path,
    systemd_run: Path,
    snapshot_dir: Path,
    check: RegisteredCheck,
    timeout_seconds: int,
    extra_dirs: list[str] | None = None,
    extra_ro_binds: list[tuple[Path, str]] | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    memory_bytes = check.memory_mb * 1024 * 1024
    extra_dirs = [] if extra_dirs is None else extra_dirs
    extra_ro_binds = [] if extra_ro_binds is None else extra_ro_binds
    extra_env = {} if extra_env is None else extra_env
    command = [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--hostname",
        "vedaops-check",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
    ]
    if Path("/lib64").exists():
        command.extend(["--ro-bind", "/lib64", "/lib64"])
    command.extend(
        [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/home",
            "--dir",
            "/home/worker",
            "--dir",
            "/workspace",
            "--symlink",
            "usr/bin",
            "/bin",
            "--bind",
            str(snapshot_dir),
            "/workspace",
        ]
    )
    for directory in extra_dirs:
        command.extend(["--dir", directory])
    for source, target in extra_ro_binds:
        command.extend(["--ro-bind", str(source), target])
    command.extend(
        [
            "--chdir",
            "/workspace",
            "--clearenv",
            "--setenv",
            "HOME",
            "/home/worker",
            "--setenv",
            "USER",
            "worker",
            "--setenv",
            "LOGNAME",
            "worker",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
        ]
    )
    for name, value in sorted(extra_env.items()):
        command.extend(["--setenv", name, value])
    command.extend(
        [
            "--",
            str(prlimit),
            f"--as={memory_bytes}",
            "--nofile=256",
            f"--fsize={MAX_FILE_SIZE_LIMIT}",
            f"--cpu={timeout_seconds + 2}",
            "--core=0",
            "--",
            *check.argv,
        ]
    )
    return [
        str(systemd_run),
        "--user",
        "--scope",
        "--quiet",
        f"--property=MemoryMax={memory_bytes}",
        "--property=MemorySwapMax=0",
        f"--property=TasksMax={MAX_WORKER_TASKS}",
        "--",
        *command,
    ]


def _terminate_process(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return process.poll() is not None
    try:
        process.wait(timeout=PROCESS_GRACE_SECONDS)
        return True
    except subprocess.TimeoutExpired:
        pass
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=PROCESS_GRACE_SECONDS)
        return True
    except subprocess.TimeoutExpired:
        return process.poll() is not None


def _append_termination_limitation(limitations: list[Limitation]) -> None:
    if any(item.code == "VEDAOPS_CHECK_TERMINATION_UNCERTAIN" for item in limitations):
        return
    limitations.append(
        Limitation(
            code="VEDAOPS_CHECK_TERMINATION_UNCERTAIN",
            detail="the sandbox process could not be conclusively reaped after termination",
        )
    )


def _read_output(handle) -> tuple[str, bool]:
    handle.seek(0)
    raw = handle.read(MAX_CAPTURE_BYTES + 1)
    truncated = len(raw) > MAX_RETURN_BYTES
    text = raw[:MAX_RETURN_BYTES].decode("utf-8", errors="replace")
    return text, truncated


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
