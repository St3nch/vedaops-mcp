"""Restricted execution of operator-approved project checks.

MCP-02 executes only exact commit snapshots and only operator-defined argv.
Project code runs inside a Linux bubblewrap namespace with no operator home,
controller configuration, other projects, Docker socket, SSH agent, or network.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
from contextlib import suppress
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vedaops_mcp.authority import Limitation, RegisteredCheck, get_authorized_check
from vedaops_mcp.errors import AuthorityError, PolicyError
from vedaops_mcp.policy import normalize_relative, protected_reason, run_git_bytes, run_git_text

RUNNER_PROFILE = "linux-bwrap-v1"
BWRAP_PATH = Path("/usr/bin/bwrap")
PRLIMIT_PATH = Path("/usr/bin/prlimit")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SNAPSHOT_FILES = 5000
MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_RETURN_BYTES = 128 * 1024
MAX_FILE_SIZE_LIMIT = 32 * 1024 * 1024
MAX_CHECK_PROCESSES = 8
PROCESS_GRACE_SECONDS = 2.0


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


def project_check_run(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    expected_git_head: str,
    check_id: str,
    timeout_seconds: int | None = None,
) -> CheckRunResult:
    """Run one operator-approved check against one exact disposable commit snapshot."""
    project, check = get_authorized_check(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        check_id=check_id,
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

    archive = run_git_bytes(
        project.root,
        "archive",
        "--format=tar",
        expected,
        limit_bytes=MAX_ARCHIVE_BYTES,
        timeout_seconds=30,
    )
    tree = run_git_text(project.root, "rev-parse", f"{expected}^{{tree}}")
    check_digest = _check_definition_sha256(check)
    operation_id = uuid.uuid4().hex
    snapshot_dir = Path(tempfile.mkdtemp(prefix="vedaops-check-"))
    process: subprocess.Popen[bytes] | None = None
    cleanup = "removed"
    limitations: list[Limitation] = []
    uncertain_effects = False
    try:
        captured_digest, excluded_count, exclusions = _materialize_snapshot(archive, snapshot_dir)
        argv = _sandbox_argv(
            bwrap=bwrap,
            prlimit=prlimit,
            snapshot_dir=snapshot_dir,
            check=check,
            timeout_seconds=effective_timeout,
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
                    env={"PATH": "/usr/bin:/bin"},
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
                _terminate_process(process)
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
    finally:
        if process is not None and process.poll() is None:
            _terminate_process(process)
        try:
            shutil.rmtree(snapshot_dir)
        except OSError:
            cleanup = "uncertain"
            uncertain_effects = True
            limitations.append(
                Limitation(
                    code="VEDAOPS_CHECK_CLEANUP_UNCERTAIN",
                    detail="disposable check workspace could not be fully removed",
                )
            )

    return CheckRunResult(
        operation_id=operation_id,
        principal_id=project.principal_id,
        project_id=project.id,
        workspace_id=project.workspace_id,
        requested_git_head=expected,
        captured_commit=expected,
        captured_tree=tree,
        subject_kind="exact_commit_snapshot",
        captured_input_sha256=captured_digest,
        excluded_count=excluded_count,
        exclusions=exclusions,
        check_id=check.id,
        check_definition_sha256=check_digest,
        runner_profile=RUNNER_PROFILE,
        runner_sha256=_sha256_file(bwrap),
        limiter_sha256=_sha256_file(prlimit),
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


def _open_archive(archive: bytes) -> tarfile.TarFile:
    try:
        return tarfile.open(fileobj=io.BytesIO(archive), mode="r:")
    except tarfile.TarError as exc:
        raise PolicyError("VEDAOPS_CHECK_SUBJECT_UNAVAILABLE", "Git archive was invalid") from exc


def _materialize_snapshot(archive: bytes, destination: Path) -> tuple[str, int, list[str]]:
    digest = hashlib.sha256()
    files = 0
    total_bytes = 0
    excluded = 0
    exclusion_kinds: set[str] = {"working_tree_and_untracked_changes"}
    with _open_archive(archive) as opened:
        for member in opened:
            if member.isdir():
                continue
            if files >= MAX_SNAPSHOT_FILES:
                raise PolicyError(
                    "VEDAOPS_CHECK_SUBJECT_TOO_LARGE",
                    f"check snapshot exceeds {MAX_SNAPSHOT_FILES} files",
                )
            try:
                relative = normalize_relative(member.name)
            except PolicyError:
                excluded += 1
                exclusion_kinds.add("unsupported_paths")
                continue
            if protected_reason(relative) is not None:
                excluded += 1
                exclusion_kinds.add("protected_paths")
                continue
            if not member.isfile():
                excluded += 1
                exclusion_kinds.add("symlinks_or_special_entries")
                continue
            if member.size > MAX_SNAPSHOT_FILE_BYTES:
                raise PolicyError(
                    "VEDAOPS_CHECK_SUBJECT_TOO_LARGE",
                    f"check snapshot file {relative!r} exceeds the per-file bound",
                )
            total_bytes += member.size
            if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES:
                raise PolicyError(
                    "VEDAOPS_CHECK_SUBJECT_TOO_LARGE",
                    "check snapshot exceeds the total materialized byte bound",
                )
            source = opened.extractfile(member)
            if source is None:
                raise PolicyError(
                    "VEDAOPS_CHECK_SUBJECT_UNAVAILABLE",
                    f"check snapshot file {relative!r} could not be read",
                )
            content = source.read(MAX_SNAPSHOT_FILE_BYTES + 1)
            if len(content) != member.size:
                raise PolicyError(
                    "VEDAOPS_CHECK_SUBJECT_UNAVAILABLE",
                    f"check snapshot file {relative!r} changed during capture",
                )
            target = destination.joinpath(*Path(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
            path_bytes = relative.encode("utf-8")
            digest.update(len(path_bytes).to_bytes(4, "big"))
            digest.update(path_bytes)
            digest.update((1 if member.mode & 0o111 else 0).to_bytes(1, "big"))
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
            files += 1
    return digest.hexdigest(), excluded, sorted(exclusion_kinds)


def _sandbox_argv(
    *,
    bwrap: Path,
    prlimit: Path,
    snapshot_dir: Path,
    check: RegisteredCheck,
    timeout_seconds: int,
) -> list[str]:
    memory_bytes = check.memory_mb * 1024 * 1024
    command = [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
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
            "--",
            str(prlimit),
            f"--as={memory_bytes}",
            f"--nproc={MAX_CHECK_PROCESSES}",
            "--nofile=256",
            f"--fsize={MAX_FILE_SIZE_LIMIT}",
            f"--cpu={timeout_seconds + 2}",
            "--core=0",
            "--",
            *check.argv,
        ]
    )
    return command


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=PROCESS_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=PROCESS_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        return


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
