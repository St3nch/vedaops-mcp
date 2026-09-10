"""Sanitized, bounded dependency-runtime capture for restricted project checks."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vedaops_mcp.errors import PolicyError

RUNTIME_VENV_RELATIVE = Path(".venv")
MAX_RUNTIME_FILES = 20_000
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
RUNTIME_COPY_TIMEOUT_SECONDS = 30
TRUSTED_SYSTEM_PYTHON = Path("/usr/bin/python3")
BWRAP_PATH = Path("/usr/bin/bwrap")
RUNTIME_HELPER_PATH = Path(__file__).with_name("runtime_helper.py")


class RuntimeIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    sha256: str
    files: int
    bytes: int
    uv_sha256: str
    python_sha256: str


def capture_project_runtime(
    project_root: Path,
    destination: Path,
    uv_copy: Path,
) -> RuntimeIdentity:
    """Capture installed project packages without executing project-controlled Python."""
    source = project_venv(project_root)
    uv_source = trusted_uv_executable(project_root)
    copy_runtime_venv(source, destination, project_root=project_root)
    shutil.copyfile(uv_source, uv_copy)
    uv_copy.chmod(0o755)
    return runtime_identity(destination, uv_copy)


def trusted_uv_executable(project_root: Path) -> Path:
    found = shutil.which("uv")
    if not found:
        raise PolicyError("VEDAOPS_CHECK_RUNTIME_UNAVAILABLE", "uv is unavailable")
    path = Path(found).resolve()
    try:
        info = path.stat()
    except OSError as exc:
        raise PolicyError("VEDAOPS_CHECK_RUNTIME_UNAVAILABLE", "uv is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise PolicyError("VEDAOPS_CHECK_RUNTIME_UNAVAILABLE", "uv is unavailable")
    root = project_root.resolve()
    if path == root or root in path.parents:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "uv must come from the trusted controller environment, not the managed project",
        )
    return path


def project_venv(project_root: Path) -> Path:
    path = project_root / RUNTIME_VENV_RELATIVE
    try:
        info = path.lstat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "the pre-provisioned project virtual environment is unavailable",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "the project virtual environment must be a real directory",
        )
    return path


def copy_runtime_venv(source: Path, destination: Path, *, project_root: Path) -> None:
    system_python = TRUSTED_SYSTEM_PYTHON
    try:
        python_info = system_python.stat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "trusted system Python is unavailable",
        ) from exc
    if not stat.S_ISREG(python_info.st_mode) or not os.access(system_python, os.X_OK):
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "trusted system Python is unavailable",
        )

    try:
        completed = subprocess.run(
            [str(system_python), "-I", "-m", "venv", "--without-pip", str(destination)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=RUNTIME_COPY_TIMEOUT_SECONDS,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "sanitized runtime creation failed",
        ) from exc
    if completed.returncode != 0:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "sanitized runtime creation failed",
        )

    config_path = destination / "pyvenv.cfg"
    try:
        config_lines = config_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "sanitized runtime metadata is unavailable",
        ) from exc
    normalized_lines: list[str] = []
    for line in config_lines:
        if line.startswith("home = "):
            normalized_lines.append("home = /usr/bin")
        elif line.startswith("executable = "):
            normalized_lines.append("executable = /usr/bin/python3")
        elif line.startswith("command = "):
            normalized_lines.append("command = /usr/bin/python3 -I -m venv /workspace/.venv")
        else:
            normalized_lines.append(line)
    config_path.write_text("\n".join(normalized_lines) + "\n", encoding="utf-8")
    _copy_runtime_payload_confined(project_root, destination)


def _copy_runtime_payload_confined(project_root: Path, destination: Path) -> None:
    """Copy project dependency bytes inside a read-only project mount."""
    helper = RUNTIME_HELPER_PATH.resolve(strict=True)
    root = project_root.resolve(strict=True)
    if helper == root or root in helper.parents:
        raise PolicyError(
            "VEDAOPS_CONTROLLER_LAYOUT_UNSAFE",
            "controller runtime helper must be installed outside managed projects",
        )
    command = [
        str(BWRAP_PATH),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--hostname",
        "vedaops-runtime-capture",
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
            "--ro-bind",
            str(root),
            "/project",
            "--bind",
            str(destination.resolve(strict=True)),
            "/runtime",
            "--ro-bind",
            str(helper),
            "/vedaops-runtime-helper.py",
            "--chdir",
            "/",
            "--clearenv",
            "--setenv",
            "HOME",
            "/nonexistent",
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
            str(TRUSTED_SYSTEM_PYTHON),
            "-I",
            "/vedaops-runtime-helper.py",
            str(root),
            str(MAX_RUNTIME_FILES),
            str(MAX_RUNTIME_BYTES),
            str(RUNTIME_COPY_TIMEOUT_SECONDS),
        ]
    )
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=RUNTIME_COPY_TIMEOUT_SECONDS + 5,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "confined runtime capture failed",
        ) from exc
    if completed.returncode != 0:
        detail = completed.stdout.strip()[:1024] or "confined runtime capture failed"
        raise PolicyError("VEDAOPS_CHECK_RUNTIME_UNAVAILABLE", detail)


def runtime_identity(runtime_dir: Path, uv_path: Path) -> RuntimeIdentity:
    digest = hashlib.sha256()
    files = 0
    total = 0
    for current, directories, filenames in os.walk(runtime_dir, topdown=True, followlinks=False):
        directories.sort()
        filenames.sort()
        current_path = Path(current)
        for directory in directories:
            path = current_path / directory
            if path.is_symlink():
                relative = path.relative_to(runtime_dir).as_posix().encode()
                target = os.readlink(path).encode()
                digest.update(b"L" + len(relative).to_bytes(4, "big") + relative)
                digest.update(len(target).to_bytes(4, "big") + target)
        for filename in filenames:
            path = current_path / filename
            relative = path.relative_to(runtime_dir).as_posix().encode()
            info = path.lstat()
            files += 1
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path).encode()
                digest.update(b"L" + len(relative).to_bytes(4, "big") + relative)
                digest.update(len(target).to_bytes(4, "big") + target)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise PolicyError("VEDAOPS_CHECK_RUNTIME_UNAVAILABLE", "runtime identity failed")
            content = path.read_bytes()
            total += len(content)
            digest.update(b"F" + len(relative).to_bytes(4, "big") + relative)
            digest.update(len(content).to_bytes(8, "big") + content)
    python_path = runtime_dir / "bin" / "python"
    try:
        resolved_python = python_path.resolve(strict=True)
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "runtime Python is unavailable",
        ) from exc
    return RuntimeIdentity(
        kind="project_venv_sanitized",
        sha256=digest.hexdigest(),
        files=files,
        bytes=total,
        uv_sha256=_sha256_file(uv_path),
        python_sha256=_sha256_file(resolved_python),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
