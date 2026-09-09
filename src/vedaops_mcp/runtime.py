"""Sanitized, bounded dependency-runtime capture for restricted project checks."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vedaops_mcp.errors import PolicyError

RUNTIME_VENV_RELATIVE = Path(".venv")
MAX_RUNTIME_FILES = 20_000
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
RUNTIME_COPY_TIMEOUT_SECONDS = 30
TRUSTED_SYSTEM_PYTHON = Path("/usr/bin/python3")


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


def _site_packages_root(venv_root: Path) -> Path:
    lib = venv_root / "lib"
    try:
        lib_info = lib.lstat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "runtime lib directory is unavailable",
        ) from exc
    if not stat.S_ISDIR(lib_info.st_mode) or stat.S_ISLNK(lib_info.st_mode):
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "runtime lib directory must be a real directory",
        )
    candidates: list[Path] = []
    for item in lib.iterdir():
        info = item.lstat()
        if item.name.startswith("python") and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(
            info.st_mode
        ):
            site = item / "site-packages"
            try:
                site_info = site.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(site_info.st_mode) and not stat.S_ISLNK(site_info.st_mode):
                candidates.append(site)
    if len(candidates) != 1:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "runtime site-packages layout is unsupported",
        )
    return candidates[0]


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

    started = time.monotonic()
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

    source_site = _site_packages_root(source)
    target_site = _site_packages_root(destination)
    if source_site.parent.name != target_site.parent.name:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "project runtime Python version does not match trusted system Python",
        )

    files = 0
    total = 0
    for current, directories, filenames, directory_fd in os.fwalk(
        source_site,
        topdown=True,
        follow_symlinks=False,
    ):
        if time.monotonic() - started > RUNTIME_COPY_TIMEOUT_SECONDS:
            raise PolicyError(
                "VEDAOPS_CHECK_RUNTIME_TOO_LARGE",
                "runtime capture exceeded its deadline",
            )
        current_path = Path(current)
        relative_dir = current_path.relative_to(source_site)
        target_dir = target_site / relative_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        directories.sort()
        filenames.sort()
        for directory in directories:
            info = os.stat(directory, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                    "runtime packages contain an unsupported directory entry",
                )
        for filename in filenames:
            info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                    "runtime packages contain an unsupported file entry",
                )
            files += 1
            total += info.st_size
            if files > MAX_RUNTIME_FILES or total > MAX_RUNTIME_BYTES:
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_TOO_LARGE",
                    "runtime packages exceed the capture bound",
                )
            descriptor = os.open(
                filename,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                with os.fdopen(descriptor, "rb", closefd=True) as source_file:
                    target_file = target_dir / filename
                    with target_file.open("wb") as destination_file:
                        shutil.copyfileobj(source_file, destination_file)
                target_file.chmod(stat.S_IMODE(info.st_mode) & 0o777)
            except Exception:
                raise

    _rewrite_project_paths_in_pth(project_root, target_site)
    files, total = _copy_runtime_executables(
        source,
        destination,
        started=started,
        files=files,
        total=total,
    )


def _rewrite_project_paths_in_pth(project_root: Path, target_site: Path) -> None:
    """Retarget editable-install path entries from the live repo to the sandbox snapshot."""
    root = Path(os.path.normpath(str(project_root.resolve(strict=True))))
    for path in sorted(target_site.glob("*.pth")):
        try:
            info = path.lstat()
        except OSError as exc:
            raise PolicyError(
                "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                "runtime path metadata is unavailable",
            ) from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PolicyError(
                "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                "runtime path metadata must be a regular file",
            )
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(
                "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                "runtime path metadata must be UTF-8 text",
            ) from exc
        rewritten: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            candidate = Path(os.path.normpath(stripped)) if stripped else None
            if candidate is not None and candidate.is_absolute() and (
                candidate == root or root in candidate.parents
            ):
                relative = candidate.relative_to(root)
                rewritten.append((Path("/workspace") / relative).as_posix())
            else:
                rewritten.append(line)
        trailing = "\n" if text.endswith("\n") else ""
        path.write_text("\n".join(rewritten) + trailing, encoding="utf-8")


def _copy_runtime_executables(
    source: Path,
    destination: Path,
    *,
    started: float,
    files: int,
    total: int,
) -> tuple[int, int]:
    """Copy bounded regular venv console executables without preserving Python aliases."""
    source_bin = source / "bin"
    target_bin = destination / "bin"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        directory_fd = os.open(source_bin, flags)
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
            "runtime bin directory is unavailable",
        ) from exc
    try:
        for filename in sorted(os.listdir(directory_fd)):
            if time.monotonic() - started > RUNTIME_COPY_TIMEOUT_SECONDS:
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_TOO_LARGE",
                    "runtime capture exceeded its deadline",
                )
            target = target_bin / filename
            if filename in {"uv", "uvx"} or target.exists() or target.is_symlink():
                continue
            try:
                info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                    "runtime executable metadata is unavailable",
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                    "runtime bin contains an unsupported entry",
                )
            if not info.st_mode & 0o111:
                continue
            files += 1
            total += info.st_size
            if files > MAX_RUNTIME_FILES or total > MAX_RUNTIME_BYTES:
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_TOO_LARGE",
                    "runtime packages and executables exceed the capture bound",
                )
            try:
                descriptor = os.open(
                    filename,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise PolicyError(
                    "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                    "runtime executable is unavailable",
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_dev != info.st_dev
                    or opened.st_ino != info.st_ino
                ):
                    raise PolicyError(
                        "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                        "runtime executable changed during capture",
                    )
                with os.fdopen(descriptor, "rb", closefd=True) as handle:
                    descriptor = -1
                    raw = handle.read(info.st_size + 1)
                if len(raw) != info.st_size:
                    raise PolicyError(
                        "VEDAOPS_CHECK_RUNTIME_UNAVAILABLE",
                        "runtime executable changed during capture",
                    )
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            first_line, separator, remainder = raw.partition(b"\n")
            if separator and first_line.startswith(b"#!") and b"python" in first_line.lower():
                raw = b"#!/workspace/.venv/bin/python\n" + remainder
            target.write_bytes(raw)
            target.chmod(stat.S_IMODE(info.st_mode) & 0o777)
    finally:
        os.close(directory_fd)
    return files, total


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
