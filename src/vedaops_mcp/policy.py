"""Shared path and Git policy for every inspect surface.

Managed repositories are untrusted inputs. This module is the only place that
decides which relative names may be resolved, which files may be read, and how
Git is invoked against a project root.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path, PurePosixPath

from vedaops_mcp.errors import PolicyError

MAX_FILE_BYTES = 128 * 1024
MAX_RELATIVE_PATH_CHARS = 1024
MAX_RELATIVE_PATH_PARTS = 40
MAX_GIT_OUTPUT_BYTES = 64 * 1024
MAX_GIT_RESULT_BYTES = 256 * 1024
GIT_TIMEOUT_SECONDS = 15
IGNORE_CHECK_TIMEOUT_SECONDS = 5
FALLBACK_PATH = "/usr/local/bin:/usr/bin:/bin"
GIT_PATH = Path("/usr/bin/git")
GIT_BWRAP_PATH = Path("/usr/bin/bwrap")
TRUSTED_PYTHON_PATH = Path("/usr/bin/python3")
FS_HELPER_PATH = Path(__file__).with_name("fs_helper.py")
MAX_GIT_ADMIN_ENTRIES = 200_000
GIT_ENVIRONMENT_ALLOWLIST = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "TZ",
    "USER",
)

GIT_CONFIG_OVERRIDES = (
    ("core.fsmonitor", ""),
    ("core.hooksPath", "/dev/null"),
    ("core.pager", "cat"),
    ("core.editor", "false"),
    ("core.sshCommand", ""),
    ("core.attributesFile", "/dev/null"),
    ("core.excludesFile", "/dev/null"),
    ("diff.external", ""),
    ("interactive.diffFilter", ""),
    ("uploadpack.packObjectsHook", ""),
    ("commit.gpgSign", "false"),
    ("tag.gpgSign", "false"),
)

SAFE_LOCAL_GIT_CONFIG_KEYS = frozenset(
    {
        "advice.detachedhead",
        "commit.gpgsign",
        "core.autocrlf",
        "core.bare",
        "core.eol",
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.precomposeunicode",
        "core.protecthfs",
        "core.protectntfs",
        "core.quotepath",
        "core.repositoryformatversion",
        "core.safecrlf",
        "core.sshcommand",
        "core.symlinks",
        "init.defaultbranch",
        "pull.ff",
        "pull.rebase",
        "push.default",
        "tag.gpgsign",
        "user.email",
        "user.name",
        "user.signingkey",
        "user.useconfigonly",
    }
)
SAFE_LOCAL_GIT_CONFIG_FAMILIES = {
    "branch": frozenset({"description", "merge", "pushremote", "rebase", "remote"}),
    "remote": frozenset(
        {
            "fetch",
            "mirror",
            "pushurl",
            "tagopt",
            "url",
        }
    ),
}

PROTECTED_DIRECTORY_PARTS = frozenset({".git"})
SENSITIVE_FILENAMES = frozenset(
    {
        ".env",
        ".envrc",
        ".htpasswd",
        ".netrc",
        ".npmrc",
        ".pgpass",
        ".pypirc",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
)
SENSITIVE_FILENAME_PREFIXES = (".env.",)
SENSITIVE_SUFFIXES = frozenset({".jks", ".key", ".keystore", ".p12", ".pem", ".pfx", ".ppk"})
MUTATION_PROTECTED_PATHS = frozenset({".vedaops/project.toml"})


def normalize_relative(value: str, *, allow_root: bool = False) -> str:
    """Return a normalized POSIX-relative project path, or refuse it."""
    if not isinstance(value, str):
        raise PolicyError("VEDAOPS_PATH_INVALID", "path must be a string")
    if value != value.strip():
        raise PolicyError(
            "VEDAOPS_PATH_INVALID",
            "path must not have leading or trailing whitespace",
        )
    normalized = value
    if allow_root and normalized in {"", "."}:
        return ""
    if not normalized or len(normalized) > MAX_RELATIVE_PATH_CHARS:
        raise PolicyError("VEDAOPS_PATH_INVALID", "path must be a bounded relative path")
    if (
        "\x00" in normalized
        or normalized.startswith('"')
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise PolicyError("VEDAOPS_PATH_INVALID", "path contains unsupported characters")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or "\\" in normalized
        or path.as_posix() != normalized
        or len(path.parts) > MAX_RELATIVE_PATH_PARTS
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PolicyError("VEDAOPS_PATH_INVALID", "path must be normalized and relative")
    return normalized


def protected_reason(relative_path: str) -> str | None:
    """Return why a normalized relative path is protected, or None."""
    parts = [part.casefold() for part in PurePosixPath(relative_path).parts]
    if not parts:
        return None
    filename = parts[-1]
    if any(part in PROTECTED_DIRECTORY_PARTS for part in parts):
        return "Git internal path"
    if filename in SENSITIVE_FILENAMES:
        return "secret-like filename"
    if filename.startswith(SENSITIVE_FILENAME_PREFIXES):
        return "secret-like filename"
    if PurePosixPath(filename).suffix.casefold() in SENSITIVE_SUFFIXES:
        return "secret-like file suffix"
    return None


def ensure_not_protected(relative_path: str) -> None:
    """Refuse a normalized relative path that names protected content."""
    reason = protected_reason(relative_path)
    if reason is not None:
        raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{relative_path} is a {reason}")


def ensure_mutation_path(relative_path: str) -> None:
    """Refuse paths that are readable but not mutable through the Change plane."""
    ensure_not_protected(relative_path)
    if relative_path.casefold() in MUTATION_PROTECTED_PATHS:
        raise PolicyError(
            "VEDAOPS_PATH_FORBIDDEN",
            f"{relative_path} is project mechanical authority and is not agent-writable",
        )


def resolve_within_root(root: Path, relative_path: str, *, must_exist: bool) -> Path:
    """Resolve a project-relative path and confirm the resolved target is legal."""
    ensure_not_protected(relative_path)
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    if resolved == root or root not in resolved.parents:
        raise PolicyError("VEDAOPS_PATH_ESCAPE", f"{relative_path} resolves outside the root")
    resolved_relative = resolved.relative_to(root).as_posix()
    if resolved_relative != relative_path:
        reason = protected_reason(resolved_relative)
        if reason is not None:
            raise PolicyError(
                "VEDAOPS_PATH_FORBIDDEN",
                f"{relative_path} resolves to a {reason}",
            )
        ensure_not_ignored(root, resolved_relative)
    try:
        if resolved.exists() and resolved.stat().st_dev != root.stat().st_dev:
            raise PolicyError("VEDAOPS_PATH_DEVICE_ESCAPE", relative_path)
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    return resolved


def _open_project_parent(root: Path, relative_path: str) -> tuple[int, str, os.stat_result]:
    """Pin every parent directory without following a project-controlled symlink."""
    normalized = normalize_relative(relative_path)
    parts = PurePosixPath(normalized).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise PolicyError("VEDAOPS_PATH_ESCAPE", "project root could not be pinned") from exc
    try:
        root_info = os.fstat(descriptor)
        for part in parts[:-1]:
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise PolicyError(
                    "VEDAOPS_PATH_FORBIDDEN",
                    f"{normalized} contains an unavailable or symlinked parent",
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1], root_info
    except Exception:
        os.close(descriptor)
        raise


def read_bounded_file(
    root: Path,
    relative_path: str,
    *,
    offset_bytes: int = 0,
    limit_bytes: int,
) -> tuple[bytes, os.stat_result]:
    """Read one bounded regular file through pinned no-follow path components."""
    normalized = normalize_relative(relative_path)
    ensure_not_protected(normalized)
    parent_descriptor, filename, root_info = _open_project_parent(root, normalized)
    try:
        entry = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode):
            raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{normalized} is a symlink")
        descriptor = os.open(
            filename,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
    except PolicyError:
        os.close(parent_descriptor)
        raise
    except OSError as exc:
        os.close(parent_descriptor)
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("VEDAOPS_FILE_UNAVAILABLE", f"{relative_path} is not a regular file")
        if info.st_dev != root_info.st_dev:
            raise PolicyError("VEDAOPS_PATH_DEVICE_ESCAPE", relative_path)
        if offset_bytes:
            os.lseek(descriptor, offset_bytes, os.SEEK_SET)
        raw = os.read(descriptor, limit_bytes + 1)
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    return raw, info


def read_bounded_file_with_digest(
    root: Path,
    relative_path: str,
    *,
    offset_bytes: int,
    limit_bytes: int,
    digest_limit_bytes: int,
) -> tuple[bytes, os.stat_result, str | None]:
    """Read one window and optional digest from the same pinned file descriptor."""
    normalized = normalize_relative(relative_path)
    ensure_not_protected(normalized)
    parent_descriptor, filename, root_info = _open_project_parent(root, normalized)
    try:
        entry = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode):
            raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{normalized} is a symlink")
        descriptor = os.open(
            filename,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
    except PolicyError:
        os.close(parent_descriptor)
        raise
    except OSError as exc:
        os.close(parent_descriptor)
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("VEDAOPS_FILE_UNAVAILABLE", f"{relative_path} is not a regular file")
        if info.st_dev != root_info.st_dev:
            raise PolicyError("VEDAOPS_PATH_DEVICE_ESCAPE", relative_path)
        digest: str | None = None
        if info.st_size <= digest_limit_bytes:
            whole = bytearray()
            while len(whole) <= digest_limit_bytes:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, digest_limit_bytes + 1 - len(whole)),
                )
                if not chunk:
                    break
                whole.extend(chunk)
            if len(whole) != info.st_size:
                raise PolicyError(
                    "VEDAOPS_FILE_UNAVAILABLE",
                    "file changed while it was being captured",
                )
            digest = hashlib.sha256(whole).hexdigest()
            raw = bytes(whole[offset_bytes : offset_bytes + limit_bytes + 1])
        else:
            if offset_bytes:
                os.lseek(descriptor, offset_bytes, os.SEEK_SET)
            raw = os.read(descriptor, limit_bytes + 1)
        return raw, info, digest
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def ensure_project_parent_directories(root: Path, relative_path: str) -> list[str]:
    """Create missing parent directories through pinned no-follow directory descriptors."""
    normalized = normalize_relative(relative_path)
    parts = PurePosixPath(normalized).parts[:-1]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    created: list[str] = []
    traversed: list[str] = []
    try:
        for part in parts:
            traversed.append(part)
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=descriptor)
                created.append(PurePosixPath(*traversed).as_posix())
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise PolicyError(
                    "VEDAOPS_PATH_FORBIDDEN",
                    f"{normalized} contains an unavailable or symlinked parent",
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
    finally:
        os.close(descriptor)
    return created


def remove_project_empty_directories(root: Path, directories: list[str]) -> None:
    """Best-effort removal of directories created by one failed governed write."""
    for relative in reversed(directories):
        parent = PurePosixPath(relative).parent
        name = PurePosixPath(relative).name
        parent_path = "placeholder" if str(parent) == "." else f"{parent.as_posix()}/placeholder"
        try:
            descriptor, _filename, _root_info = _open_project_parent(root, parent_path)
        except PolicyError:
            continue
        try:
            os.rmdir(name, dir_fd=descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)


def atomic_write_project_file(root: Path, relative_path: str, data: bytes, mode: int) -> None:
    """Atomically replace one file through a pinned parent directory descriptor."""
    parent_descriptor, filename, _root_info = _open_project_parent(root, relative_path)
    temporary: str | None = None
    descriptor: int | None = None
    try:
        for _attempt in range(8):
            temporary = f".{filename}.vedaops-{secrets.token_hex(8)}"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    mode & 0o777,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                continue
        if descriptor is None or temporary is None:
            raise PolicyError("VEDAOPS_FILE_UNAVAILABLE", "temporary file name collision")
        os.fchmod(descriptor, mode & 0o777)
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary,
            filename,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary = None
        os.fsync(parent_descriptor)
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(OSError):
                os.unlink(temporary, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def unlink_project_file(root: Path, relative_path: str) -> None:
    """Unlink one final path component through a pinned parent descriptor."""
    parent_descriptor, filename, _root_info = _open_project_parent(root, relative_path)
    try:
        os.unlink(filename, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    finally:
        os.close(parent_descriptor)


def project_lstat(root: Path, relative_path: str) -> os.stat_result | None:
    """Return a no-follow final-entry stat through pinned parent components."""
    try:
        parent_descriptor, filename, _root_info = _open_project_parent(root, relative_path)
    except PolicyError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise
    try:
        try:
            return os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    finally:
        os.close(parent_descriptor)


def conditional_write_project_file(
    root: Path,
    relative_path: str,
    data: bytes,
    mode: int,
    *,
    expected_sha256: str | None,
) -> None:
    """Apply one conditional write inside a filesystem-confined helper."""
    expected = "-" if expected_sha256 is None else expected_sha256
    _run_file_helper(root, "write", relative_path, expected, f"{mode & 0o777:o}", input_bytes=data)


def conditional_delete_project_file(
    root: Path,
    relative_path: str,
    *,
    expected_sha256: str,
) -> None:
    """Delete only the exact expected file object inside a filesystem-confined helper."""
    _run_file_helper(root, "delete", relative_path, expected_sha256, input_bytes=b"")


def _run_file_helper(
    root: Path,
    operation: str,
    relative_path: str,
    expected: str,
    *extra: str,
    input_bytes: bytes,
) -> None:
    helper = FS_HELPER_PATH.resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    if helper == resolved_root or resolved_root in helper.parents:
        raise PolicyError(
            "VEDAOPS_CONTROLLER_LAYOUT_UNSAFE",
            "controller file-effect helper must be installed outside managed projects",
        )
    command = [
        str(GIT_BWRAP_PATH),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--hostname",
        "vedaops-file",
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
            "--bind",
            str(resolved_root),
            "/workspace",
            "--ro-bind",
            str(helper),
            "/vedaops-fs-helper.py",
            "--chdir",
            "/workspace",
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
            str(TRUSTED_PYTHON_PATH),
            "-I",
            "/vedaops-fs-helper.py",
            operation,
            relative_path,
            expected,
            *extra,
        ]
    )
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(
            "VEDAOPS_CHANGE_EFFECT_UNCERTAIN",
            "confined file operation may have started; inspect the exact target before retrying",
        ) from exc
    if len(completed.stdout) > 4096 or len(completed.stderr) > 4096:
        raise PolicyError(
            "VEDAOPS_CHANGE_EFFECT_UNCERTAIN",
            "confined file operation returned malformed evidence; inspect before retrying",
        )
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
        state = payload["state"]
        detail = str(payload.get("detail", ""))
        backup = payload.get("backup")
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PolicyError(
            "VEDAOPS_CHANGE_EFFECT_UNCERTAIN",
            "confined file operation returned malformed evidence; inspect before retrying",
        ) from exc
    if completed.returncode == 0 and state == "succeeded":
        return
    if completed.returncode == 2 and state == "precondition_failed":
        raise PolicyError(
            "VEDAOPS_CHANGE_PRECONDITION_FAILED",
            detail or "file precondition changed before the effect",
        )
    if completed.returncode == 3 and state == "uncertain":
        suffix = f"; preserved backup {backup!r}" if backup else ""
        raise PolicyError(
            "VEDAOPS_CHANGE_EFFECT_UNCERTAIN",
            (detail or "file effect could not be verified") + suffix,
        )
    raise PolicyError(
        "VEDAOPS_CHANGE_EFFECT_UNCERTAIN",
        "confined file operation failed without trustworthy terminal evidence; "
        "inspect before retrying",
    )


def literal_pathspec(relative_path: str) -> str:
    """Return a Git pathspec that matches exactly one repository path."""
    return f":(literal){relative_path}"


def ensure_git_repository(root: Path) -> None:
    """Refuse unsupported Git metadata before a confined Git subprocess starts."""
    git_directory = root / ".git"
    try:
        info = git_directory.lstat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_PROJECT_NOT_A_GIT_REPOSITORY",
            "registered project root is not a Git repository",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository Git directory must be a real in-root directory",
        )

    for relative, expected_kind in (
        ("HEAD", "file"),
        ("config", "file"),
        ("objects", "directory"),
        ("refs", "directory"),
    ):
        candidate = git_directory / relative
        try:
            child = candidate.lstat()
        except OSError as exc:
            raise PolicyError(
                "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                f"repository Git administrative path .git/{relative} is unavailable",
            ) from exc
        valid = (
            stat.S_ISREG(child.st_mode)
            if expected_kind == "file"
            else stat.S_ISDIR(child.st_mode)
        )
        if not valid or stat.S_ISLNK(child.st_mode):
            raise PolicyError(
                "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                "repository Git administrative path "
                f".git/{relative} must be a real {expected_kind}",
            )

    for relative in (
        "commondir",
        "gitdir",
        "objects/info/alternates",
        "info/grafts",
        "shallow",
        "modules",
    ):
        candidate = git_directory / relative
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PolicyError(
                "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                f"repository Git administrative path .git/{relative} is unavailable",
            ) from exc
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            f"repository Git administrative indirection .git/{relative} is unsupported",
        )

    for relative in ("refs", "objects", "logs", "info"):
        _validate_git_admin_subtree(git_directory, relative)

    for relative in ("packed-refs", "index"):
        candidate = git_directory / relative
        try:
            entry = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PolicyError(
                "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                f"repository Git administrative path .git/{relative} is unavailable",
            ) from exc
        if not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode):
            raise PolicyError(
                "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                f"repository Git administrative path .git/{relative} must be a regular file",
            )


def _validate_git_admin_subtree(git_directory: Path, relative: str) -> None:
    """Reject aliases/non-files in metadata trees that Git may read or mutate."""
    start = git_directory / relative
    try:
        info = start.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            f"repository Git administrative path .git/{relative} is unavailable",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            f"repository Git administrative path .git/{relative} must be a real directory",
        )
    count = 0
    for current, directories, filenames in os.walk(start, topdown=True, followlinks=False):
        directories.sort()
        filenames.sort()
        current_path = Path(current)
        for name in [*directories, *filenames]:
            count += 1
            if count > MAX_GIT_ADMIN_ENTRIES:
                raise PolicyError(
                    "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                    "Git administrative tree exceeds the validation bound",
                )
            entry = (current_path / name).lstat()
            if stat.S_ISLNK(entry.st_mode) or not (
                stat.S_ISDIR(entry.st_mode) or stat.S_ISREG(entry.st_mode)
            ):
                raise PolicyError(
                    "VEDAOPS_PROJECT_CONFIG_UNSAFE",
                    "Git administrative trees may contain only real files/directories",
                )


def ensure_safe_local_git_config(root: Path) -> None:
    """Refuse repository-local Git configuration outside a strict inert allowlist.

    Inspection uses ``--no-includes``. Include and includeIf keys fail closed so
    a managed repository cannot point Git at operator configuration outside the
    root.
    """
    ensure_git_repository(root)
    config_path = root / ".git" / "config"
    try:
        info = config_path.lstat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository local Git configuration is unavailable",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository local Git configuration must be a regular file",
        )

    try:
        completed = subprocess.run(
            _git_command(
                root,
                "config",
                "--local",
                "--no-includes",
                "--null",
                "--name-only",
                "--list",
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=IGNORE_CHECK_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            env=git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository local Git configuration could not be inspected",
        ) from exc
    if completed.returncode != 0 or len(completed.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository local Git configuration is invalid or too large",
        )

    try:
        keys = [
            value.decode("utf-8").casefold() for value in completed.stdout.split(b"\x00") if value
        ]
    except UnicodeDecodeError as exc:
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository local Git configuration is not UTF-8",
        ) from exc
    unsafe = sorted({key for key in keys if not _safe_local_git_config_key(key)})
    if unsafe:
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            f"repository local Git configuration key {unsafe[0]!r} is not allowed",
        )


def ensure_not_ignored(root: Path, relative_path: str) -> None:
    """Refuse a path that Git ignores. Fails closed when Git cannot answer."""
    ensure_safe_local_git_config(root)
    try:
        completed = subprocess.run(
            _git_command(root, "check-ignore", "--quiet", "--no-index", "--", relative_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=IGNORE_CHECK_TIMEOUT_SECONDS,
            check=False,
            env=git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git ignore check failed") from exc
    if completed.returncode == 0:
        raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{relative_path} is ignored by Git")
    if completed.returncode != 1:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git ignore check failed")


def git_environment() -> dict[str, str]:
    """Return a minimal, non-interactive environment for Git subprocesses."""
    environment = {
        name: os.environ[name] for name in GIT_ENVIRONMENT_ALLOWLIST if name in os.environ
    }
    if not environment.get("PATH"):
        environment["PATH"] = FALLBACK_PATH
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_PAGER"] = "cat"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_ALLOW_PROTOCOL"] = ""
    environment["GIT_PROTOCOL_FROM_USER"] = "0"
    return environment


def run_git_bytes(
    root: Path,
    *args: str,
    limit_bytes: int = MAX_GIT_RESULT_BYTES,
    timeout_seconds: int = GIT_TIMEOUT_SECONDS,
    allow_exit_1: bool = False,
) -> bytes:
    """Run one bounded Git command and return at most ``limit_bytes`` of stdout."""
    try:
        with tempfile.TemporaryFile() as out_handle, tempfile.TemporaryFile() as err_handle:
            ensure_safe_local_git_config(root)
            completed = subprocess.run(
                _git_command(root, *args),
                stdin=subprocess.DEVNULL,
                stdout=out_handle,
                stderr=err_handle,
                timeout=timeout_seconds,
                check=False,
                shell=False,
                env=git_environment(),
            )
            out_handle.seek(0)
            raw = out_handle.read(limit_bytes + 1)
            err_handle.seek(0)
            error_text = err_handle.read(2048).decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git command failed") from exc
    if completed.returncode != 0 and not (allow_exit_1 and completed.returncode == 1):
        detail = _first_line(error_text) or "Git command failed"
        if str(root) in detail:
            detail = "Git command failed for the managed project"
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", detail)
    if len(raw) > limit_bytes:
        raise PolicyError("VEDAOPS_GIT_OUTPUT_TOO_LARGE", "Git output exceeded the hard limit")
    return raw


def run_git_text(root: Path, *args: str, allow_exit_1: bool = False) -> str:
    """Run one bounded Git command expected to return short UTF-8 text."""
    raw = run_git_bytes(
        root,
        *args,
        limit_bytes=MAX_GIT_OUTPUT_BYTES,
        allow_exit_1=allow_exit_1,
    )
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git output was not UTF-8") from exc


def run_git_input(
    root: Path,
    *args: str,
    input_bytes: bytes,
    limit_bytes: int = MAX_GIT_RESULT_BYTES,
    timeout_seconds: int = GIT_TIMEOUT_SECONDS,
) -> bytes:
    """Run one bounded Git command with bounded stdin and return bounded stdout."""
    if len(input_bytes) > MAX_GIT_RESULT_BYTES:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "Git input exceeded the hard limit")
    try:
        with tempfile.TemporaryFile() as out_handle, tempfile.TemporaryFile() as err_handle:
            ensure_safe_local_git_config(root)
            completed = subprocess.run(
                _git_command(root, *args),
                input=input_bytes,
                stdout=out_handle,
                stderr=err_handle,
                timeout=timeout_seconds,
                check=False,
                shell=False,
                env=git_environment(),
            )
            out_handle.seek(0)
            raw = out_handle.read(limit_bytes + 1)
            err_handle.seek(0)
            error_text = err_handle.read(2048).decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git command failed") from exc
    if completed.returncode != 0:
        detail = _first_line(error_text) or "Git command failed"
        if str(root) in detail:
            detail = "Git command failed for the managed project"
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", detail)
    if len(raw) > limit_bytes:
        raise PolicyError("VEDAOPS_GIT_OUTPUT_TOO_LARGE", "Git output exceeded the hard limit")
    return raw


def read_git_blobs_batch(
    root: Path,
    object_ids: list[str],
    *,
    max_blob_bytes: int,
    max_batch_bytes: int,
    timeout_seconds: int,
) -> dict[str, bytes]:
    """Read exact Git blobs in two bounded batch calls with replacement refs disabled."""
    unique_ids = list(dict.fromkeys(object_ids))
    if not unique_ids:
        return {}
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in unique_ids)
    deadline = time.monotonic() + timeout_seconds

    def _run(*args: str) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob capture timed out")
        try:
            ensure_safe_local_git_config(root)
            completed = subprocess.run(
                _git_command(root, *args),
                input=request,
                capture_output=True,
                timeout=remaining,
                check=False,
                shell=False,
                env=git_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob capture failed") from exc
        if completed.returncode != 0:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob capture failed")
        return completed.stdout

    checked = _run("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
    lines = checked.splitlines()
    if len(lines) != len(unique_ids):
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob metadata was malformed")
    total = 0
    expected_sizes: dict[str, int] = {}
    for requested, line in zip(unique_ids, lines, strict=True):
        try:
            actual, object_type, raw_size = line.decode("ascii").split(" ", 2)
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob metadata was malformed") from exc
        if actual != requested or object_type != "blob" or size < 0:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob metadata was malformed")
        if size > max_blob_bytes:
            raise PolicyError("VEDAOPS_GIT_OUTPUT_TOO_LARGE", "Git blob exceeded the hard limit")
        total += size
        if total > max_batch_bytes:
            raise PolicyError(
                "VEDAOPS_GIT_OUTPUT_TOO_LARGE",
                "Git blob batch exceeded the hard limit",
            )
        expected_sizes[requested] = size

    raw = _run("cat-file", "--batch")
    cursor = 0
    result: dict[str, bytes] = {}
    for requested in unique_ids:
        newline = raw.find(b"\n", cursor)
        if newline < 0:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob batch was malformed")
        try:
            actual, object_type, raw_size = raw[cursor:newline].decode("ascii").split(" ", 2)
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob batch was malformed") from exc
        if actual != requested or object_type != "blob" or size != expected_sizes[requested]:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob batch was malformed")
        start = newline + 1
        end = start + size
        if end >= len(raw) or raw[end : end + 1] != b"\n":
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob batch was malformed")
        result[requested] = raw[start:end]
        cursor = end + 1
    if cursor != len(raw):
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git blob batch was malformed")
    return result


def decode_bounded_utf8(raw: bytes, *, may_end_mid_codepoint: bool) -> tuple[str, int]:
    """Decode bytes as UTF-8, trimming at most three trailing partial bytes."""
    candidate = raw
    while True:
        try:
            return candidate.decode("utf-8"), len(candidate)
        except UnicodeDecodeError as exc:
            if (
                may_end_mid_codepoint
                and exc.end == len(candidate)
                and len(raw) - len(candidate) < 4
            ):
                candidate = candidate[:-1]
                continue
            raise PolicyError(
                "VEDAOPS_FILE_INVALID_ENCODING",
                "content must be valid UTF-8",
            ) from exc


def bounded_text(raw: bytes, limit: int) -> tuple[str, int, bool]:
    """Return bounded decoded text, the byte count returned, and truncation."""
    chunk = raw[:limit]
    text, returned = decode_bounded_utf8(chunk, may_end_mid_codepoint=len(raw) > limit)
    return text, returned, len(raw) > returned


def _git_command(root: Path, *args: str) -> list[str]:
    """Run Git in a mount/network namespace that exposes only the managed root."""
    command = [
        str(GIT_BWRAP_PATH),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--hostname",
        "vedaops-git",
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
            "--bind",
            str(root.resolve()),
            "/workspace",
            "--chdir",
            "/workspace",
            "--clearenv",
            "--setenv",
            "HOME",
            "/home/worker",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "GIT_TERMINAL_PROMPT",
            "0",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_OPTIONAL_LOCKS",
            "0",
            "--setenv",
            "GIT_PAGER",
            "cat",
            "--setenv",
            "GIT_NO_REPLACE_OBJECTS",
            "1",
            "--setenv",
            "GIT_ALLOW_PROTOCOL",
            "",
            "--setenv",
            "GIT_PROTOCOL_FROM_USER",
            "0",
            "--",
            str(GIT_PATH),
            "--no-replace-objects",
            "-C",
            "/workspace",
        ]
    )
    for key, value in GIT_CONFIG_OVERRIDES:
        command.extend(["-c", f"{key}={value}"])
    command.extend(args)
    return command


def _safe_local_git_config_key(key: str) -> bool:
    if (
        key == "include"
        or key == "includeif"
        or key.startswith("include.")
        or key.startswith("includeif.")
    ):
        return False
    if key in SAFE_LOCAL_GIT_CONFIG_KEYS:
        return True
    parts = key.split(".")
    if len(parts) < 3:
        return False
    family = SAFE_LOCAL_GIT_CONFIG_FAMILIES.get(parts[0])
    return family is not None and parts[-1] in family and all(parts[1:-1])


def _filesystem_error_detail(relative_path: str, exc: OSError) -> str:
    error_name = errno.errorcode.get(exc.errno or 0, "FILESYSTEM_ERROR")
    return f"{relative_path}: {error_name}"


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
