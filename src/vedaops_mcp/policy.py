"""Shared path and Git policy for every inspect surface.

Managed repositories are untrusted inputs. This module is the only place that
decides which relative names may be resolved, which files may be read, and how
Git is invoked against a project root.
"""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import tempfile
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
            "partialclonefilter",
            "promisor",
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


def normalize_relative(value: str, *, allow_root: bool = False) -> str:
    """Return a normalized POSIX-relative project path, or refuse it."""
    if not isinstance(value, str):
        raise PolicyError("VEDAOPS_PATH_INVALID", "path must be a string")
    normalized = value.strip()
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


def read_bounded_file(
    root: Path,
    relative_path: str,
    *,
    offset_bytes: int = 0,
    limit_bytes: int,
) -> tuple[bytes, os.stat_result]:
    """Open and read one bounded regular file without following a final symlink."""
    resolved = resolve_within_root(root, relative_path, must_exist=True)
    try:
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_FILE_UNAVAILABLE",
            _filesystem_error_detail(relative_path, exc),
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("VEDAOPS_FILE_UNAVAILABLE", f"{relative_path} is not a regular file")
        if info.st_dev != root.stat().st_dev:
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
    return raw, info


def literal_pathspec(relative_path: str) -> str:
    """Return a Git pathspec that matches exactly one repository path."""
    return f":(literal){relative_path}"


def ensure_git_repository(root: Path) -> None:
    """Refuse a registered root that is not a self-contained Git repository."""
    git_directory = root / ".git"
    try:
        info = git_directory.lstat()
    except OSError as exc:
        raise PolicyError(
            "VEDAOPS_PROJECT_NOT_A_GIT_REPOSITORY",
            "registered project root is not a Git repository",
        ) from exc
    if not stat.S_ISDIR(info.st_mode):
        raise PolicyError(
            "VEDAOPS_PROJECT_CONFIG_UNSAFE",
            "the repository Git directory must be a real in-root directory",
        )


def ensure_safe_local_git_config(root: Path) -> None:
    """Refuse repository-local Git configuration outside a strict inert allowlist."""
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
                "--includes",
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
    command = ["git", "-C", str(root)]
    for key, value in GIT_CONFIG_OVERRIDES:
        command.extend(["-c", f"{key}={value}"])
    command.extend(args)
    return command


def _safe_local_git_config_key(key: str) -> bool:
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
