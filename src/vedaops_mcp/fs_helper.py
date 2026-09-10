"""Trusted Linux helper for conditional file effects inside a confined project mount."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path, PurePosixPath

AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
MAX_BYTES = 128 * 1024
ROOT = Path("/workspace")


def _emit(state: str, detail: str = "", *, backup: str | None = None) -> int:
    payload: dict[str, object] = {"state": state, "detail": detail[:1024]}
    if backup is not None:
        payload["backup"] = backup
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    return {"succeeded": 0, "precondition_failed": 2, "uncertain": 3}.get(state, 4)


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("invalid relative path")
    return value


def _validate_parent_chain(relative: str, *, create: bool) -> list[Path]:
    current = ROOT
    created: list[Path] = []
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                raise
            current.mkdir(mode=0o755)
            created.append(current)
            info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise OSError(errno.ELOOP, "parent is not a real directory")
    return created


def _cleanup_created(directories: list[Path]) -> None:
    for directory in reversed(directories):
        try:
            directory.rmdir()
        except OSError:
            return


def _read_regular(path: Path) -> tuple[bytes, int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise OSError(errno.EFBIG, "target is not a bounded regular file")
        raw = bytearray()
        while len(raw) <= MAX_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != info.st_size:
            raise OSError(errno.ESTALE, "target changed during read")
        return bytes(raw), stat.S_IMODE(info.st_mode)
    finally:
        os.close(descriptor)


def _renameat2(old: Path, new: Path, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(old),
        AT_FDCWD,
        os.fsencode(new),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _temporary(target: Path) -> Path:
    return target.with_name(f".{target.name}.vedaops-{secrets.token_hex(12)}")


def _write_temp(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode & 0o777,
    )
    try:
        os.fchmod(descriptor, mode & 0o777)
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            offset += os.write(descriptor, view[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(relative: str, expected: str, mode: int, raw: bytes) -> int:
    if len(raw) > MAX_BYTES:
        return _emit("precondition_failed", "replacement exceeds the hard limit")
    target = ROOT.joinpath(*PurePosixPath(relative).parts)
    temporary = _temporary(target)
    created: list[Path] = []
    try:
        created = _validate_parent_chain(relative, create=expected == "-")
        _write_temp(temporary, raw, mode)
        if expected == "-":
            try:
                _renameat2(temporary, target, RENAME_NOREPLACE)
            except FileExistsError:
                temporary.unlink(missing_ok=True)
                _cleanup_created(created)
                return _emit("precondition_failed", "target appeared concurrently")
            _validate_parent_chain(relative, create=False)
            current, _current_mode = _read_regular(target)
            if hashlib.sha256(current).hexdigest() != hashlib.sha256(raw).hexdigest():
                return _emit("uncertain", "created target could not be verified")
            return _emit("succeeded")

        try:
            _renameat2(temporary, target, RENAME_EXCHANGE)
        except FileNotFoundError:
            temporary.unlink(missing_ok=True)
            return _emit("precondition_failed", "target disappeared concurrently")
        try:
            displaced, _displaced_mode = _read_regular(temporary)
        except OSError as exc:
            try:
                _renameat2(temporary, target, RENAME_EXCHANGE)
            except OSError:
                return _emit(
                    "uncertain",
                    f"target substitution rollback failed: {exc}",
                    backup=temporary.name,
                )
            return _emit("precondition_failed", "target was substituted concurrently")
        if hashlib.sha256(displaced).hexdigest() != expected:
            try:
                _renameat2(temporary, target, RENAME_EXCHANGE)
            except OSError:
                return _emit(
                    "uncertain",
                    "concurrent target could not be restored",
                    backup=temporary.name,
                )
            return _emit("precondition_failed", "target was substituted concurrently")
        _validate_parent_chain(relative, create=False)
        current, _current_mode = _read_regular(target)
        if hashlib.sha256(current).hexdigest() != hashlib.sha256(raw).hexdigest():
            return _emit(
                "uncertain",
                "replacement target changed after conditional exchange",
                backup=temporary.name,
            )
        temporary.unlink()
        return _emit("succeeded")
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
            _cleanup_created(created)
        except OSError:
            return _emit(
                "uncertain",
                f"conditional write cleanup failed: {exc}",
                backup=temporary.name,
            )
        return _emit("precondition_failed", f"conditional write refused: {exc.strerror or exc}")


def _delete(relative: str, expected: str) -> int:
    target = ROOT.joinpath(*PurePosixPath(relative).parts)
    backup = _temporary(target)
    try:
        _validate_parent_chain(relative, create=False)
        _renameat2(target, backup, RENAME_NOREPLACE)
        try:
            displaced, _mode = _read_regular(backup)
        except OSError as exc:
            try:
                _renameat2(backup, target, RENAME_NOREPLACE)
            except OSError:
                return _emit(
                    "uncertain",
                    f"delete rollback failed: {exc}",
                    backup=backup.name,
                )
            return _emit("precondition_failed", "target was substituted concurrently")
        if hashlib.sha256(displaced).hexdigest() != expected:
            try:
                _renameat2(backup, target, RENAME_NOREPLACE)
            except OSError:
                return _emit(
                    "uncertain",
                    "concurrent target could not be restored",
                    backup=backup.name,
                )
            return _emit("precondition_failed", "target was substituted concurrently")
        _validate_parent_chain(relative, create=False)
        if target.exists() or target.is_symlink():
            return _emit(
                "uncertain",
                "target was recreated during conditional delete",
                backup=backup.name,
            )
        backup.unlink()
        return _emit("succeeded")
    except OSError as exc:
        return _emit("precondition_failed", f"conditional delete refused: {exc.strerror or exc}")


def main() -> int:
    try:
        operation = sys.argv[1]
        relative = _relative(sys.argv[2])
        expected = sys.argv[3]
        if operation == "write":
            mode = int(sys.argv[4], 8)
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            return _write(relative, expected, mode, raw)
        if operation == "delete":
            return _delete(relative, expected)
        return _emit("precondition_failed", "unsupported helper operation")
    except (IndexError, ValueError, OSError) as exc:
        return _emit("precondition_failed", f"invalid helper request: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
