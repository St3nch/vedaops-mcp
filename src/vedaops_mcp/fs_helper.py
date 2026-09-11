"""Trusted Linux helper for conditional file effects inside a confined project mount."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
from contextlib import suppress
from pathlib import PurePosixPath

RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
MAX_BYTES = 128 * 1024
ROOT_PATH = "/workspace"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _emit(
    state: str,
    detail: str = "",
    *,
    recoveries: list[str] | None = None,
    cleanup: list[dict[str, object]] | None = None,
    effect_occurred: bool = False,
) -> int:
    payload: dict[str, object] = {
        "state": state,
        "detail": detail[:1024],
        "effect_occurred": effect_occurred,
    }
    if recoveries:
        payload["recoveries"] = recoveries
    if cleanup:
        payload["cleanup"] = cleanup
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


def _operation_id(value: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if not value or len(value) > 64 or any(character not in allowed for character in value):
        raise ValueError("invalid operation id")
    return value


def _parent_guard(value: str, relative: str) -> list[tuple[int, int] | None]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid parent guard") from exc
    expected_length = len(PurePosixPath(relative).parts)
    if not isinstance(payload, list) or len(payload) != expected_length:
        raise ValueError("invalid parent guard")
    guard: list[tuple[int, int] | None] = []
    missing_seen = False
    for item in payload:
        if item is None:
            missing_seen = True
            guard.append(None)
            continue
        if missing_seen or not isinstance(item, list) or len(item) != 2:
            raise ValueError("invalid parent guard")
        dev, ino = item
        if (
            not isinstance(dev, int)
            or isinstance(dev, bool)
            or dev < 0
            or not isinstance(ino, int)
            or isinstance(ino, bool)
            or ino <= 0
        ):
            raise ValueError("invalid parent guard")
        guard.append((dev, ino))
    if guard[0] is None:
        raise ValueError("invalid parent guard")
    return guard


def _matches_identity(descriptor: int, expected: tuple[int, int]) -> bool:
    info = os.fstat(descriptor)
    return info.st_dev == expected[0] and info.st_ino == expected[1]


def _open_parent(
    relative: str,
    *,
    create: bool,
    guard: list[tuple[int, int] | None] | None = None,
) -> tuple[list[int], int, str, list[tuple[int, str]]]:
    parts = PurePosixPath(relative).parts
    descriptors = [os.open(ROOT_PATH, DIR_FLAGS)]
    created: list[tuple[int, str]] = []
    try:
        if guard is not None and not _matches_identity(descriptors[0], guard[0]):
            raise OSError(errno.ESTALE, "project root changed before effect")
        for index, part in enumerate(parts[:-1], start=1):
            parent_fd = descriptors[-1]
            expected = guard[index] if guard is not None else None
            try:
                child_fd = os.open(part, DIR_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                if guard is not None and expected is not None:
                    raise OSError(
                        errno.ESTALE, "authorized parent disappeared before effect"
                    ) from None
                os.mkdir(part, mode=0o755, dir_fd=parent_fd)
                created.append((parent_fd, part))
                child_fd = os.open(part, DIR_FLAGS, dir_fd=parent_fd)
            else:
                if guard is not None and expected is None:
                    os.close(child_fd)
                    raise OSError(errno.ESTALE, "unauthorized parent appeared before effect")
            if (
                guard is not None
                and expected is not None
                and not _matches_identity(child_fd, expected)
            ):
                os.close(child_fd)
                raise OSError(errno.ESTALE, "authorized parent identity changed before effect")
            descriptors.append(child_fd)
        return descriptors, descriptors[-1], parts[-1], created
    except Exception:
        _close_descriptors(descriptors)
        raise


def _close_descriptors(descriptors: list[int]) -> None:
    for descriptor in reversed(descriptors):
        with suppress(OSError):
            os.close(descriptor)



def _read_regular_at(parent_fd: int, name: str) -> tuple[bytes, int]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
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
        final = os.fstat(descriptor)
        if final.st_dev != info.st_dev or final.st_ino != info.st_ino or len(raw) != final.st_size:
            raise OSError(errno.ESTALE, "target changed during read")
        return bytes(raw), stat.S_IMODE(info.st_mode)
    finally:
        os.close(descriptor)


def _write_temp_at(
    parent_fd: int,
    name: str,
    raw: bytes,
    mode: int,
    owned_entries: list[dict[str, object]],
) -> dict[str, object]:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode & 0o777,
        dir_fd=parent_fd,
    )
    try:
        info = os.fstat(descriptor)
        entry: dict[str, object] = {"name": name, "dev": info.st_dev, "ino": info.st_ino}
        owned_entries.append(entry)
        os.fchmod(descriptor, mode & 0o777)
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            offset += os.write(descriptor, view[offset:])
        os.fsync(descriptor)
        return entry
    finally:
        os.close(descriptor)


def _entry_identity_at(parent_fd: int, name: str) -> tuple[int, int]:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(errno.EINVAL, "entry is not a regular file")
    return info.st_dev, info.st_ino



def _exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _renameat2(old_fd: int, old_name: str, new_fd: int, new_name: str, flags: int) -> None:
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
        old_fd,
        os.fsencode(old_name),
        new_fd,
        os.fsencode(new_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _parent_identity_matches(relative: str, pinned_parent_fd: int) -> bool:
    try:
        descriptors, current_parent_fd, _target, _created = _open_parent(
            relative,
            create=False,
        )
    except OSError:
        return False
    try:
        pinned = os.fstat(pinned_parent_fd)
        current = os.fstat(current_parent_fd)
        return pinned.st_dev == current.st_dev and pinned.st_ino == current.st_ino
    finally:
        _close_descriptors(descriptors)


def _temp_names(target: str, operation_id: str) -> tuple[str, str]:
    prefix = f".{target}.vedaops-{operation_id}"
    return f"{prefix}-candidate", f"{prefix}-recovery"



def _write(
    relative: str,
    expected: str,
    mode: int,
    raw: bytes,
    operation_id: str,
    parent_guard: list[tuple[int, int] | None] | None = None,
) -> int:
    if len(raw) > MAX_BYTES:
        return _emit("precondition_failed", "replacement exceeds the hard limit")
    descriptors: list[int] = []
    created: list[tuple[int, str]] = []
    cleanup_entries: list[dict[str, object]] = []
    candidate = ""
    recovery = ""
    effect_occurred = False
    try:
        descriptors, parent_fd, target, created = _open_parent(
            relative,
            create=expected == "-",
            guard=parent_guard,
        )
        candidate, recovery = _temp_names(target, operation_id)
        _write_temp_at(parent_fd, candidate, raw, mode, cleanup_entries)

        if expected == "-":
            if not _parent_identity_matches(relative, parent_fd):
                return _emit(
                    "uncertain",
                    "target parent changed before create; candidate preserved",
                    recoveries=[candidate],
                )
            try:
                _renameat2(parent_fd, candidate, parent_fd, target, RENAME_NOREPLACE)
            except FileExistsError:
                if created:
                    return _emit(
                        "uncertain",
                        "target appeared after parent creation; candidate preserved",
                        recoveries=[candidate],
                    )
                return _emit(
                    "precondition_failed",
                    "target appeared concurrently",
                    cleanup=cleanup_entries,
                )
            effect_occurred = True
            cleanup_entries.clear()
            try:
                current, _current_mode = _read_regular_at(parent_fd, target)
                if hashlib.sha256(current).hexdigest() != hashlib.sha256(raw).hexdigest():
                    raise OSError(errno.ESTALE, "created target bytes changed")
                if not _parent_identity_matches(relative, parent_fd):
                    raise OSError(errno.ESTALE, "target parent changed after create")
                os.fsync(parent_fd)
            except OSError as exc:
                return _emit(
                    "uncertain",
                    f"create effect requires inspection: {exc}",
                    effect_occurred=True,
                )
            return _emit("succeeded", effect_occurred=True)

        before, before_mode = _read_regular_at(parent_fd, target)
        if hashlib.sha256(before).hexdigest() != expected:
            return _emit(
                "precondition_failed",
                "target bytes do not match expected SHA-256",
                cleanup=cleanup_entries,
            )
        recovery_entry = _write_temp_at(parent_fd, recovery, before, before_mode, cleanup_entries)
        recoveries = [recovery]
        if not _parent_identity_matches(relative, parent_fd):
            return _emit(
                "precondition_failed",
                "target parent changed before replace",
                cleanup=cleanup_entries,
            )
        latest, _latest_mode = _read_regular_at(parent_fd, target)
        if hashlib.sha256(latest).hexdigest() != expected:
            return _emit(
                "precondition_failed",
                "target changed before replace effect",
                cleanup=cleanup_entries,
            )
        target_identity = _entry_identity_at(parent_fd, target)
        try:
            _renameat2(parent_fd, candidate, parent_fd, target, RENAME_EXCHANGE)
        except FileNotFoundError:
            return _emit(
                "precondition_failed",
                "target disappeared before replace effect",
                cleanup=cleanup_entries,
            )
        effect_occurred = True
        recoveries.append(candidate)
        cleanup_entries.clear()
        try:
            displaced, _displaced_mode = _read_regular_at(parent_fd, candidate)
            current, _current_mode = _read_regular_at(parent_fd, target)
            if hashlib.sha256(displaced).hexdigest() != expected:
                raise OSError(errno.ESTALE, "a concurrent target was displaced")
            if _entry_identity_at(parent_fd, candidate) != target_identity:
                raise OSError(errno.ESTALE, "a different target inode was displaced")
            if hashlib.sha256(current).hexdigest() != hashlib.sha256(raw).hexdigest():
                raise OSError(errno.ESTALE, "replacement target changed after exchange")
            if not _parent_identity_matches(relative, parent_fd):
                raise OSError(errno.ESTALE, "target parent changed after replace")
            os.fsync(parent_fd)
        except OSError as exc:
            return _emit(
                "uncertain",
                f"replace effect requires inspection: {exc}",
                recoveries=recoveries,
                effect_occurred=True,
            )
        os.fsync(parent_fd)
        return _emit(
            "succeeded",
            cleanup=[
                {"name": candidate, "dev": target_identity[0], "ino": target_identity[1]},
                recovery_entry,
            ],
            effect_occurred=True,
        )
    except OSError as exc:
        if effect_occurred:
            return _emit(
                "uncertain",
                f"write effect requires inspection: {exc}",
                recoveries=[name for name in (recovery, candidate) if name],
                effect_occurred=True,
            )
        if created:
            return _emit(
                "uncertain",
                f"conditional write stopped after creating parent state: {exc.strerror or exc}",
                recoveries=[item["name"] for item in cleanup_entries],
            )
        return _emit(
            "precondition_failed",
            f"conditional write refused: {exc.strerror or exc}",
            cleanup=cleanup_entries,
        )
    finally:
        _close_descriptors(descriptors)


def _delete(
    relative: str,
    expected: str,
    operation_id: str,
    parent_guard: list[tuple[int, int] | None] | None = None,
) -> int:
    descriptors: list[int] = []
    recovery = ""
    removed = ""
    cleanup_entries: list[dict[str, object]] = []
    effect_occurred = False
    try:
        descriptors, parent_fd, target, _created = _open_parent(
            relative,
            create=False,
            guard=parent_guard,
        )
        removed, recovery = _temp_names(target, operation_id)
        before, before_mode = _read_regular_at(parent_fd, target)
        if hashlib.sha256(before).hexdigest() != expected:
            return _emit("precondition_failed", "target bytes do not match expected SHA-256")
        recovery_entry = _write_temp_at(parent_fd, recovery, before, before_mode, cleanup_entries)
        if not _parent_identity_matches(relative, parent_fd):
            return _emit(
                "precondition_failed",
                "target parent changed before delete",
                cleanup=cleanup_entries,
            )
        latest, _latest_mode = _read_regular_at(parent_fd, target)
        if hashlib.sha256(latest).hexdigest() != expected:
            return _emit(
                "precondition_failed",
                "target changed before delete effect",
                cleanup=cleanup_entries,
            )
        target_identity = _entry_identity_at(parent_fd, target)
        try:
            _renameat2(parent_fd, target, parent_fd, removed, RENAME_NOREPLACE)
        except FileNotFoundError:
            return _emit(
                "precondition_failed",
                "target disappeared before delete effect",
                cleanup=cleanup_entries,
            )
        effect_occurred = True
        recoveries = [recovery, removed]
        cleanup_entries.clear()
        try:
            displaced, _mode = _read_regular_at(parent_fd, removed)
            if hashlib.sha256(displaced).hexdigest() != expected:
                raise OSError(errno.ESTALE, "a concurrent target was removed")
            if _entry_identity_at(parent_fd, removed) != target_identity:
                raise OSError(errno.ESTALE, "a different target inode was removed")
            if _exists_at(parent_fd, target):
                raise OSError(errno.ESTALE, "target was recreated after delete")
            if not _parent_identity_matches(relative, parent_fd):
                raise OSError(errno.ESTALE, "target parent changed after delete")
            os.fsync(parent_fd)
        except OSError as exc:
            return _emit(
                "uncertain",
                f"delete effect requires inspection: {exc}",
                recoveries=recoveries,
                effect_occurred=True,
            )
        os.fsync(parent_fd)
        return _emit(
            "succeeded",
            cleanup=[
                {"name": removed, "dev": target_identity[0], "ino": target_identity[1]},
                recovery_entry,
            ],
            effect_occurred=True,
        )
    except OSError as exc:
        if effect_occurred:
            return _emit(
                "uncertain",
                f"delete effect requires inspection: {exc}",
                recoveries=[name for name in (recovery, removed) if name],
                effect_occurred=True,
            )
        return _emit(
            "precondition_failed",
            f"conditional delete refused: {exc.strerror or exc}",
            cleanup=cleanup_entries,
        )
    finally:
        _close_descriptors(descriptors)


def main() -> int:
    try:
        operation = sys.argv[1]
        relative = _relative(sys.argv[2])
        expected = sys.argv[3]
        guard = _parent_guard(sys.argv[4], relative)
        operation_id = _operation_id(sys.argv[5])
        if operation == "write":
            mode = int(sys.argv[6], 8)
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            return _write(relative, expected, mode, raw, operation_id, guard)
        if operation == "delete":
            return _delete(relative, expected, operation_id, guard)
        return _emit("precondition_failed", "unsupported helper operation")
    except (IndexError, ValueError, OSError) as exc:
        return _emit("precondition_failed", f"invalid helper request: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
