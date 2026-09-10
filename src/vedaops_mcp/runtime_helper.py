"""Trusted stdlib-only dependency copier for the confined runtime-capture mount."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

PROJECT = Path("/project")
SOURCE = PROJECT / ".venv"
TARGET = Path("/runtime")
CHUNK = 64 * 1024


class CaptureError(RuntimeError):
    pass


def _real_directory(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise CaptureError(f"{label} must be a real directory")


def _site_packages(venv_root: Path) -> Path:
    lib = venv_root / "lib"
    _real_directory(lib, "runtime lib")
    candidates: list[Path] = []
    for child in sorted(lib.iterdir()):
        info = child.lstat()
        if child.name.startswith("python") and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(
            info.st_mode
        ):
            site = child / "site-packages"
            try:
                site_info = site.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(site_info.st_mode) and not stat.S_ISLNK(site_info.st_mode):
                candidates.append(site)
    if len(candidates) != 1:
        raise CaptureError("runtime site-packages layout is unsupported")
    return candidates[0]


class Budget:
    def __init__(self, max_files: int, max_bytes: int, timeout_seconds: float) -> None:
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.deadline = time.monotonic() + timeout_seconds
        self.files = 0
        self.bytes = 0

    def checkpoint(self) -> None:
        if time.monotonic() > self.deadline:
            raise CaptureError("runtime capture exceeded its deadline")

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise CaptureError("runtime capture exceeded its file bound")

    def add_bytes(self, count: int) -> None:
        self.bytes += count
        if self.bytes > self.max_bytes:
            raise CaptureError("runtime capture exceeded its byte bound")


def _read_open_file(
    directory_fd: int,
    filename: str,
    expected: os.stat_result,
    budget: Budget,
) -> bytes:
    descriptor = os.open(
        filename,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
        ):
            raise CaptureError("runtime file changed during capture")
        raw = bytearray()
        while True:
            budget.checkpoint()
            remaining = budget.max_bytes - budget.bytes
            if remaining < 0:
                raise CaptureError("runtime capture exceeded its byte bound")
            chunk = os.read(descriptor, min(CHUNK, remaining + 1))
            if not chunk:
                break
            budget.add_bytes(len(chunk))
            raw.extend(chunk)
        final = os.fstat(descriptor)
        if final.st_dev != opened.st_dev or final.st_ino != opened.st_ino:
            raise CaptureError("runtime file identity changed during capture")
        if len(raw) != final.st_size:
            raise CaptureError("runtime file changed size during capture")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _copy_site(source_site: Path, target_site: Path, budget: Budget) -> None:
    for current, directories, filenames, directory_fd in os.fwalk(
        source_site,
        topdown=True,
        follow_symlinks=False,
    ):
        budget.checkpoint()
        current_path = Path(current)
        relative = current_path.relative_to(source_site)
        destination = target_site / relative
        destination.mkdir(parents=True, exist_ok=True)
        directories.sort()
        filenames.sort()
        for directory in directories:
            info = os.stat(directory, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CaptureError("runtime packages contain an unsupported directory entry")
        for filename in filenames:
            info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise CaptureError("runtime packages contain an unsupported file entry")
            budget.add_file()
            raw = _read_open_file(directory_fd, filename, info, budget)
            target = destination / filename
            target.write_bytes(raw)
            target.chmod(stat.S_IMODE(info.st_mode) & 0o777)


def _copy_executables(budget: Budget) -> None:
    source_bin = SOURCE / "bin"
    target_bin = TARGET / "bin"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(source_bin, flags)
    try:
        for filename in sorted(os.listdir(descriptor)):
            budget.checkpoint()
            target = target_bin / filename
            if filename in {"uv", "uvx"} or target.exists() or target.is_symlink():
                continue
            info = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise CaptureError("runtime bin contains an unsupported entry")
            if not info.st_mode & 0o111:
                continue
            budget.add_file()
            raw = _read_open_file(descriptor, filename, info, budget)
            first, separator, remainder = raw.partition(b"\n")
            if separator and first.startswith(b"#!") and b"python" in first.lower():
                raw = b"#!/workspace/.venv/bin/python\n" + remainder
            target.write_bytes(raw)
            target.chmod(stat.S_IMODE(info.st_mode) & 0o777)
    finally:
        os.close(descriptor)


def _rewrite_project_pth(host_project_root: Path, target_site: Path) -> None:
    root = Path(os.path.normpath(str(host_project_root)))
    for path in sorted(target_site.glob("*.pth")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise CaptureError("runtime path metadata must be a regular file")
        text = path.read_text(encoding="utf-8")
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


def main() -> int:
    try:
        host_root = Path(sys.argv[1])
        max_files = int(sys.argv[2])
        max_bytes = int(sys.argv[3])
        timeout_seconds = float(sys.argv[4])
        _real_directory(PROJECT, "project root")
        _real_directory(SOURCE, "project runtime")
        _real_directory(TARGET, "sanitized runtime")
        source_site = _site_packages(SOURCE)
        target_site = _site_packages(TARGET)
        if source_site.parent.name != target_site.parent.name:
            raise CaptureError(
                "project runtime Python version does not match trusted system Python"
            )
        budget = Budget(max_files, max_bytes, timeout_seconds)
        _copy_site(source_site, target_site, budget)
        _rewrite_project_pth(host_root, target_site)
        _copy_executables(budget)
        print(json.dumps({"files": budget.files, "bytes": budget.bytes}, separators=(",", ":")))
        return 0
    except (CaptureError, OSError, UnicodeDecodeError, ValueError, IndexError) as exc:
        print(json.dumps({"error": str(exc)[:1024]}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
