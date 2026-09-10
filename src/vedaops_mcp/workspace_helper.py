"""Trusted stdlib-only copier into Bubblewrap-provided tmpfs scratch."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

INPUT = Path("/input")
WORKSPACE = Path("/workspace")
CHUNK = 64 * 1024


def _copy_tree(source: Path, destination: Path) -> None:
    for current, directories, filenames, directory_fd in os.fwalk(
        source,
        topdown=True,
        follow_symlinks=False,
    ):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_dir = destination / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        directories.sort()
        filenames.sort()
        for directory in directories:
            info = os.stat(directory, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise OSError("snapshot contains an unsupported directory entry")
        for filename in filenames:
            info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise OSError("snapshot contains an unsupported file entry")
            descriptor = os.open(
                filename,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_dev != info.st_dev
                    or opened.st_ino != info.st_ino
                ):
                    raise OSError("snapshot file changed during workspace setup")
                target = target_dir / filename
                output = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    stat.S_IMODE(opened.st_mode) & 0o777,
                )
                try:
                    while True:
                        chunk = os.read(descriptor, CHUNK)
                        if not chunk:
                            break
                        view = memoryview(chunk)
                        written = 0
                        while written < len(view):
                            written += os.write(output, view[written:])
                finally:
                    os.close(output)
            finally:
                os.close(descriptor)


def main() -> int:
    try:
        separator = sys.argv.index("--", 1)
        command = sys.argv[separator + 1 :]
        if not command:
            raise ValueError("missing worker command")
        _copy_tree(INPUT, WORKSPACE)
        os.chdir(WORKSPACE)
        os.execv(command[0], command)
    except (OSError, ValueError, IndexError) as exc:
        print(f"workspace setup failed: {exc}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
