"""Bounded orientation, tree/file/search reads, and native Git inspect."""

from __future__ import annotations

import fnmatch
import hashlib
import re
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict

from vedaops_mcp.authority import (
    AuthorizedProject,
    GitOrientation,
    Limitation,
    ProjectDetail,
    get_authorized_project,
    get_project_detail,
    load_registry,
    normalize_project_id,
    require_principal,
)
from vedaops_mcp.errors import AuthorityError, PolicyError, VedaOpsError
from vedaops_mcp.policy import (
    MAX_FILE_BYTES,
    MAX_GIT_RESULT_BYTES,
    bounded_text,
    decode_bounded_utf8,
    ensure_git_repository,
    ensure_not_ignored,
    literal_pathspec,
    normalize_relative,
    protected_reason,
    read_bounded_file,
    resolve_within_root,
    run_git_bytes,
    run_git_text,
)

MAX_TREE_ENTRIES = 1000
MAX_LISTED_FILES = 20000
MAX_SEARCH_FILES = 2000
MAX_SEARCH_RESULTS = 200
MAX_SEARCH_LINE_BYTES = 4096
MAX_COMPARE_FILES = 200
MAX_COMPARE_CAPTURE_BYTES = 1024 * 1024
MAX_CONTEXT_FILE_BYTES = 32 * 1024
MAX_CONTEXT_TOTAL_BYTES = 128 * 1024
ALLOWED_CONTEXT_SUFFIXES = frozenset({".md", ".txt"})
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class TreeEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    type: str
    size: int | None


class ProjectTreeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    root: str
    entries: list[TreeEntry]
    returned_count: int
    total_count: int
    skipped_count: int
    truncated: bool


class ProjectFileResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    path: str
    content: str
    sha256: str | None
    bytes_total: int
    bytes_returned: int
    truncated: bool


class SearchMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    line: int
    text: str
    truncated: bool


class ProjectSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    query: str
    matches: list[SearchMatch]
    returned_count: int
    files_searched: int
    skipped_count: int
    truncated: bool


class ContextDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    content: str
    bytes_total: int
    bytes_returned: int
    truncated: bool


class ProjectContextResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    root: str
    documents: list[ContextDocument]
    returned_count: int
    total_bytes: int
    returned_bytes: int
    truncated: bool


class GitStatusResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    git_head: str
    branch: str | None
    detached: bool
    clean: bool
    status: str
    hidden_entries: int
    bytes_returned: int
    truncated: bool


class GitChangedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    status: str
    additions: int | None
    deletions: int | None
    binary: bool


class GitCompareResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    workspace_id: str
    base_commit: str
    head_commit: str
    path: str | None
    files: list[GitChangedFile]
    returned_count: int
    excluded_count: int
    diff: str
    bytes_returned: int
    truncated: bool


def project_tree(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    path: str = "",
    max_entries: int = 500,
) -> ProjectTreeResult:
    """Return tracked and unignored project files beneath a relative path."""
    project = _readable_project(registry_path, principal_id, project_id)
    if not isinstance(max_entries, int) or isinstance(max_entries, bool):
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "max_entries must be an integer")
    if max_entries < 1 or max_entries > MAX_TREE_ENTRIES:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"max_entries must be between 1 and {MAX_TREE_ENTRIES}",
        )
    prefix = normalize_relative(path, allow_root=True)
    files, listing_truncated = _git_file_list(project.root)
    if prefix:
        prefix_with_slash = f"{prefix}/"
        files = [item for item in files if item == prefix or item.startswith(prefix_with_slash)]

    entries: dict[str, TreeEntry] = {}
    skipped = 0
    for item in files:
        try:
            item = normalize_relative(item)
        except PolicyError:
            skipped += 1
            continue
        if protected_reason(item) is not None:
            skipped += 1
            continue
        try:
            resolved = resolve_within_root(project.root, item, must_exist=True)
            size = resolved.stat().st_size
        except (VedaOpsError, OSError):
            skipped += 1
            continue
        parts = PurePosixPath(item).parts
        for index in range(1, len(parts)):
            directory = PurePosixPath(*parts[:index]).as_posix()
            entries.setdefault(directory, TreeEntry(path=directory, type="directory", size=None))
        entries[item] = TreeEntry(path=item, type="file", size=size)

    ordered = sorted(entries.values(), key=lambda entry: (entry.path, entry.type))
    total = len(ordered)
    page = ordered[:max_entries]
    return ProjectTreeResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        root=str(project.root),
        entries=page,
        returned_count=len(page),
        total_count=total,
        skipped_count=skipped,
        truncated=listing_truncated or total > len(page),
    )


def project_file_read(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    path: str,
    offset_bytes: int = 0,
    max_bytes: int = 64 * 1024,
) -> ProjectFileResult:
    """Read one bounded UTF-8 project file."""
    project = _readable_project(registry_path, principal_id, project_id)
    if (
        isinstance(offset_bytes, bool)
        or isinstance(max_bytes, bool)
        or not isinstance(offset_bytes, int)
        or not isinstance(max_bytes, int)
        or offset_bytes < 0
        or max_bytes < 1
        or max_bytes > MAX_FILE_BYTES
    ):
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"offset_bytes must be non-negative and max_bytes 1..{MAX_FILE_BYTES}",
        )
    normalized = normalize_relative(path)
    ensure_not_ignored(project.root, normalized)
    raw, info = read_bounded_file(
        project.root,
        normalized,
        offset_bytes=offset_bytes,
        limit_bytes=max_bytes,
    )
    chunk = raw[:max_bytes]
    content, returned = decode_bounded_utf8(chunk, may_end_mid_codepoint=len(raw) > max_bytes)
    sha256 = None
    if info.st_size <= MAX_FILE_BYTES:
        whole, whole_info = read_bounded_file(
            project.root,
            normalized,
            limit_bytes=MAX_FILE_BYTES,
        )
        if whole_info.st_size == info.st_size and len(whole) == whole_info.st_size:
            sha256 = hashlib.sha256(whole).hexdigest()
    return ProjectFileResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        path=normalized,
        content=content,
        sha256=sha256,
        bytes_total=info.st_size,
        bytes_returned=returned,
        truncated=offset_bytes + returned < info.st_size,
    )


def project_search(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    query: str,
    path: str = "",
    file_pattern: str = "*",
    max_results: int = 100,
) -> ProjectSearchResult:
    """Search tracked and unignored UTF-8 files for literal text."""
    project = _readable_project(registry_path, principal_id, project_id)
    normalized_query = query.strip() if isinstance(query, str) else ""
    if not normalized_query or len(normalized_query.encode()) > 4096:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "query must contain 1..4096 bytes")
    if (
        not isinstance(max_results, int)
        or isinstance(max_results, bool)
        or max_results < 1
        or max_results > MAX_SEARCH_RESULTS
    ):
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"max_results must be between 1 and {MAX_SEARCH_RESULTS}",
        )
    prefix = normalize_relative(path, allow_root=True)
    if not isinstance(file_pattern, str) or not file_pattern or len(file_pattern) > 200:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "file_pattern is invalid")
    if "\\" in file_pattern:
        raise PolicyError("VEDAOPS_INVALID_ARGUMENT", "file_pattern is invalid")

    prefix_with_slash = f"{prefix}/" if prefix else ""
    listed, truncated = _git_file_list(project.root)
    skipped = 0
    candidates: list[str] = []
    for item in listed:
        try:
            item = normalize_relative(item)
        except PolicyError:
            skipped += 1
            continue
        if prefix and item != prefix and not item.startswith(prefix_with_slash):
            continue
        if not fnmatch.fnmatch(PurePosixPath(item).name, file_pattern):
            continue
        if protected_reason(item) is not None:
            skipped += 1
            continue
        candidates.append(item)
    if len(candidates) > MAX_SEARCH_FILES:
        candidates = candidates[:MAX_SEARCH_FILES]
        truncated = True

    matches: list[SearchMatch] = []
    files_searched = 0
    for item in candidates:
        try:
            resolved = resolve_within_root(project.root, item, must_exist=True)
            if resolved.stat().st_size > MAX_FILE_BYTES:
                truncated = True
                continue
            raw, _info = read_bounded_file(project.root, item, limit_bytes=MAX_FILE_BYTES)
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        except (VedaOpsError, OSError):
            skipped += 1
            continue
        files_searched += 1
        for line_number, line in enumerate(content.splitlines(), start=1):
            if normalized_query not in line:
                continue
            encoded = line.encode()
            clipped = encoded[:MAX_SEARCH_LINE_BYTES]
            text, _ = decode_bounded_utf8(
                clipped,
                may_end_mid_codepoint=len(encoded) > len(clipped),
            )
            matches.append(
                SearchMatch(
                    path=item,
                    line=line_number,
                    text=text,
                    truncated=len(encoded) > len(clipped),
                )
            )
            if len(matches) >= max_results:
                truncated = True
                break
        if len(matches) >= max_results:
            break

    return ProjectSearchResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        query=normalized_query,
        matches=matches,
        returned_count=len(matches),
        files_searched=files_searched,
        skipped_count=skipped,
        truncated=truncated,
    )


def project_context_get(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
) -> ProjectContextResult:
    """Return operator-selected, bounded UTF-8 context documents."""
    project = _readable_project(registry_path, principal_id, project_id)
    remaining = MAX_CONTEXT_TOTAL_BYTES
    documents: list[ContextDocument] = []
    total_bytes = 0
    returned_bytes = 0
    for configured_path in project.context_files:
        relative_path = _validated_context_path(configured_path)
        budget = min(MAX_CONTEXT_FILE_BYTES, remaining)
        document = _read_context_document(project.root, relative_path, budget)
        documents.append(document)
        total_bytes += document.bytes_total
        returned_bytes += document.bytes_returned
        remaining -= document.bytes_returned
    return ProjectContextResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        root=str(project.root),
        documents=documents,
        returned_count=len(documents),
        total_bytes=total_bytes,
        returned_bytes=returned_bytes,
        truncated=any(document.truncated for document in documents),
    )


def project_git_status(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
) -> GitStatusResult:
    """Return bounded branch, HEAD, and porcelain status without protected paths."""
    project = _readable_project(registry_path, principal_id, project_id)
    observed = observe_git(project.root)
    if observed.state != "observed" or observed.git_head is None:
        limitation = observed.limitations[0] if observed.limitations else None
        code = limitation.code if limitation else "VEDAOPS_GIT_UNAVAILABLE"
        detail = limitation.detail if limitation else "Git state is unavailable"
        raise PolicyError(code, detail)
    raw = run_git_bytes(
        project.root,
        "status",
        "--porcelain=v1",
        "-z",
        "--no-renames",
        "--untracked-files=normal",
    )
    visible, hidden, total = _visible_status_entries(raw)
    text, returned, truncated = bounded_text(
        ("\n".join(visible) + "\n" if visible else "").encode("utf-8"),
        MAX_GIT_RESULT_BYTES,
    )
    return GitStatusResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        git_head=observed.git_head,
        branch=observed.branch,
        detached=bool(observed.detached),
        clean=total == 0,
        status=text,
        hidden_entries=hidden,
        bytes_returned=returned,
        truncated=truncated,
    )


def project_git_compare(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
    base_commit: str,
    head_commit: str,
    path: str | None = None,
) -> GitCompareResult:
    """Compare two exact commits without exposing protected paths."""
    project = _readable_project(registry_path, principal_id, project_id)
    base = _validated_commit(project.root, base_commit, argument="base_commit")
    head = _validated_commit(project.root, head_commit, argument="head_commit")

    normalized_path: str | None = None
    if path is not None:
        normalized_path = normalize_relative(path)
        reason = protected_reason(normalized_path)
        if reason is not None:
            raise PolicyError("VEDAOPS_PATH_FORBIDDEN", f"{normalized_path} is a {reason}")

    name_args = ["diff", "--name-status", "-z", "--no-renames", base, head]
    if normalized_path is not None:
        name_args.extend(["--", literal_pathspec(normalized_path)])
    raw_names = run_git_bytes(project.root, *name_args, limit_bytes=MAX_COMPARE_CAPTURE_BYTES)
    named = _parse_name_status(raw_names)

    selected: list[tuple[str, str]] = []
    excluded = 0
    for status, name in named:
        try:
            normalized = normalize_relative(name)
        except PolicyError:
            excluded += 1
            continue
        if protected_reason(normalized) is not None:
            excluded += 1
            continue
        selected.append((status, normalized))
    if len(selected) > MAX_COMPARE_FILES:
        raise PolicyError(
            "VEDAOPS_GIT_OUTPUT_TOO_LARGE",
            f"commit comparison exceeds {MAX_COMPARE_FILES} visible files",
        )

    if not selected:
        return GitCompareResult(
            project_id=project.id,
            workspace_id=project.workspace_id,
            base_commit=base,
            head_commit=head,
            path=normalized_path,
            files=[],
            returned_count=0,
            excluded_count=excluded,
            diff="",
            bytes_returned=0,
            truncated=False,
        )

    paths = [name for _status, name in selected]
    numstat = run_git_bytes(
        project.root,
        "diff",
        "--numstat",
        "-z",
        "--no-renames",
        base,
        head,
        "--",
        *(literal_pathspec(name) for name in paths),
        limit_bytes=MAX_COMPARE_CAPTURE_BYTES,
    )
    statistics = _parse_numstat(numstat)
    if set(statistics) != set(paths):
        raise PolicyError(
            "VEDAOPS_GIT_UNAVAILABLE",
            "Git name-status and numstat path sets did not agree",
        )
    files = [
        GitChangedFile(
            path=name,
            status=status,
            additions=statistics[name][0],
            deletions=statistics[name][1],
            binary=statistics[name][2],
        )
        for status, name in selected
    ]
    raw_diff = run_git_bytes(
        project.root,
        "diff",
        "--no-ext-diff",
        "--no-color",
        "--no-renames",
        "--unified=3",
        base,
        head,
        "--",
        *(literal_pathspec(name) for name in paths),
        limit_bytes=MAX_COMPARE_CAPTURE_BYTES,
    )
    content, returned, truncated = bounded_text(raw_diff, MAX_GIT_RESULT_BYTES)
    return GitCompareResult(
        project_id=project.id,
        workspace_id=project.workspace_id,
        base_commit=base,
        head_commit=head,
        path=normalized_path,
        files=files,
        returned_count=len(files),
        excluded_count=excluded,
        diff=content,
        bytes_returned=returned,
        truncated=truncated,
    )


def orient_project(
    registry_path: Path,
    *,
    principal_id: str,
    project_id: str,
) -> ProjectDetail:
    """Return project/workspace identity, permissions, and observed Git state."""
    registry = load_registry(registry_path)
    principal = require_principal(registry, principal_id)
    normalized_id = normalize_project_id(project_id)
    if normalized_id not in principal.projects:
        raise AuthorityError(
            "VEDAOPS_PROJECT_NOT_AUTHORIZED",
            f"project {normalized_id!r} is not authorized for this principal",
        )
    entry = next((item for item in registry.projects if item.id == normalized_id), None)
    if entry is None:
        raise AuthorityError(
            "VEDAOPS_PROJECT_NOT_AUTHORIZED",
            f"project {normalized_id!r} is not authorized for this principal",
        )
    git_orientation = observe_git(entry.root)
    return get_project_detail(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        git_orientation=git_orientation,
    )


def observe_git(root: Path) -> GitOrientation:
    """Observe native Git HEAD/branch/dirtiness without inventing Git state."""
    try:
        ensure_git_repository(root)
        head = run_git_text(root, "rev-parse", "HEAD")
        branch = (
            run_git_text(root, "symbolic-ref", "--short", "-q", "HEAD", allow_exit_1=True) or None
        )
        raw = run_git_bytes(
            root,
            "status",
            "--porcelain=v1",
            "-z",
            "--no-renames",
            "--untracked-files=normal",
        )
    except VedaOpsError as exc:
        return GitOrientation(
            state="unavailable",
            git_head=None,
            branch=None,
            detached=None,
            clean=None,
            hidden_entries=None,
            limitations=[Limitation(code=exc.code, detail=exc.detail)],
        )
    _visible, hidden, total = _visible_status_entries(raw)
    return GitOrientation(
        state="observed",
        git_head=head,
        branch=branch,
        detached=branch is None,
        clean=total == 0,
        hidden_entries=hidden,
        limitations=[],
    )


def _readable_project(registry_path: Path, principal_id: str, project_id: str) -> AuthorizedProject:
    project = get_authorized_project(
        registry_path,
        principal_id=principal_id,
        project_id=project_id,
        capability="read",
    )
    ensure_git_repository(project.root)
    return project


def _git_file_list(root: Path) -> tuple[list[str], bool]:
    raw = run_git_bytes(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    files: list[str] = []
    truncated = False
    for value in raw.split(b"\x00"):
        if not value:
            continue
        if len(files) >= MAX_LISTED_FILES:
            truncated = True
            break
        try:
            files.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            truncated = True
            continue
    return sorted(files), truncated


def _visible_status_entries(raw: bytes) -> tuple[list[str], int, int]:
    visible: list[str] = []
    hidden = 0
    total = 0
    for record in raw.split(b"\x00"):
        if not record:
            continue
        total += 1
        entry = record.decode("utf-8", errors="replace")
        candidate = entry[3:] if len(entry) > 3 else ""
        try:
            candidate = normalize_relative(candidate)
        except PolicyError:
            hidden += 1
            continue
        if protected_reason(candidate) is not None:
            hidden += 1
            continue
        visible.append(entry)
    return visible, hidden, total


def _validated_commit(root: Path, value: str, *, argument: str) -> str:
    normalized = value.strip().lower() if isinstance(value, str) else ""
    if GIT_COMMIT_PATTERN.fullmatch(normalized) is None:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"{argument} must be a full hexadecimal Git commit object ID",
        )
    try:
        actual = run_git_text(root, "rev-parse", "--verify", f"{normalized}^{{commit}}")
    except PolicyError as exc:
        if exc.code != "VEDAOPS_GIT_UNAVAILABLE":
            raise
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"{argument} must name an existing full commit object ID",
        ) from exc
    if actual != normalized:
        raise PolicyError(
            "VEDAOPS_INVALID_ARGUMENT",
            f"{argument} must identify a commit object directly",
        )
    return actual


def _parse_name_status(raw: bytes) -> list[tuple[str, str]]:
    values = raw.split(b"\x00")
    if values and values[-1] == b"":
        values.pop()
    if len(values) % 2:
        raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git name-status output was malformed")
    result: list[tuple[str, str]] = []
    for index in range(0, len(values), 2):
        try:
            status = values[index].decode("ascii")
            name = values[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git path output was not UTF-8") from exc
        if status not in {"A", "D", "M", "T"}:
            raise PolicyError("VEDAOPS_GIT_UNAVAILABLE", "Git returned an unsupported status")
        result.append((status, name))
    return result


def _parse_numstat(raw: bytes) -> dict[str, tuple[int | None, int | None, bool]]:
    result: dict[str, tuple[int | None, int | None, bool]] = {}
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            added, deleted, name = record.decode("utf-8").split("\t", 2)
        except (UnicodeDecodeError, ValueError) as exc:
            raise PolicyError(
                "VEDAOPS_GIT_UNAVAILABLE",
                "Git numstat output was malformed",
            ) from exc
        binary = added == "-" and deleted == "-"
        if binary:
            result[name] = (None, None, True)
            continue
        try:
            result[name] = (int(added), int(deleted), False)
        except ValueError as exc:
            raise PolicyError(
                "VEDAOPS_GIT_UNAVAILABLE",
                "Git numstat output was malformed",
            ) from exc
    return result


def _validated_context_path(configured_path: str) -> str:
    try:
        relative_path = normalize_relative(configured_path)
    except PolicyError as exc:
        raise PolicyError(
            "VEDAOPS_CONTEXT_PATH_INVALID",
            f"context path {configured_path!r} must be a normalized relative path",
        ) from exc
    suffix = PurePosixPath(relative_path).suffix.casefold()
    if suffix not in ALLOWED_CONTEXT_SUFFIXES:
        raise PolicyError(
            "VEDAOPS_CONTEXT_PATH_FORBIDDEN",
            f"context path {configured_path!r} is not an approved document type",
        )
    return relative_path


def _read_context_document(root: Path, relative_path: str, budget: int) -> ContextDocument:
    ensure_not_ignored(root, relative_path)
    raw, info = read_bounded_file(root, relative_path, limit_bytes=budget)
    chunk = raw[:budget]
    content, returned = decode_bounded_utf8(
        chunk,
        may_end_mid_codepoint=info.st_size > budget,
    )
    return ContextDocument(
        path=relative_path,
        content=content,
        bytes_total=info.st_size,
        bytes_returned=returned,
        truncated=info.st_size > returned,
    )
