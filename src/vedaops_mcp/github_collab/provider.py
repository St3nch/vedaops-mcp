"""Provider contract and parsers for official GitHub MCP tool results.

Operations depend on this normalized contract. The stdio adapter is the only
code that interprets upstream payloads.
"""

from __future__ import annotations

import re
from typing import Protocol, TypedDict

_PULL_NUMBER = re.compile(r"/pull/(\d+)(?:$|[?#])")
_REPOSITORY = re.compile(r"https?://[^/]+/([^/]+)/([^/]+)/", re.IGNORECASE)


class ProviderTransportError(Exception):
    """A provider call was sent, or may have been sent, and no response came back."""


class ProviderCallError(Exception):
    """The provider answered, or the payload could not be interpreted."""

    def __init__(self, detail: str, *, effect_uncertain: bool) -> None:
        super().__init__(detail)
        self.detail = detail
        self.effect_uncertain = effect_uncertain


class CommitView(TypedDict):
    sha: str
    html_url: str


class PullView(TypedDict):
    number: int
    title: str
    body: str
    state: str
    draft: bool
    html_url: str
    head_ref: str
    head_sha: str
    base_ref: str
    base_sha: str
    requested_reviewers: list[str]
    user_login: str | None


class CommentView(TypedDict):
    id: str
    body: str
    html_url: str
    user_login: str | None
    created_at: str | None


class ReviewView(TypedDict):
    id: str
    state: str
    body: str
    html_url: str
    user_login: str | None
    commit_id: str | None


class WriteView(TypedDict):
    id: str
    url: str


class IdentityView(TypedDict):
    login: str | None
    id: str | None
    profile_url: str | None
    unavailable: bool
    detail: str | None


class GitHubProvider(Protocol):
    def catalog(self) -> tuple[str, ...]: ...

    def provider_version(self) -> str: ...

    def get_identity(self) -> IdentityView: ...

    def get_commit(self, owner: str, repo: str, ref: str) -> CommitView: ...

    def get_pull_request(self, owner: str, repo: str, number: int) -> PullView: ...

    def read_pull_request(
        self,
        owner: str,
        repo: str,
        number: int,
        method: str,
        page: int = 1,
        per_page: int = 30,
    ) -> object: ...

    def list_pull_requests(
        self,
        owner: str,
        repo: str,
        *,
        head: str,
        base: str,
        state: str,
    ) -> list[PullView]: ...

    def list_comments(self, owner: str, repo: str, number: int) -> list[CommentView]: ...

    def list_reviews(self, owner: str, repo: str, number: int) -> list[ReviewView]: ...

    def list_actions(
        self,
        owner: str,
        repo: str,
        method: str,
        resource_id: str | None,
        page: int = 1,
        per_page: int = 30,
    ) -> object: ...

    def create_pull_request(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool,
    ) -> WriteView: ...

    def update_pull_request_title(
        self,
        owner: str,
        repo: str,
        number: int,
        title: str,
    ) -> WriteView: ...

    def update_pull_request_body(
        self,
        owner: str,
        repo: str,
        number: int,
        body: str,
    ) -> WriteView: ...

    def add_pull_request_comment(
        self,
        owner: str,
        repo: str,
        number: int,
        body: str,
    ) -> WriteView: ...

    def request_reviewers(
        self,
        owner: str,
        repo: str,
        number: int,
        reviewers: list[str],
    ) -> WriteView: ...


def parse_commit(payload: object) -> CommitView:
    table = _table(payload, "commit observation")
    sha = table.get("sha")
    url = table.get("html_url", "")
    if not isinstance(sha, str) or not sha:
        raise ProviderCallError("commit observation omitted sha", effect_uncertain=True)
    if not isinstance(url, str):
        raise ProviderCallError("commit observation has a non-text html_url", effect_uncertain=True)
    return {"sha": sha, "html_url": url}


def parse_pull(payload: object) -> PullView:
    table = _table(payload, "pull request observation")
    number = table.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ProviderCallError("pull request observation omitted number", effect_uncertain=True)
    head = _table(table.get("head"), "pull request head")
    base = _table(table.get("base"), "pull request base")
    user = table.get("user")
    login = None
    if isinstance(user, dict) and isinstance(user.get("login"), str):
        login = user["login"]
    reviewers = table.get("requested_reviewers") or []
    if not isinstance(reviewers, list) or not all(isinstance(item, str) for item in reviewers):
        raise ProviderCallError(
            "pull request reviewers were not a list of logins",
            effect_uncertain=True,
        )
    return {
        "number": number,
        "title": _text(table.get("title"), "title"),
        "body": _text(table.get("body", ""), "body"),
        "state": _text(table.get("state"), "state"),
        "draft": bool(table.get("draft", False)),
        "html_url": _text(table.get("html_url", ""), "html_url"),
        "head_ref": _text(head.get("ref"), "head ref"),
        "head_sha": _text(head.get("sha"), "head sha"),
        "base_ref": _text(base.get("ref"), "base ref"),
        "base_sha": _text(base.get("sha"), "base sha"),
        "requested_reviewers": list(reviewers),
        "user_login": login,
    }


def parse_comments(payload: object) -> list[CommentView]:
    if not isinstance(payload, list):
        raise ProviderCallError("comment observation was not a list", effect_uncertain=True)
    comments: list[CommentView] = []
    for item in payload:
        table = _table(item, "comment")
        user = table.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        comment_id = table.get("id")
        comments.append(
            {
                "id": str(comment_id),
                "body": _text(table.get("body", ""), "comment body"),
                "html_url": _text(table.get("html_url", ""), "comment url"),
                "user_login": login if isinstance(login, str) else None,
                "created_at": table.get("created_at")
                if isinstance(table.get("created_at"), str)
                else None,
            }
        )
    return comments


def parse_reviews(payload: object) -> list[ReviewView]:
    if not isinstance(payload, list):
        raise ProviderCallError("review observation was not a list", effect_uncertain=True)
    reviews: list[ReviewView] = []
    for item in payload:
        table = _table(item, "review")
        user = table.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        reviews.append(
            {
                "id": str(table.get("id")),
                "state": _text(table.get("state", ""), "review state"),
                "body": _text(table.get("body", ""), "review body"),
                "html_url": _text(table.get("html_url", ""), "review url"),
                "user_login": login if isinstance(login, str) else None,
                "commit_id": table.get("commit_id")
                if isinstance(table.get("commit_id"), str)
                else None,
            }
        )
    return reviews


def parse_write(payload: object) -> WriteView:
    table = _table(payload, "provider write result")
    identifier = table.get("id")
    url = table.get("url")
    if not isinstance(identifier, str) or not identifier or not isinstance(url, str):
        raise ProviderCallError(
            "provider write result omitted id or url",
            effect_uncertain=True,
        )
    return {"id": identifier, "url": url}


def parse_identity(payload: object) -> IdentityView:
    table = _table(payload, "identity")
    login = table.get("login")
    identifier = table.get("id")
    profile = table.get("profile_url") or table.get("html_url")
    return {
        "login": login if isinstance(login, str) else None,
        "id": str(identifier) if isinstance(identifier, int | str) and identifier != "" else None,
        "profile_url": profile if isinstance(profile, str) else None,
        "unavailable": False,
        "detail": None,
    }


def pull_number_from_url(url: str) -> int | None:
    match = _PULL_NUMBER.search(url)
    if match is None:
        return None
    return int(match.group(1))


def url_repository(url: str) -> str | None:
    match = _REPOSITORY.search(url)
    if match is None:
        return None
    return f"{match.group(1)}/{match.group(2)}"


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProviderCallError(f"{label} was not an object", effect_uncertain=True)
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ProviderCallError(f"{label} was not text", effect_uncertain=True)
    return value
