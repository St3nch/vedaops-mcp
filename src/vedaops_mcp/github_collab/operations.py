"""F008 collaboration operations.

Reads and writes go through the provider contract only after an operator grant
matches the project, repository, and operation class. A local Git ref is never
consulted. Product acceptance is not represented here.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from vedaops_mcp.github_collab.allowlist import (
    ACCEPTED_PROVIDER_VERSIONS,
    ACTIONS_LIST_METHODS,
    PULL_REQUEST_READ_METHODS,
    catalog_rejection,
)
from vedaops_mcp.github_collab.errors import GitHubPolicyError, GitHubProviderError
from vedaops_mcp.github_collab.evidence import GitHubJournal, start_github_operation
from vedaops_mcp.github_collab.permissions import ISSUE_COMMENT_PERMISSION
from vedaops_mcp.github_collab.policy import GitHubPolicy, GitHubProject, authorize
from vedaops_mcp.github_collab.provider import (
    CommentView,
    GitHubProvider,
    ProviderCallError,
    ProviderTransportError,
    PullView,
    url_repository,
)
from vedaops_mcp.github_collab.sanitize import scrub_payload, scrub_text

_SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_REVIEWER = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,99})?$"
)
_NOT_PRODUCT_ACCEPTANCE = "native GitHub state is not Product acceptance"


def read_identity(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="read",
    )
    limitations: list[str] = []
    try:
        identity = dict(provider.get_identity())
    except ProviderCallError as exc:
        identity = {
            "login": None,
            "id": None,
            "profile_url": None,
            "unavailable": True,
            "detail": _safe_detail(exc.detail),
        }
        limitations.append("authenticated_user_lookup_unavailable")
    if identity.get("unavailable"):
        limitations.append("installation_token_may_have_no_user")
    return _observation(
        kind="identity",
        project=project,
        repository=project.repository,
        outcome="succeeded",
        subject={"provider_login": identity.get("login")},
        native={
            "app_id": policy.app_id,
            "installation_id": policy.installation_id,
            "provider_release": policy.release,
            "provider_commit": policy.commit,
            "identity": identity,
        },
        limitations=limitations,
    )


def read_commit(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    ref: str,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="read",
    )
    branch_or_sha = _ref(ref)
    commit = provider.get_commit(project.owner, project.repo, branch_or_sha)
    return _commit_observation(project, commit, requested_ref=branch_or_sha)


def read_pull_request(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    number: int,
    method: str,
    page: int = 1,
    per_page: int = 30,
    after: str | None = None,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="read",
    )
    pull_number = _pull_number(number)
    _page(page, per_page)
    cursor = _review_cursor(method, page, after)
    if method not in PULL_REQUEST_READ_METHODS:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "pull request read method is not in the accepted read set",
        )
    if method == "get_reviews":
        reviews = provider.list_reviews(project.owner, project.repo, pull_number)
        annotated = [_annotate_review(policy, review) for review in reviews]
        return _observation(
            kind="pull_request_reviews",
            project=project,
            repository=project.repository,
            outcome="succeeded",
            subject={"pull_number": pull_number},
            native={"reviews": annotated},
            limitations=[
                "a review author matching the provider login is not an independent reviewer",
                "review state is not Product acceptance",
            ],
        )
    payload = provider.read_pull_request(
        project.owner,
        project.repo,
        pull_number,
        method,
        page,
        per_page,
        cursor,
    )
    subject: dict[str, Any] = {"pull_number": pull_number, "method": method}
    limitations = ["this observation is current only at observed_at"]
    if method == "get_review_comments":
        subject["after"] = cursor
        limitations.append(
            "review threads use cursor pagination; pass after, not an ordinary page number"
        )
        if _has_next_cursor_page(payload):
            limitations.append("additional review-thread pages were not read")
    if method == "get" and isinstance(payload, dict):
        subject["head_sha"] = payload.get("head_sha") or _nested_sha(payload, "head")
        subject["base_sha"] = payload.get("base_sha") or _nested_sha(payload, "base")
    return _observation(
        kind="pull_request_read",
        project=project,
        repository=project.repository,
        outcome="succeeded",
        subject=subject,
        native=payload,
        limitations=limitations,
    )


def read_actions(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    method: str,
    resource_id: str | None = None,
    page: int = 1,
    per_page: int = 30,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="read",
    )
    _page(page, per_page)
    if method not in ACTIONS_LIST_METHODS:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "actions method is not in the accepted read set",
        )
    if resource_id is not None and (
        not isinstance(resource_id, str) or not resource_id or len(resource_id) > 256
    ):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "actions resource id is invalid",
        )
    payload = provider.list_actions(
        project.owner,
        project.repo,
        method,
        resource_id,
        page,
        per_page,
    )
    return _observation(
        kind="actions_list",
        project=project,
        repository=project.repository,
        outcome="succeeded",
        subject={"method": method, "resource_id": resource_id},
        native=payload,
        limitations=["workflow evidence is not Product acceptance"],
    )


def create_pull_request(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    head: str,
    base: str,
    expected_head_sha: str,
    title: str,
    body: str = "",
    draft: bool = False,
    expected_base_sha: str | None = None,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="pr_create",
    )
    head_branch = _branch(head)
    base_branch = _branch(base)
    if head_branch == base_branch:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "head and base branches must differ",
        )
    expected = _sha(expected_head_sha)
    expected_base = _sha(expected_base_sha) if expected_base_sha is not None else None
    title_text = _title(title)
    body_text = _body(body, allow_empty=True)
    if not isinstance(draft, bool):
        raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "draft must be a boolean")
    head_commit = provider.get_commit(project.owner, project.repo, head_branch)
    base_commit = provider.get_commit(project.owner, project.repo, base_branch)
    head_sha = _require_live_sha(project, head_commit, ref=head_branch)
    base_sha = _require_live_sha(project, base_commit, ref=base_branch)
    intention = _intention(
        {
            "base": base_branch,
            "body": body_text,
            "draft": draft,
            "expected_base_sha": expected_base,
            "expected_head_sha": expected,
            "head": head_branch,
            "repository": project.repository,
            "title": title_text,
        }
    )
    target = {
        "base": base_branch,
        "draft": draft,
        "head": head_branch,
        "observed_base_sha": base_sha,
        "observed_head_sha": head_sha,
    }
    if head_sha != expected or (expected_base is not None and base_sha != expected_base):
        journal = _start(
            policy,
            project,
            principal_id,
            kind="pr_create",
            target=target,
            expected_source_sha=expected,
            intention=intention,
            operation="pr_create",
        )
        journal.terminal(
            "failed",
            detail="remote head or base SHA did not match the requested subject",
            outcome_code="head_sha_mismatch",
        )
        return _finished(
            journal,
            kind="pr_create",
            project=project,
            outcome="failed",
            subject=target | {"expected_head_sha": expected, "expected_base_sha": expected_base},
            native=None,
            limitations=[
                "pull request was not created",
                "local remote-tracking refs were not used",
            ],
            code="head_sha_mismatch",
        )
    existing = provider.list_pull_requests(
        project.owner,
        project.repo,
        head=f"{project.owner}:{head_branch}",
        base=base_branch,
        state="open",
    )
    same_head = [
        item
        for item in existing
        if item["head_ref"] == head_branch and item["state"] == "open"
    ]
    if same_head:
        matched = [
            item
            for item in same_head
            if _create_matches(
                item,
                expected_head_sha=expected,
                title=title_text,
                body=body_text,
                draft=draft,
                base_branch=base_branch,
                head_branch=head_branch,
            )
        ]
        if len(matched) == 1:
            return _observation(
                kind="pr_create",
                project=project,
                repository=project.repository,
                outcome="existing",
                subject=target | {"expected_head_sha": expected},
                native=_pull_native(matched[0]),
                limitations=[
                    "an open pull request already existed for this head and base",
                    "no create call was dispatched",
                    _NOT_PRODUCT_ACCEPTANCE,
                ],
            )
        journal = _start(
            policy,
            project,
            principal_id,
            kind="pr_create",
            target=target,
            expected_source_sha=expected,
            intention=intention,
            operation="pr_create",
        )
        journal.terminal("failed", detail="open pull request already exists for this head")
        return _finished(
            journal,
            kind="pr_create",
            project=project,
            outcome="failed",
            subject=target | {"expected_head_sha": expected},
            native=[_pull_native(item) for item in same_head],
            limitations=["pull request was not created"],
            code="open_pull_request_exists",
        )
    journal = _start(
        policy,
        project,
        principal_id,
        kind="pr_create",
        target=target,
        expected_source_sha=expected,
        intention=intention,
        operation="pr_create",
    )
    try:
        journal.mark_dispatched()
        written = provider.create_pull_request(
            project.owner,
            project.repo,
            title=title_text,
            body=body_text,
            head=head_branch,
            base=base_branch,
            draft=draft,
        )
    except (ProviderTransportError, ProviderCallError) as exc:
        uncertain = isinstance(exc, ProviderTransportError) or (
            isinstance(exc, ProviderCallError) and exc.effect_uncertain
        )
        if not uncertain:
            return _fail_response(journal, project, "pr_create", target, exc)
        return _recover_create(
            journal,
            provider,
            project,
            target=target,
            expected_head_sha=expected,
            title=title_text,
            body=body_text,
            draft=draft,
            base_branch=base_branch,
            head_branch=head_branch,
            reason=_safe_detail(str(exc)),
        )
    number = _write_pull_number(written["url"], project.repository)
    if number is None:
        return _recover_create(
            journal,
            provider,
            project,
            target=target,
            expected_head_sha=expected,
            title=title_text,
            body=body_text,
            draft=draft,
            base_branch=base_branch,
            head_branch=head_branch,
            reason="provider create result did not identify a pull request number",
        )
    try:
        observed = provider.get_pull_request(project.owner, project.repo, number)
    except (ProviderTransportError, ProviderCallError) as exc:
        return _recover_create(
            journal,
            provider,
            project,
            target=target,
            expected_head_sha=expected,
            title=title_text,
            body=body_text,
            draft=draft,
            base_branch=base_branch,
            head_branch=head_branch,
            reason=_safe_detail(str(exc)),
        )
    if not _create_matches(
        observed,
        expected_head_sha=expected,
        title=title_text,
        body=body_text,
        draft=draft,
        base_branch=base_branch,
        head_branch=head_branch,
    ):
        journal.terminal(
            "uncertain",
            may_have_occurred=True,
            native_id=written["id"],
            native_url=written["url"],
            observed_after=_pull_subject(observed),
            detail="post-write pull request did not match the intended subject",
        )
        return _uncertain(
            journal,
            project,
            "pr_create",
            subject=target | _pull_subject(observed),
            native=_pull_native(observed),
            matching_state=False,
            reason="post-write observation did not match the intended pull request",
        )
    limitations = [
        _NOT_PRODUCT_ACCEPTANCE,
        "GitHub does not provide compare-and-swap for this write",
    ]
    if observed["head_sha"].lower() != head_sha:
        limitations.append("head SHA changed between pre-write and post-write reads")
    journal.terminal(
        "succeeded",
        native_id=str(observed["number"]),
        native_url=observed["html_url"],
        observed_after=_pull_subject(observed),
    )
    return _finished(
        journal,
        kind="pr_create",
        project=project,
        outcome="succeeded",
        subject=target | _pull_subject(observed),
        native=_pull_native(observed),
        limitations=limitations,
    )


def update_pull_request_title(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    number: int,
    title: str,
) -> dict[str, Any]:
    return _update_text(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        number=number,
        operation="pr_update_title",
        field="title",
        value=_title(title),
    )


def update_pull_request_body(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    number: int,
    body: str,
) -> dict[str, Any]:
    return _update_text(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        number=number,
        operation="pr_update_body",
        field="body",
        value=_body(body, allow_empty=True),
    )


def add_pull_request_comment(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    number: int,
    body: str,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="pr_comment",
    )
    pull_number = _pull_number(number)
    comment_body = _body(body, allow_empty=False)
    try:
        current = provider.get_pull_request(project.owner, project.repo, pull_number)
    except ProviderCallError as exc:
        if exc.effect_uncertain:
            raise GitHubProviderError(
                "VEDAOPS_GITHUB_PROVIDER_UNAVAILABLE",
                "pull request identity could not be read before commenting",
            ) from exc
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "comment target is not an observable pull request",
        ) from exc
    intention = _intention({"body": comment_body, "pull_number": pull_number})
    target = {"pull_number": pull_number, **_pull_subject(current)}
    journal = _start(
        policy,
        project,
        principal_id,
        kind="pr_comment",
        target=target,
        expected_source_sha=current["head_sha"],
        intention=intention,
        operation="pr_comment",
    )
    try:
        journal.mark_dispatched()
        written = provider.add_pull_request_comment(
            project.owner,
            project.repo,
            pull_number,
            comment_body,
        )
    except (ProviderTransportError, ProviderCallError) as exc:
        uncertain = isinstance(exc, ProviderTransportError) or (
            isinstance(exc, ProviderCallError) and exc.effect_uncertain
        )
        if not uncertain:
            return _fail_response(journal, project, "pr_comment", target, exc)
        return _recover_comment(
            journal,
            provider,
            project,
            pull_number=pull_number,
            body=comment_body,
            reason=_safe_detail(str(exc)),
        )
    try:
        comments = provider.list_comments(project.owner, project.repo, pull_number)
    except (ProviderTransportError, ProviderCallError) as exc:
        return _recover_comment(
            journal,
            provider,
            project,
            pull_number=pull_number,
            body=comment_body,
            reason=_safe_detail(str(exc)),
        )
    matched = [
        item
        for item in comments
        if item["id"] == written["id"] and item["body"] == comment_body
    ]
    if len(matched) != 1:
        return _recover_comment(
            journal,
            provider,
            project,
            pull_number=pull_number,
            body=comment_body,
            reason="comment id returned by the provider was not observed afterward",
            comments=comments,
        )
    journal.terminal(
        "succeeded",
        native_id=matched[0]["id"],
        native_url=matched[0]["html_url"],
        observed_after={"pull_number": pull_number, "comment_id": matched[0]["id"]},
    )
    return _finished(
        journal,
        kind="pr_comment",
        project=project,
        outcome="succeeded",
        subject=target | {"comment_id": matched[0]["id"]},
        native=matched[0],
        limitations=[
            _NOT_PRODUCT_ACCEPTANCE,
            ISSUE_COMMENT_PERMISSION["reason"],
        ],
    )


def request_reviewers(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    number: int,
    reviewers: list[str],
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation="pr_request_reviewers",
    )
    pull_number = _pull_number(number)
    requested = _reviewers(reviewers)
    current = provider.get_pull_request(project.owner, project.repo, pull_number)
    intention = _intention({"pull_number": pull_number, "reviewers": requested})
    target = {"pull_number": pull_number, "reviewers": requested, **_pull_subject(current)}
    journal = _start(
        policy,
        project,
        principal_id,
        kind="pr_request_reviewers",
        target=target,
        expected_source_sha=current["head_sha"],
        intention=intention,
        operation="pr_request_reviewers",
    )
    try:
        journal.mark_dispatched()
        written = provider.request_reviewers(
            project.owner,
            project.repo,
            pull_number,
            requested,
        )
    except (ProviderTransportError, ProviderCallError) as exc:
        uncertain = isinstance(exc, ProviderTransportError) or (
            isinstance(exc, ProviderCallError) and exc.effect_uncertain
        )
        if not uncertain:
            return _fail_response(journal, project, "pr_request_reviewers", target, exc)
        return _recover_reviewers(
            journal,
            provider,
            project,
            pull_number,
            requested,
            _safe_detail(str(exc)),
        )
    try:
        observed = provider.get_pull_request(project.owner, project.repo, pull_number)
    except (ProviderTransportError, ProviderCallError) as exc:
        return _recover_reviewers(
            journal,
            provider,
            project,
            pull_number,
            requested,
            _safe_detail(str(exc)),
        )
    if not set(requested) <= set(observed["requested_reviewers"]):
        journal.terminal(
            "uncertain",
            may_have_occurred=True,
            native_id=written["id"],
            native_url=written["url"],
            observed_after=_pull_subject(observed),
            detail="requested reviewers were not all present after the write",
        )
        return _uncertain(
            journal,
            project,
            "pr_request_reviewers",
            subject=target | _pull_subject(observed),
            native=_pull_native(observed),
            matching_state=False,
            reason="post-write reviewer list did not contain every requested reviewer",
        )
    journal.terminal(
        "succeeded",
        native_id=str(observed["number"]),
        native_url=observed["html_url"],
        observed_after=_pull_subject(observed)
        | {"requested_reviewers": observed["requested_reviewers"]},
    )
    return _finished(
        journal,
        kind="pr_request_reviewers",
        project=project,
        outcome="succeeded",
        subject=target | _pull_subject(observed),
        native=_pull_native(observed),
        limitations=[
            _NOT_PRODUCT_ACCEPTANCE,
            "requesting a reviewer does not submit a review",
            "GitHub does not provide compare-and-swap for this write",
        ],
    )


def _update_text(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    number: int,
    operation: str,
    field: str,
    value: str,
) -> dict[str, Any]:
    project = _prepare(
        policy,
        provider,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation=operation,
    )
    pull_number = _pull_number(number)
    current = provider.get_pull_request(project.owner, project.repo, pull_number)
    intention = _intention({field: value, "pull_number": pull_number})
    target = {"pull_number": pull_number, field: value, **_pull_subject(current)}
    journal = _start(
        policy,
        project,
        principal_id,
        kind=operation,
        target=target,
        expected_source_sha=current["head_sha"],
        intention=intention,
        operation=operation,
    )
    try:
        journal.mark_dispatched()
        if field == "title":
            written = provider.update_pull_request_title(
                project.owner, project.repo, pull_number, value
            )
        else:
            written = provider.update_pull_request_body(
                project.owner, project.repo, pull_number, value
            )
    except (ProviderTransportError, ProviderCallError) as exc:
        uncertain = isinstance(exc, ProviderTransportError) or (
            isinstance(exc, ProviderCallError) and exc.effect_uncertain
        )
        if not uncertain:
            return _fail_response(journal, project, operation, target, exc)
        return _recover_text(
            journal,
            provider,
            project,
            pull_number,
            field,
            value,
            _safe_detail(str(exc)),
        )
    try:
        observed = provider.get_pull_request(project.owner, project.repo, pull_number)
    except (ProviderTransportError, ProviderCallError) as exc:
        return _recover_text(
            journal,
            provider,
            project,
            pull_number,
            field,
            value,
            _safe_detail(str(exc)),
        )
    if observed[field] != value:
        journal.terminal(
            "uncertain",
            may_have_occurred=True,
            native_id=written["id"],
            native_url=written["url"],
            observed_after=_pull_subject(observed),
            detail=f"post-write pull request {field} did not match",
        )
        return _uncertain(
            journal,
            project,
            operation,
            subject=target | _pull_subject(observed),
            native=_pull_native(observed),
            matching_state=False,
            reason=f"post-write {field} did not match the intended text",
        )
    limitations = [
        _NOT_PRODUCT_ACCEPTANCE,
        "GitHub does not provide compare-and-swap for this write",
    ]
    head_changed = observed["head_sha"].lower() != current["head_sha"].lower()
    base_changed = observed["base_sha"].lower() != current["base_sha"].lower()
    if head_changed or base_changed:
        limitations.append("head or base SHA changed between pre-write and post-write reads")
    journal.terminal(
        "succeeded",
        native_id=str(observed["number"]),
        native_url=observed["html_url"],
        observed_after=_pull_subject(observed),
    )
    return _finished(
        journal,
        kind=operation,
        project=project,
        outcome="succeeded",
        subject=target | _pull_subject(observed),
        native=_pull_native(observed),
        limitations=limitations,
    )


def _recover_create(
    journal: GitHubJournal,
    provider: GitHubProvider,
    project: GitHubProject,
    *,
    target: dict[str, Any],
    expected_head_sha: str,
    title: str,
    body: str,
    draft: bool,
    base_branch: str,
    head_branch: str,
    reason: str,
) -> dict[str, Any]:
    try:
        found = provider.list_pull_requests(
            project.owner,
            project.repo,
            head=f"{project.owner}:{head_branch}",
            base=base_branch,
            state="open",
        )
    except (ProviderTransportError, ProviderCallError) as exc:
        found = []
        reason = f"{reason}; follow-up read failed: {_safe_detail(str(exc))}"
    matched = [
        item
        for item in found
        if _create_matches(
            item,
            expected_head_sha=expected_head_sha,
            title=title,
            body=body,
            draft=draft,
            base_branch=base_branch,
            head_branch=head_branch,
        )
    ]
    journal.terminal(
        "uncertain",
        may_have_occurred=True,
        detail=reason[:500],
        observed_after=[_pull_subject(item) for item in matched],
    )
    return _uncertain(
        journal,
        project,
        "pr_create",
        subject=target,
        native=[_pull_native(item) for item in matched],
        matching_state=len(matched) == 1,
        reason=reason if len(matched) <= 1 else "more than one matching pull request was observed",
        conflicting=len(matched) > 1,
    )


def _recover_text(
    journal: GitHubJournal,
    provider: GitHubProvider,
    project: GitHubProject,
    pull_number: int,
    field: str,
    value: str,
    reason: str,
) -> dict[str, Any]:
    observed = None
    try:
        observed = provider.get_pull_request(project.owner, project.repo, pull_number)
        matching = observed[field] == value
    except (ProviderTransportError, ProviderCallError) as exc:
        matching = False
        reason = f"{reason}; follow-up read failed: {_safe_detail(str(exc))}"
    journal.terminal(
        "uncertain",
        may_have_occurred=True,
        detail=reason[:500],
        observed_after=_pull_subject(observed) if observed else None,
    )
    return _uncertain(
        journal,
        project,
        journal.payload["kind"],
        subject={"pull_number": pull_number, field: value},
        native=_pull_native(observed) if observed else None,
        matching_state=matching,
        reason=reason,
    )


def _recover_comment(
    journal: GitHubJournal,
    provider: GitHubProvider,
    project: GitHubProject,
    *,
    pull_number: int,
    body: str,
    reason: str,
    comments: list[CommentView] | None = None,
) -> dict[str, Any]:
    if comments is None:
        try:
            comments = provider.list_comments(project.owner, project.repo, pull_number)
        except (ProviderTransportError, ProviderCallError) as exc:
            comments = []
            reason = f"{reason}; follow-up read failed: {_safe_detail(str(exc))}"
    started = str(journal.payload.get("started_at", ""))
    matched = [
        item
        for item in comments
        if item["body"] == body and _not_before(item.get("created_at"), started)
    ]
    journal.terminal(
        "uncertain",
        may_have_occurred=True,
        detail=reason[:500],
        observed_comment_ids=[item["id"] for item in matched],
    )
    return _uncertain(
        journal,
        project,
        "pr_comment",
        subject={"pull_number": pull_number},
        native=matched,
        matching_state=len(matched) == 1,
        reason=reason if len(matched) <= 1 else "more than one matching comment was observed",
        conflicting=len(matched) > 1,
    )


def _recover_reviewers(
    journal: GitHubJournal,
    provider: GitHubProvider,
    project: GitHubProject,
    pull_number: int,
    reviewers: list[str],
    reason: str,
) -> dict[str, Any]:
    observed = None
    matching = False
    try:
        observed = provider.get_pull_request(project.owner, project.repo, pull_number)
        matching = set(reviewers) <= set(observed["requested_reviewers"])
    except (ProviderTransportError, ProviderCallError) as exc:
        reason = f"{reason}; follow-up read failed: {_safe_detail(str(exc))}"
    journal.terminal("uncertain", may_have_occurred=True, detail=reason[:500])
    return _uncertain(
        journal,
        project,
        "pr_request_reviewers",
        subject={"pull_number": pull_number, "reviewers": reviewers},
        native=_pull_native(observed) if observed else None,
        matching_state=matching,
        reason=reason,
    )


def _prepare(
    policy: GitHubPolicy,
    provider: GitHubProvider,
    *,
    principal_id: str,
    project_id: str,
    github_repository: str,
    operation: str,
) -> GitHubProject:
    project = authorize(
        policy,
        principal_id=principal_id,
        project_id=project_id,
        github_repository=github_repository,
        operation=operation,
    )
    version = provider.provider_version()
    if version not in ACCEPTED_PROVIDER_VERSIONS:
        raise GitHubProviderError(
            "VEDAOPS_GITHUB_CATALOG_REJECTED",
            f"provider version {version!r} is not the pinned GitHub MCP Server release",
        )
    reason = catalog_rejection(list(provider.catalog()))
    if reason is not None:
        raise GitHubProviderError("VEDAOPS_GITHUB_CATALOG_REJECTED", reason)
    return project


def _start(
    policy: GitHubPolicy,
    project: GitHubProject,
    principal_id: str,
    *,
    kind: str,
    target: dict[str, Any],
    expected_source_sha: str | None,
    intention: str,
    operation: str,
) -> GitHubJournal:
    return start_github_operation(
        policy,
        kind=kind,
        project=project,
        principal_id=principal_id,
        github_repository=project.repository,
        target=target,
        expected_source_sha=expected_source_sha,
        intention_sha256=intention,
        authorization_basis=(
            f"operator-policy:{policy.sha256}:principal:{principal_id}:"
            f"project:{project.id}:operation:{operation}"
        ),
    )


def _commit_observation(
    project: GitHubProject,
    commit: dict[str, str],
    *,
    requested_ref: str,
) -> dict[str, Any]:
    sha = commit["sha"].lower()
    if _SHA.fullmatch(sha) is None:
        raise GitHubProviderError(
            "VEDAOPS_GITHUB_PROVIDER_UNAVAILABLE",
            "provider commit SHA was not a Git SHA",
        )
    limitations = [
        "this SHA is the provider observation at observed_at, not a later remote claim"
    ]
    url = commit.get("html_url", "")
    observed_repository = url_repository(url) if url else None
    repository_conflict = (
        observed_repository is None
        or observed_repository.casefold() != project.repository.casefold()
    )
    if not url:
        limitations.append("commit URL was absent; identity is the authorized query target")
    elif repository_conflict:
        return _observation(
            kind="commit",
            project=project,
            repository=project.repository,
            outcome="failed",
            subject={"requested_ref": requested_ref, "observed_sha": sha},
            native={"html_url": url},
            limitations=["commit URL did not match the authorized repository"],
            code="repository_url_conflict",
        )
    return _observation(
        kind="commit",
        project=project,
        repository=project.repository,
        outcome="succeeded",
        subject={"requested_ref": requested_ref, "observed_sha": sha},
        native={"html_url": url},
        limitations=limitations,
    )


def _require_live_sha(project: GitHubProject, commit: dict[str, str], *, ref: str) -> str:
    observed = _commit_observation(project, commit, requested_ref=ref)
    if observed["outcome"] != "succeeded":
        raise GitHubProviderError(
            "VEDAOPS_GITHUB_PROVIDER_UNAVAILABLE",
            "live ref observation did not match the authorized repository",
        )
    return str(observed["subject"]["observed_sha"])


def _create_matches(
    item: PullView,
    *,
    expected_head_sha: str,
    title: str,
    body: str,
    draft: bool,
    base_branch: str,
    head_branch: str,
) -> bool:
    return (
        item["head_ref"] == head_branch
        and item["head_sha"].lower() == expected_head_sha
        and item["base_ref"] == base_branch
        and item["title"] == title
        and item["body"] == body
        and bool(item["draft"]) is bool(draft)
        and item["state"] == "open"
    )


def _pull_subject(item: PullView) -> dict[str, Any]:
    return {
        "pull_number": item["number"],
        "observed_head_sha": item["head_sha"].lower(),
        "observed_base_sha": item["base_sha"].lower(),
        "head_ref": item["head_ref"],
        "base_ref": item["base_ref"],
        "state": item["state"],
    }


def _pull_native(item: PullView) -> dict[str, Any]:
    return {
        "number": item["number"],
        "title": item["title"],
        "state": item["state"],
        "draft": item["draft"],
        "html_url": item["html_url"],
        "head_ref": item["head_ref"],
        "head_sha": item["head_sha"].lower(),
        "base_ref": item["base_ref"],
        "base_sha": item["base_sha"].lower(),
        "requested_reviewers": list(item["requested_reviewers"]),
        "user_login": item["user_login"],
    }


def _annotate_review(policy: GitHubPolicy, review: dict[str, Any]) -> dict[str, Any]:
    login = review.get("user_login")
    independent = None if policy.provider_login is None else login != policy.provider_login
    annotated = dict(review)
    annotated["independent"] = independent
    annotated["product_acceptance"] = False
    return annotated


def _write_pull_number(url: str, repository: str) -> int | None:
    observed = url_repository(url)
    if observed is None or observed.casefold() != repository.casefold():
        return None
    from vedaops_mcp.github_collab.provider import pull_number_from_url

    return pull_number_from_url(url)


def _fail_response(
    journal: GitHubJournal,
    project: GitHubProject,
    kind: str,
    subject: dict[str, Any],
    exc: ProviderCallError,
) -> dict[str, Any]:
    detail = _safe_detail(exc.detail)
    journal.terminal("failed", detail=detail, may_have_occurred=False)
    return _finished(
        journal,
        kind=kind,
        project=project,
        outcome="failed",
        subject=subject,
        native=None,
        limitations=["provider rejected the call before an uncertain effect was indicated"],
        code="provider_rejected",
    )


def _observation(
    *,
    kind: str,
    project: GitHubProject,
    repository: str,
    outcome: str,
    subject: dict[str, Any],
    native: object,
    limitations: list[str],
    code: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "outcome": outcome,
        "kind": kind,
        "project_id": project.id,
        "github_repository": repository,
        "observed_at": _now(),
        "currency": "provider_observation",
        "subject": subject,
        "native": native,
        "limitations": limitations,
        "product_acceptance": False,
    }
    if code is not None:
        payload["code"] = code
    return _scrubbed(payload)


def _finished(
    journal: GitHubJournal,
    *,
    kind: str,
    project: GitHubProject,
    outcome: str,
    subject: dict[str, Any],
    native: object,
    limitations: list[str],
    code: str | None = None,
) -> dict[str, Any]:
    payload = _observation(
        kind=kind,
        project=project,
        repository=project.repository,
        outcome=outcome,
        subject=subject,
        native=native,
        limitations=limitations,
        code=code,
    )
    payload["operation_id"] = journal.operation_id
    payload["effect_dispatched"] = bool(journal.payload.get("effect_dispatched"))
    return _scrubbed(payload)


def _uncertain(
    journal: GitHubJournal,
    project: GitHubProject,
    kind: str,
    *,
    subject: dict[str, Any],
    native: object,
    matching_state: bool,
    reason: str,
    conflicting: bool = False,
) -> dict[str, Any]:
    payload = _finished(
        journal,
        kind=str(kind),
        project=project,
        outcome="uncertain",
        subject=subject,
        native=native,
        limitations=[
            "an effect may have occurred",
            "the original invocation is not proven to have caused any matching state",
            "the write was not retried",
        ],
        code="recovery_required",
    )
    payload["uncertainty"] = {
        "may_have_occurred": True,
        "matching_state": matching_state,
        "causality": "unproven",
        "retry_performed": False,
        "conflicting": conflicting,
        "reason": _safe_detail(reason),
    }
    return _scrubbed(payload)


def _scrubbed(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned, redacted = scrub_payload(payload)
    if redacted and isinstance(cleaned, dict):
        limitations = list(cleaned.get("limitations") or [])
        if "secret_like_text_redacted" not in limitations:
            limitations.append("secret_like_text_redacted")
        cleaned["limitations"] = limitations
    return cleaned


def _intention(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _safe_detail(value: str) -> str:
    text, _redacted = scrub_text(value)
    return text[:500]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(value: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "SHA must be 40 or 64 lowercase hexadecimal characters",
        )
    return value


def _branch(value: str) -> str:
    if (
        not isinstance(value, str)
        or _BRANCH.fullmatch(value) is None
        or value.startswith("refs/")
        or ".." in value
        or "@{" in value
        or value.endswith("/")
        or value.endswith(".lock")
        or "//" in value
    ):
        raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "branch name is not accepted")
    return value


def _ref(value: str) -> str:
    if isinstance(value, str) and _SHA.fullmatch(value) is not None:
        return value
    return _branch(value)


def _title(value: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > 256:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "title must be 1 to 256 characters",
        )
    return value


def _body(value: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str) or len(value) > 16384 or (not allow_empty and not value):
        raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "body is empty or too large")
    return value


def _pull_number(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 1_000_000_000:
        raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "pull request number is invalid")
    return value


def _reviewers(value: list[str]) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 10:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "reviewers must contain 1 to 10 logins",
        )
    if len(value) != len(set(value)):
        raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "reviewers must be unique")
    for login in value:
        if not isinstance(login, str) or _REVIEWER.fullmatch(login) is None:
            raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "reviewer login is invalid")
    return list(value)


def _review_cursor(method: str, page: int, after: str | None) -> str | None:
    if method == "get_review_comments" and page != 1:
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "get_review_comments uses cursor pagination; pass after, not page",
        )
    if after is None:
        return None
    if method != "get_review_comments":
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "after is only valid for get_review_comments",
        )
    if (
        not isinstance(after, str)
        or not after
        or len(after) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in after)
    ):
        raise GitHubPolicyError(
            "VEDAOPS_GITHUB_SUBJECT_INVALID",
            "review-thread cursor is invalid",
        )
    return after


def _has_next_cursor_page(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    page_info = payload.get("pageInfo")
    if not isinstance(page_info, dict):
        return False
    return page_info.get("hasNextPage") is True


def _page(page: int, per_page: int) -> None:
    if (
        not isinstance(page, int)
        or isinstance(page, bool)
        or not isinstance(per_page, int)
        or isinstance(per_page, bool)
        or page < 1
        or not 1 <= per_page <= 100
    ):
        raise GitHubPolicyError("VEDAOPS_GITHUB_SUBJECT_INVALID", "pagination is outside 1..100")


def _nested_sha(payload: dict[str, Any], side: str) -> str | None:
    branch = payload.get(side)
    if isinstance(branch, dict) and isinstance(branch.get("sha"), str):
        return branch["sha"]
    return None


def _not_before(created_at: str | None, started_at: str) -> bool:
    if created_at is None or not started_at:
        return True
    return created_at >= started_at
