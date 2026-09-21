"""F008 authorization, catalog, subject binding, evidence, and isolation tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastmcp import Client

from vedaops_mcp.github_collab.allowlist import (
    PROHIBITED_TOOLS,
    PROVIDER_COMMIT,
    PROVIDER_FEATURE,
    PROVIDER_RELEASE,
    PROVIDER_TOOLS,
    catalog_fingerprint,
    catalog_rejection,
)
from vedaops_mcp.github_collab.entrypoints import main
from vedaops_mcp.github_collab.errors import (
    GitHubAuthorityError,
    GitHubPolicyError,
    GitHubProviderError,
)
from vedaops_mcp.github_collab.launcher import launch_plan, validate_artifact
from vedaops_mcp.github_collab.mcp_client import StdioGitHubProvider
from vedaops_mcp.github_collab.operations import (
    add_pull_request_comment,
    create_pull_request,
    read_actions,
    read_commit,
    read_identity,
    read_pull_request,
    request_reviewers,
    update_pull_request_title,
)
from vedaops_mcp.github_collab.policy import (
    authorize,
    load_policy,
    principal_from_environ,
)
from vedaops_mcp.github_collab.provider import (
    ProviderCallError,
    ProviderTransportError,
    parse_commit,
    parse_pull,
    parse_write,
    pull_number_from_url,
)
from vedaops_mcp.github_collab.server import build_github_server, tool_catalog
from vedaops_mcp.server import TOOL_CATALOG, build_server
from vedaops_mcp.settings import Settings

HEAD = "a" * 40
OTHER = "b" * 40
BASE = "c" * 40
CANARY = "ghp_CANARYTOKENVALUE1234567890"
PEM_CANARY = "CANARYSECRETVALUE1234567890"
PRINCIPAL = "project-steward"


class FakeGitHub:
    def __init__(self, journal: Path) -> None:
        self.journal = journal
        self.calls: list[object] = []
        self.version = PROVIDER_RELEASE
        self.tools = list(PROVIDER_TOOLS)
        self.head_sha = HEAD
        self.base_sha = BASE
        self.pulls: list[dict] = []
        self.comments: list[dict] = []
        self.reviews: list[dict] = []
        self.identity = {
            "login": "example-app[bot]",
            "id": 1,
            "profile_url": "https://github.com/apps/example-app",
            "unavailable": False,
            "detail": None,
        }
        self.transport_on: str | None = None
        self.reject_on: str | None = None
        self.seen_at_create: dict | None = None
        self.next_number = 7

    def catalog(self) -> tuple[str, ...]:
        return tuple(self.tools)

    def provider_version(self) -> str:
        return self.version

    def get_identity(self) -> dict:
        self.calls.append("get_identity")
        return dict(self.identity)

    def get_commit(self, owner: str, repo: str, ref: str) -> dict:
        self.calls.append(("get_commit", owner, repo, ref))
        sha = self.head_sha if ref == "feature" else self.base_sha if ref == "main" else ref
        return {
            "sha": sha,
            "html_url": f"https://github.com/{owner}/{repo}/commit/{sha}",
        }

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict:
        self.calls.append(("get_pull_request", number))
        if self.reject_on == "get_pull_request":
            raise ProviderCallError("status 404 pull request", effect_uncertain=False)
        for item in self.pulls:
            if item["number"] == number:
                return item
        raise ProviderCallError("status 404 pull request", effect_uncertain=False)

    def read_pull_request(
        self,
        owner: str,
        repo: str,
        number: int,
        method: str,
        page: int = 1,
        per_page: int = 30,
    ) -> object:
        self.calls.append(("read_pull_request", method, page, per_page))
        return {"method": method, "number": number, "owner": owner, "repo": repo}

    def list_pull_requests(
        self,
        owner: str,
        repo: str,
        *,
        head: str,
        base: str,
        state: str,
    ) -> list:
        self.calls.append(("list_pull_requests", head, base, state))
        return [
            item
            for item in self.pulls
            if item["state"] == state and item["head_ref"] == head.split(":", 1)[1]
        ]

    def list_comments(self, owner: str, repo: str, number: int) -> list:
        self.calls.append(("list_comments", number))
        return [item for item in self.comments if item["pull_number"] == number]

    def list_reviews(self, owner: str, repo: str, number: int) -> list:
        self.calls.append(("list_reviews", number))
        return list(self.reviews)

    def list_actions(
        self,
        owner: str,
        repo: str,
        method: str,
        resource_id: str | None,
        page: int = 1,
        per_page: int = 30,
    ) -> object:
        self.calls.append(("list_actions", method, resource_id, page, per_page))
        return {"method": method, "resource_id": resource_id}

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
    ) -> dict:
        self.calls.append("create_pull_request")
        records = sorted(self.journal.glob("*.json"))
        assert len(records) == 1
        self.seen_at_create = json.loads(records[0].read_text())
        if self.transport_on == "create":
            self._add_pull(owner, repo, title=title, body=body, head=head, base=base, draft=draft)
            raise ProviderTransportError("connection reset")
        if self.reject_on == "create":
            raise ProviderCallError("status 422 validation failed", effect_uncertain=False)
        pull = self._add_pull(
            owner, repo, title=title, body=body, head=head, base=base, draft=draft
        )
        return {"id": str(pull["number"]), "url": pull["html_url"]}

    def update_pull_request_title(self, owner: str, repo: str, number: int, title: str) -> dict:
        self.calls.append("update_pull_request_title")
        self._require_dispatched()
        if self.transport_on == "title":
            raise ProviderTransportError("connection reset")
        pull = self.get_pull_request(owner, repo, number)
        pull["title"] = title
        return {"id": str(number), "url": pull["html_url"]}

    def update_pull_request_body(self, owner: str, repo: str, number: int, body: str) -> dict:
        self.calls.append("update_pull_request_body")
        pull = self.get_pull_request(owner, repo, number)
        pull["body"] = body
        return {"id": str(number), "url": pull["html_url"]}

    def add_pull_request_comment(self, owner: str, repo: str, number: int, body: str) -> dict:
        self.calls.append(("add_pull_request_comment", body))
        self._require_dispatched()
        if self.transport_on == "comment":
            self.comments.append(
                {
                    "id": "55",
                    "body": body,
                    "html_url": f"https://github.com/{owner}/{repo}/pull/{number}#issuecomment-55",
                    "user_login": "example-app[bot]",
                    "created_at": "2099-01-01T00:00:00Z",
                    "pull_number": number,
                }
            )
            raise ProviderTransportError("connection reset")
        comment = {
            "id": "55",
            "body": body,
            "html_url": f"https://github.com/{owner}/{repo}/pull/{number}#issuecomment-55",
            "user_login": "example-app[bot]",
            "created_at": "2099-01-01T00:00:00Z",
            "pull_number": number,
        }
        self.comments.append(comment)
        return {"id": "55", "url": comment["html_url"]}

    def request_reviewers(self, owner: str, repo: str, number: int, reviewers: list[str]) -> dict:
        self.calls.append(("request_reviewers", tuple(reviewers)))
        pull = self.get_pull_request(owner, repo, number)
        pull["requested_reviewers"] = sorted(set(pull["requested_reviewers"]) | set(reviewers))
        return {"id": str(number), "url": pull["html_url"]}

    def _add_pull(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool,
    ) -> dict:
        pull = {
            "number": self.next_number,
            "title": title,
            "body": body,
            "state": "open",
            "draft": draft,
            "html_url": f"https://github.com/{owner}/{repo}/pull/{self.next_number}",
            "head_ref": head,
            "head_sha": self.head_sha,
            "base_ref": base,
            "base_sha": self.base_sha,
            "requested_reviewers": [],
            "user_login": "example-app[bot]",
        }
        self.next_number += 1
        self.pulls.append(pull)
        return pull

    def _require_dispatched(self) -> None:
        payloads = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in self.journal.glob("*.json")
        ]
        started = [
            item
            for item in payloads
            if item["state"] == "started" and item["effect_dispatched"] is True
        ]
        assert len(started) == 1


def _chmod(path: Path, mode: int) -> None:
    os.chmod(path, mode)


def _write_policy(
    root: Path,
    *,
    operations: list[str] | None = None,
    second_operations: list[str] | None = None,
    enabled: bool = True,
    private_key: Path | None = None,
    binary: Path | None = None,
    journal: Path | None = None,
    extra: str = "",
) -> Path:
    project_a = root / "projects" / "alpha"
    project_b = root / "projects" / "beta"
    project_a.mkdir(parents=True)
    project_b.mkdir(parents=True)
    _chmod(project_a, 0o755)
    _chmod(project_b, 0o755)
    journal_dir = journal or (root / "journal")
    journal_dir.mkdir(mode=0o700, exist_ok=True)
    _chmod(journal_dir, 0o700)
    key = private_key or (root / "secrets" / "app.pem")
    key.parent.mkdir(mode=0o700, exist_ok=True)
    _chmod(key.parent, 0o700)
    key.write_text(
        "-----BEGIN PRIVATE KEY-----\n" + PEM_CANARY + "\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    _chmod(key, 0o600)
    binary_path = binary or (root / "bin" / "github-mcp-server")
    binary_path.parent.mkdir(exist_ok=True)
    if not binary_path.exists():
        binary_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        _chmod(binary_path, 0o755)
    granted = operations or [
        "read",
        "pr_create",
        "pr_update_title",
        "pr_update_body",
        "pr_comment",
        "pr_request_reviewers",
    ]
    other = second_operations or ["read"]
    policy_path = root / "policy.toml"
    policy_path.write_text(
        f"""
schema_version = 1
enabled = {"true" if enabled else "false"}

[provider]
release = "{PROVIDER_RELEASE}"
commit = "{PROVIDER_COMMIT}"
artifact = "github-mcp-server_Linux_x86_64.tar.gz"
artifact_sha256 = "95843162759da2c31dde082dd145be35db82164594796c294414b69790c2290e"
api_version = "2022-11-28"
feature = "{PROVIDER_FEATURE}"
app_id = "123456"
installation_id = "7891011"
binary_path = "{binary_path}"
private_key_path = "{key}"
provider_login = "example-app[bot]"

[journal]
directory = "{journal_dir}"

[[projects]]
id = "alpha"
root = "{project_a}"
github_owner = "example-org"
github_repo = "alpha"

[[projects]]
id = "beta"
root = "{project_b}"
github_owner = "example-org"
github_repo = "beta"

[[principals]]
id = "{PRINCIPAL}"

[[principals.grants]]
project = "alpha"
operations = {json.dumps(granted)}

[[principals.grants]]
project = "beta"
operations = {json.dumps(other)}
{extra}
""",
        encoding="utf-8",
    )
    _chmod(policy_path, 0o600)
    return policy_path


def _policy(tmp_path: Path, **kwargs):
    path = _write_policy(tmp_path, **kwargs)
    return load_policy(path), path


def _journals(policy) -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(policy.journal_directory.glob("*.json"))
    ]


def test_authorized_grant_reaches_the_provider_and_wrong_targets_do_not(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    project = authorize(
        policy,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="Example-Org/alpha",
        operation="pr_create",
    )
    assert project.repository == "example-org/alpha"
    with pytest.raises(GitHubAuthorityError, match="VEDAOPS_GITHUB_REPOSITORY_DENIED"):
        authorize(
            policy,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/beta",
            operation="read",
        )
    with pytest.raises(GitHubAuthorityError, match="VEDAOPS_GITHUB_PROJECT_DENIED"):
        authorize(
            policy,
            principal_id=PRINCIPAL,
            project_id="gamma",
            github_repository="example-org/alpha",
            operation="read",
        )
    with pytest.raises(GitHubAuthorityError, match="VEDAOPS_GITHUB_OPERATION_DENIED"):
        authorize(
            policy,
            principal_id=PRINCIPAL,
            project_id="beta",
            github_repository="example-org/beta",
            operation="pr_create",
        )
    assert provider.calls == []


def test_unknown_operation_and_project_file_cannot_grant_authority(tmp_path: Path):
    with pytest.raises(GitHubPolicyError, match="unknown or prohibited"):
        _policy(tmp_path / "bad-op", operations=["read", "merge"])
    policy, path = _policy(tmp_path / "good")
    hostile = policy.project("alpha").root / ".vedaops" / "github.toml"
    hostile.parent.mkdir()
    hostile.write_text(
        (tmp_path / "good" / "policy.toml").read_text(encoding="utf-8").replace(
            'operations = ["read"]',
            'operations = ["read", "pr_create", "merge"]',
        ),
        encoding="utf-8",
    )
    hostile.write_text(
        hostile.read_text(encoding="utf-8")
        + '\nprivate_key_path = "'
        + str(policy.project("alpha").root / "stolen.pem")
        + '"\n',
        encoding="utf-8",
    )
    reloaded = load_policy(path)
    assert "pr_create" not in reloaded.operations_for(PRINCIPAL, "beta")
    assert "merge" not in reloaded.operations_for(PRINCIPAL, "alpha")
    assert reloaded.private_key_path == policy.private_key_path
    inside = policy.project("alpha").root / "self.toml"
    inside.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    _chmod(inside, 0o600)
    with pytest.raises(GitHubPolicyError, match="VEDAOPS_GITHUB_TRUSTED_PATH_INSIDE_PROJECT"):
        load_policy(inside)


def test_secret_path_inside_a_project_is_rejected(tmp_path: Path):
    policy, path = _policy(tmp_path)
    stolen = policy.project("alpha").root / "app.pem"
    stolen.write_text("not-a-real-key\n", encoding="utf-8")
    _chmod(stolen, 0o600)
    text = path.read_text(encoding="utf-8").replace(str(policy.private_key_path), str(stolen))
    path.write_text(text, encoding="utf-8")
    _chmod(path, 0o600)
    with pytest.raises(GitHubPolicyError, match="private key"):
        load_policy(path)


def test_catalog_accepts_only_the_pinned_surface():
    assert catalog_rejection(list(PROVIDER_TOOLS)) is None
    assert set(PROVIDER_TOOLS).isdisjoint(PROHIBITED_TOOLS)
    assert catalog_rejection([*PROVIDER_TOOLS, "merge_pull_request"]) is not None
    narrowed = [
        name for name in PROVIDER_TOOLS if name != "update_pull_request_title"
    ]
    assert "narrow provider tools" in (catalog_rejection(narrowed) or "")
    broad = [
        "update_pull_request" if name == "update_pull_request_title" else name
        for name in PROVIDER_TOOLS
    ]
    reason = catalog_rejection(broad) or ""
    assert "update_pull_request" in reason
    assert "merge_pull_request" in PROHIBITED_TOOLS
    assert "create_or_update_file" in PROHIBITED_TOOLS
    assert "push_files" in PROHIBITED_TOOLS
    assert "actions_run_trigger" in PROHIBITED_TOOLS
    assert "search_code" in PROHIBITED_TOOLS
    assert catalog_fingerprint()


def test_head_mismatch_blocks_create_and_records_the_observed_sha(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider.head_sha = OTHER
    result = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
    )
    assert result["outcome"] == "failed"
    assert result["code"] == "head_sha_mismatch"
    assert result["subject"]["observed_head_sha"] == OTHER
    assert result["subject"]["expected_head_sha"] == HEAD
    assert result["effect_dispatched"] is False
    assert "create_pull_request" not in provider.calls
    journal = _journals(policy)
    assert len(journal) == 1
    assert journal[0]["state"] == "failed"
    assert journal[0]["target"]["observed_head_sha"] == OTHER
    assert journal[0]["expected_source_sha"] == HEAD
    assert PEM_CANARY not in json.dumps(journal[0])


def test_commit_reads_are_observations_and_do_not_update_each_other(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    first = read_commit(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        ref="feature",
    )
    provider.head_sha = OTHER
    second = read_commit(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        ref="feature",
    )
    assert first["subject"]["observed_sha"] == HEAD
    assert second["subject"]["observed_sha"] == OTHER
    assert first["currency"] == "provider_observation"
    assert "later remote claim" in " ".join(first["limitations"])


def test_create_records_start_before_effect_and_success_after_reread(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    result = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title=f"Candidate {CANARY}",
    )
    assert provider.seen_at_create is not None
    assert provider.seen_at_create["state"] == "started"
    assert provider.seen_at_create["effect_dispatched"] is True
    assert provider.seen_at_create["kind"] == "pr_create"
    assert result["outcome"] == "succeeded"
    assert result["native"]["number"] == 7
    assert result["native"]["head_sha"] == HEAD
    assert result["product_acceptance"] is False
    assert CANARY not in json.dumps(result)
    assert "secret_like_text_redacted" in result["limitations"]
    journal = _journals(policy)[0]
    assert journal["state"] == "succeeded"
    assert journal["native_id"] == "7"
    assert journal["authorization_basis"].startswith("operator-policy:")
    assert PEM_CANARY not in json.dumps(journal)
    assert CANARY not in json.dumps(journal)
    assert provider.calls.count("create_pull_request") == 1


def test_lost_create_response_recovers_without_retry(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider.transport_on = "create"
    result = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
    )
    assert provider.calls.count("create_pull_request") == 1
    assert result["outcome"] == "uncertain"
    assert result["uncertainty"]["retry_performed"] is False
    assert result["uncertainty"]["may_have_occurred"] is True
    assert result["uncertainty"]["matching_state"] is True
    assert result["uncertainty"]["causality"] == "unproven"
    assert _journals(policy)[0]["state"] == "uncertain"


def test_lost_create_without_matching_state_stays_uncertain(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)

    def _raise_without_effect(*_args, **_kwargs):
        provider.calls.append("create_pull_request")
        records = list(provider.journal.glob("*.json"))
        provider.seen_at_create = json.loads(records[0].read_text())
        raise ProviderTransportError("connection reset")

    provider.create_pull_request = _raise_without_effect  # type: ignore[method-assign]
    result = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
    )
    assert provider.calls.count("create_pull_request") == 1
    assert result["outcome"] == "uncertain"
    assert result["uncertainty"]["matching_state"] is False
    assert result["uncertainty"]["retry_performed"] is False


def test_comment_requires_a_pull_request_and_uncertain_loss_does_not_retry(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider.reject_on = "get_pull_request"
    with pytest.raises(GitHubPolicyError, match="not an observable pull request"):
        add_pull_request_comment(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            number=7,
            body="hello",
        )
    comment_calls = [
        call
        for call in provider.calls
        if isinstance(call, tuple) and call[0] == "add_pull_request_comment"
    ]
    assert comment_calls == []
    provider.reject_on = None
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="",
        head="feature",
        base="main",
        draft=False,
    )
    posted = add_pull_request_comment(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body="noted",
    )
    assert posted["outcome"] == "succeeded"
    assert "Issues write" in " ".join(posted["limitations"])
    provider.transport_on = "comment"
    result = add_pull_request_comment(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body="hello",
    )
    assert result["outcome"] == "uncertain"
    assert result["uncertainty"]["causality"] == "unproven"
    assert result["uncertainty"]["retry_performed"] is False
    assert [call for call in provider.calls if call == ("add_pull_request_comment", "hello")] == [
        ("add_pull_request_comment", "hello")
    ]


def test_title_update_rereads_and_review_request_does_not_submit_review(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Old",
        body="body",
        head="feature",
        base="main",
        draft=False,
    )
    updated = update_pull_request_title(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        title="New title",
    )
    assert updated["outcome"] == "succeeded"
    assert updated["native"]["title"] == "New title"
    assert updated["subject"]["observed_head_sha"] == HEAD
    requested = request_reviewers(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        reviewers=["octocat"],
    )
    assert requested["outcome"] == "succeeded"
    assert requested["native"]["requested_reviewers"] == ["octocat"]
    provider.reviews = [
        {
            "id": "1",
            "state": "APPROVED",
            "body": "looks good",
            "html_url": "https://github.com/example-org/alpha/pull/7#pullrequestreview-1",
            "user_login": "example-app[bot]",
            "commit_id": HEAD,
        },
        {
            "id": "2",
            "state": "COMMENTED",
            "body": "question",
            "html_url": "https://github.com/example-org/alpha/pull/7#pullrequestreview-2",
            "user_login": "reviewer",
            "commit_id": HEAD,
        },
    ]
    reviews = read_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        method="get_reviews",
    )
    by_login = {item["user_login"]: item for item in reviews["native"]["reviews"]}
    assert by_login["example-app[bot]"]["independent"] is False
    assert by_login["reviewer"]["independent"] is True
    assert by_login["reviewer"]["product_acceptance"] is False


def test_actions_artifact_method_is_rejected_before_dispatch(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    with pytest.raises(GitHubPolicyError, match="actions method"):
        read_actions(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            method="list_workflow_run_artifacts",
        )
    assert provider.calls == []


def test_launch_plan_does_not_inherit_provider_overrides_or_key_material(tmp_path: Path):
    policy, path = _policy(tmp_path)
    plan = launch_plan(policy)
    assert "GITHUB_TOOLSETS" not in plan.env
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in plan.env
    assert "GITHUB_APP_PRIVATE_KEY" not in plan.env
    assert plan.env["GITHUB_FEATURES"] == PROVIDER_FEATURE
    assert plan.env["GITHUB_TOOLS"] == ",".join(PROVIDER_TOOLS)
    assert "--toolsets" not in " ".join(plan.argv)
    assert f"--features={PROVIDER_FEATURE}" in plan.argv
    rendered = main(["render-launch", "--policy", str(path)])
    assert rendered == 0
    assert PEM_CANARY not in json.dumps(plan.public_view())
    with pytest.raises(GitHubPolicyError, match="digest"):
        validate_artifact(path, "github-mcp-server_Linux_x86_64.tar.gz")


def test_stdio_client_rejects_a_widened_catalog_and_reads_a_pinned_one(tmp_path: Path):
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    good.write_text(_fake_server_script(list(PROVIDER_TOOLS), PROVIDER_RELEASE), encoding="utf-8")
    bad.write_text(
        _fake_server_script([*PROVIDER_TOOLS, "merge_pull_request"], PROVIDER_RELEASE),
        encoding="utf-8",
    )
    _chmod(good, 0o755)
    _chmod(bad, 0o755)
    good_policy, _path = _policy(tmp_path / "good-home", binary=good)
    provider = StdioGitHubProvider(good_policy)
    try:
        assert provider.provider_version() == PROVIDER_RELEASE
        assert catalog_rejection(list(provider.catalog())) is None
        commit = provider.get_commit("example-org", "alpha", HEAD)
        assert commit["sha"] == HEAD
    finally:
        provider.close()
    bad_policy, _path = _policy(tmp_path / "bad-home", binary=bad)
    with pytest.raises(GitHubProviderError, match="VEDAOPS_GITHUB_CATALOG_REJECTED"):
        StdioGitHubProvider(bad_policy)


def test_identity_reports_app_installation_without_calling_shadow_grants(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider.identity["unavailable"] = True
    provider.identity["login"] = None
    result = read_identity(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
    )
    assert result["native"]["app_id"] == "123456"
    assert result["native"]["installation_id"] == "7891011"
    assert "installation_token_may_have_no_user" in result["limitations"]
    with pytest.raises(GitHubPolicyError, match="VEDAOPS_GITHUB_IDENTITY_UNAVAILABLE"):
        principal_from_environ({"VEDAOPS_AGENT_ID": PRINCIPAL})
    assert principal_from_environ(
        {"VEDAOPS_AGENT_ID": "other-agent", "VEDAOPS_GITHUB_PRINCIPAL": PRINCIPAL}
    ) == PRINCIPAL


def test_disabled_boundary_does_not_add_tools_to_shadow(tmp_path: Path):
    policy, _path = _policy(tmp_path, enabled=False)
    assert tool_catalog(policy) == ("github_server_info",)
    info = None

    async def _list() -> list[str]:
        async with Client(build_github_server(policy, PRINCIPAL, None)) as client:
            tools = await client.list_tools()
            return [tool.name for tool in tools]

    names = pytest.importorskip("asyncio").run(_list())
    assert names == ["github_server_info"]
    core_source = Path(build_server.__code__.co_filename).read_text(encoding="utf-8")
    assert "github_collab" not in core_source
    assert set(TOOL_CATALOG).isdisjoint(set(tool_catalog(_policy(tmp_path / "enabled")[0])))
    assert info is None


def test_upstream_payload_parsers_and_cli_catalog(tmp_path: Path):
    commit = parse_commit(
        {"sha": HEAD, "html_url": f"https://github.com/example-org/alpha/commit/{HEAD}"}
    )
    assert commit["sha"] == HEAD
    pull = parse_pull(
        {
            "number": 7,
            "title": "Candidate",
            "body": "",
            "state": "open",
            "draft": False,
            "html_url": "https://github.com/example-org/alpha/pull/7",
            "head": {"ref": "feature", "sha": HEAD},
            "base": {"ref": "main", "sha": BASE},
            "requested_reviewers": ["octocat"],
            "user": {"login": "example-app[bot]"},
        }
    )
    assert pull["head_sha"] == HEAD
    write = parse_write({"id": "7", "url": "https://github.com/example-org/alpha/pull/7"})
    assert pull_number_from_url(write["url"]) == 7
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps({"tools": [{"name": name} for name in PROVIDER_TOOLS]}),
        encoding="utf-8",
    )
    assert main(["validate-catalog", str(catalog)]) == 0
    catalog.write_text(json.dumps(["merge_pull_request"]), encoding="utf-8")
    assert main(["validate-catalog", str(catalog)]) == 2


def test_provider_rejection_does_not_retry(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider.reject_on = "create"
    result = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
    )
    assert result["outcome"] == "failed"
    assert result["code"] == "provider_rejected"
    assert provider.calls.count("create_pull_request") == 1
    assert _journals(policy)[0]["state"] == "failed"
    assert _journals(policy)[0]["may_have_occurred"] is False


def _fake_server_script(tools: list[str], version: str) -> str:
    payload = json.dumps(tools)
    return f"""#!/usr/bin/env python3
import json
import sys

TOOLS = {payload}
VERSION = {version!r}

def send(message):
    sys.stdout.write(json.dumps(message) + "\\n")
    sys.stdout.flush()

while True:
    line = sys.stdin.readline()
    if not line:
        break
    message = json.loads(line)
    method = message.get("method")
    if method == "notifications/initialized":
        continue
    request_id = message.get("id")
    if method == "initialize":
        send({{
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {{
                "protocolVersion": "2024-11-05",
                "capabilities": {{"tools": {{}}}},
                "serverInfo": {{"name": "github-mcp-server", "version": VERSION}},
            }},
        }})
    elif method == "tools/list":
        send({{
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {{"tools": [{{"name": name}} for name in TOOLS]}},
        }})
    elif method == "tools/call" and message["params"]["name"] == "get_commit":
        body = json.dumps({{
            "sha": "{HEAD}",
            "html_url": "https://github.com/example-org/alpha/commit/{HEAD}",
        }})
        send({{
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {{"content": [{{"type": "text", "text": body}}], "isError": False}},
        }})
    else:
        send({{
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {{"code": -32601, "message": "unexpected tool"}},
        }})
"""


@pytest.mark.asyncio
async def test_f008_server_catalog_is_separate_from_shadow(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    async with Client(build_github_server(policy, PRINCIPAL, provider)) as client:
        tools = await client.list_tools()
        names = [tool.name for tool in tools]
        info = (await client.call_tool("github_server_info", {})).data
    assert names == list(tool_catalog(policy))
    assert "project_git_commit" not in names
    assert "merge_pull_request" not in names
    assert info["shadow_coupled"] is False
    assert info["issue_comment_permission"]["accepted_design_includes_issues_write"] is False
    assert info["provider_release"] == PROVIDER_RELEASE
    assert info["catalog_fingerprint"] == catalog_fingerprint()
    settings = Settings(principal_id="test-agent", registry_path=_shadow_registry(tmp_path))
    async with Client(build_server(settings)) as client:
        core_names = [tool.name for tool in await client.list_tools()]
    assert core_names == list(TOOL_CATALOG)
    assert set(core_names).isdisjoint(names)


def _shadow_registry(tmp_path: Path) -> Path:
    project = tmp_path / "shadow-project"
    project.mkdir()
    (project / ".git").mkdir()
    registry = tmp_path / "shadow-projects.toml"
    registry.write_text(
        f"""
schema_version = 1

[[projects]]
id = "shadow-project"
name = "Shadow Project"
status = "active"
root = "{project}"
workspace_id = "primary"
mutable = false
capabilities = ["read"]

[[principals]]
id = "test-agent"
projects = {{ "shadow-project" = ["read"] }}
""",
        encoding="utf-8",
    )
    return registry
