"""F008 authorization, catalog, subject binding, evidence, and isolation tests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from fastmcp import Client

from vedaops_mcp.github_collab import policy as github_policy
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
from vedaops_mcp.github_collab.evidence import (
    MAX_OPERATION_RECORD_BYTES,
    GitHubJournal,
    assert_journal_states_fit,
    modeled_terminal_payloads,
    record_bytes,
)
from vedaops_mcp.github_collab.launcher import launch_plan, validate_artifact
from vedaops_mcp.github_collab.mcp_client import (
    StdioGitHubProvider,
    _explicit_no_effect,
    pull_request_read_arguments,
)
from vedaops_mcp.github_collab.operations import (
    add_pull_request_comment,
    create_pull_request,
    read_actions,
    read_commit,
    read_identity,
    read_pull_request,
    request_reviewers,
    update_pull_request_body,
    update_pull_request_title,
)
from vedaops_mcp.github_collab.policy import (
    RuntimeIdentity,
    authorize,
    load_policy,
    principal_from_environ,
    runtime_can_rewrite_trusted_chain,
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
from vedaops_mcp.github_collab.text_contract import title_is_stable, visible_content
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
        self.distort_body: str | None = None
        self.distort_draft: bool | None = None
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
        after: str | None = None,
    ) -> object:
        self.calls.append(("read_pull_request", method, page, per_page, after))
        return {
            "method": method,
            "number": number,
            "owner": owner,
            "repo": repo,
            "pageInfo": {"hasNextPage": False, "endCursor": after},
        }

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

    def list_comments(
        self,
        owner: str,
        repo: str,
        number: int,
        page: int = 1,
        per_page: int = 100,
    ) -> list:
        self.calls.append(("list_comments", number, page, per_page))
        items = [item for item in self.comments if item["pull_number"] == number]
        start = (page - 1) * per_page
        return items[start : start + per_page]

    def list_reviews(
        self,
        owner: str,
        repo: str,
        number: int,
        page: int = 1,
        per_page: int = 30,
    ) -> list:
        self.calls.append(("list_reviews", number, page, per_page))
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
        pull["body"] = visible_content(body)
        return {"id": str(number), "url": pull["html_url"]}

    def add_pull_request_comment(self, owner: str, repo: str, number: int, body: str) -> dict:
        self.calls.append(("add_pull_request_comment", body))
        self._require_dispatched()
        if self.transport_on == "comment":
            self.comments.append(
                {
                    "id": "55",
                    "body": visible_content(body),
                    "html_url": f"https://github.com/{owner}/{repo}/pull/{number}#issuecomment-55",
                    "user_login": "example-app[bot]",
                    "created_at": "2099-01-01T00:00:00Z",
                    "pull_number": number,
                }
            )
            raise ProviderTransportError("connection reset")
        comment = {
            "id": "55",
            "body": visible_content(body),
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
            "body": visible_content(body),
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
        if self.distort_body is not None:
            pull["body"] = self.distort_body
        if self.distort_draft is not None:
            pull["draft"] = self.distort_draft
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


def _stat(mode: int, uid: int, gid: int = 0) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


@pytest.fixture(autouse=True)
def service_identity_does_not_own_operator_fixtures(monkeypatch: pytest.MonkeyPatch) -> None:
    """This process owns the fixtures and stands in for the operator.

    Trusted-path checks use another uid, so those files model root-owned
    configuration relative to the F008 runtime identity.
    """
    monkeypatch.setattr(
        "vedaops_mcp.github_collab.policy.current_runtime_identity",
        lambda: RuntimeIdentity(65534, frozenset({65534})),
    )


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
    project_roots: tuple[Path, Path] | None = None,
) -> Path:
    project_a = root / "projects" / "alpha"
    project_b = root / "projects" / "beta"
    project_a.mkdir(parents=True)
    project_b.mkdir(parents=True)
    _chmod(project_a, 0o755)
    _chmod(project_b, 0o755)
    declared_a, declared_b = project_roots or (project_a, project_b)
    journal_dir = journal or (root / "journal")
    journal_dir.mkdir(mode=0o700, exist_ok=True)
    _chmod(journal_dir, 0o700)
    key_dir = root / "secrets"
    key_dir.mkdir(exist_ok=True)
    key = private_key or (key_dir / "app.pem")
    key.parent.mkdir(exist_ok=True)
    key.write_text(
        "-----BEGIN PRIVATE KEY-----\n" + PEM_CANARY + "\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    _chmod(key, 0o400)
    _chmod(key.parent, 0o555)
    libexec = root / "libexec"
    libexec.mkdir(exist_ok=True)
    binary_path = libexec / "github-mcp-server"
    if binary is not None:
        binary_path.write_bytes(Path(binary).read_bytes())
    elif not binary_path.exists():
        binary_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable_sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    _chmod(binary_path, 0o555)
    _chmod(libexec, 0o555)
    granted = operations or [
        "read",
        "pr_create",
        "pr_update_title",
        "pr_update_body",
        "pr_comment",
        "pr_request_reviewers",
    ]
    other = second_operations or ["read"]
    config = root / "config"
    config.mkdir(exist_ok=True)
    policy_path = config / "policy.toml"
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
executable_sha256 = "{executable_sha256}"
private_key_path = "{key}"
provider_login = "example-app[bot]"

[journal]
directory = "{journal_dir}"

[[projects]]
id = "alpha"
root = "{declared_a}"
github_owner = "example-org"
github_repo = "alpha"

[[projects]]
id = "beta"
root = "{declared_b}"
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
    _chmod(policy_path, 0o444)
    _chmod(config, 0o555)
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
        path.read_text(encoding="utf-8").replace(
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


def test_operator_owned_project_root_is_declared_provenance(tmp_path: Path):
    """Model a chaz-owned checkout with the vedaops-github runtime identity."""
    sealed = tmp_path / "operator-home"
    owned = sealed / "projects" / "vedaops-mcp"
    other = sealed / "projects" / "other"
    owned.mkdir(parents=True)
    other.mkdir()
    owner_uid = owned.stat().st_uid
    runtime = github_policy.current_runtime_identity()
    assert owner_uid == os.getuid()
    assert runtime.uid == 65534
    assert owner_uid != runtime.uid
    (owned / "grant.toml").write_text(
        'operations = ["read", "pr_create", "merge"]\n',
        encoding="utf-8",
    )
    _chmod(sealed, 0o000)
    try:
        with pytest.raises(PermissionError):
            owned.lstat()
        policy, _path = _policy(tmp_path / "service-state", project_roots=(owned, other))
        assert policy.project("alpha").root == owned
        assert policy.project("alpha").repository == "example-org/alpha"
        project = authorize(
            policy,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            operation="pr_create",
        )
        assert project.id == "alpha"
        with pytest.raises(GitHubAuthorityError, match="VEDAOPS_GITHUB_REPOSITORY_DENIED"):
            authorize(
                policy,
                principal_id=PRINCIPAL,
                project_id="alpha",
                github_repository="example-org/other",
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
        assert "merge" not in policy.operations_for(PRINCIPAL, "alpha")
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
        recorded = _journals(policy)[0]["project_root"]
        assert recorded == {
            "declared_path": str(owned),
            "provenance": "operator_policy",
            "filesystem_verified": False,
        }
    finally:
        _chmod(sealed, 0o755)

    service_path = (
        Path(__file__).resolve().parents[1] / "config/github-collaboration/vedaops-github.service"
    )
    service = service_path.read_text(encoding="utf-8")
    directives = [
        line.strip()
        for line in service.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "ProtectHome=yes" in directives
    assert "ReadWritePaths=/var/lib/vedaops-github/operations" in directives
    assert not any("/home" in line or line.startswith("Bind") for line in directives)
    assert not any(
        line.startswith("ProtectHome=") and line != "ProtectHome=yes" for line in directives
    )


def test_declared_project_path_cannot_relocate_trusted_files(tmp_path: Path):
    policy_path = _write_policy(tmp_path)
    declared = policy_path.parent
    checkout = tmp_path / "projects" / "alpha"
    _chmod(declared, 0o755)
    _chmod(policy_path, 0o644)
    text = policy_path.read_text(encoding="utf-8").replace(str(checkout), str(declared), 1)
    policy_path.write_text(text, encoding="utf-8")
    _chmod(policy_path, 0o444)
    _chmod(declared, 0o555)
    with pytest.raises(GitHubPolicyError, match="VEDAOPS_GITHUB_TRUSTED_PATH_INSIDE_PROJECT"):
        load_policy(policy_path)


def test_secret_path_inside_a_project_is_rejected(tmp_path: Path):
    policy, path = _policy(tmp_path)
    stolen = policy.project("alpha").root / "app.pem"
    stolen.write_text("not-a-real-key\n", encoding="utf-8")
    _chmod(stolen, 0o600)
    _chmod(path.parent, 0o755)
    _chmod(path, 0o644)
    text = path.read_text(encoding="utf-8").replace(str(policy.private_key_path), str(stolen))
    path.write_text(text, encoding="utf-8")
    _chmod(path, 0o444)
    _chmod(path.parent, 0o555)
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
    limitation_text = " ".join(posted["limitations"])
    assert "Pull requests write satisfies" in limitation_text
    assert "Issues write is not granted" in limitation_text
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
    assert by_login["example-app[bot]"]["provider_identity_match"] is True
    assert by_login["example-app[bot]"]["native_actor_distinct_from_provider"] is False
    assert by_login["reviewer"]["provider_identity_match"] is False
    assert by_login["reviewer"]["native_actor_distinct_from_provider"] is True
    assert "independent" not in by_login["reviewer"]
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
    assert result["native"]["configured_app_id"] == "123456"
    assert result["native"]["configured_installation_id"] == "7891011"
    assert result["native"]["provider_observed_actor"]["unavailable"] is True
    assert "configured App identity is not proof" in " ".join(result["limitations"])
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


def test_installed_executable_digest_is_checked_before_launch(tmp_path: Path):
    policy, path = _policy(tmp_path)
    binary = policy.binary_path
    assert binary is not None
    assert policy.executable_sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert policy.executable_sha256 != policy.artifact_sha256
    launch_plan(policy)

    _chmod(binary.parent, 0o755)
    _chmod(binary, 0o644)
    binary.write_bytes(binary.read_bytes() + b"\n# changed\n")
    _chmod(binary, 0o555)
    _chmod(binary.parent, 0o555)
    with pytest.raises(GitHubPolicyError, match="VEDAOPS_GITHUB_EXECUTABLE_MISMATCH"):
        launch_plan(policy)

    _chmod(path.parent, 0o755)
    _chmod(path, 0o644)
    text = path.read_text(encoding="utf-8").replace(policy.executable_sha256 or "", "0" * 64)
    path.write_text(text, encoding="utf-8")
    _chmod(path, 0o444)
    _chmod(path.parent, 0o555)
    with pytest.raises(GitHubPolicyError, match="VEDAOPS_GITHUB_EXECUTABLE_MISMATCH"):
        load_policy(path)


def test_runtime_ownership_can_rewrite_without_a_write_bit():
    service = RuntimeIdentity(50, frozenset({50}))
    root = _stat(0o755, uid=0)
    parent = _stat(0o555, uid=0)
    owned = _stat(0o555, uid=50)
    safe = _stat(0o555, uid=0)
    assert runtime_can_rewrite_trusted_chain([root, parent, owned], service)
    assert not runtime_can_rewrite_trusted_chain([root, parent, safe], service)
    ancestor = _stat(0o777, uid=0)
    assert runtime_can_rewrite_trusted_chain([root, ancestor, parent, safe], service)
    sticky = _stat(stat.S_ISVTX | 0o777, uid=0)
    assert not runtime_can_rewrite_trusted_chain([sticky, safe], service)
    assert runtime_can_rewrite_trusted_chain([sticky, owned], service)
    group_directory = _stat(0o775, uid=0, gid=50)
    assert runtime_can_rewrite_trusted_chain([root, group_directory, safe], service)


def test_service_writable_executable_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    policy, path = _policy(tmp_path)
    binary = policy.binary_path
    assert binary is not None
    _chmod(binary.parent, 0o755)
    _chmod(binary, 0o666)
    with pytest.raises(GitHubPolicyError, match="must not be writable"):
        load_policy(path)
    _chmod(binary, 0o555)
    _chmod(binary.parent, 0o777)
    with pytest.raises(GitHubPolicyError, match="must not be writable"):
        load_policy(path)
    _chmod(binary.parent, 0o555)
    _chmod(tmp_path, 0o777)
    with pytest.raises(GitHubPolicyError, match="must not be writable"):
        load_policy(path)
    _chmod(tmp_path, 0o755)
    monkeypatch.setattr(
        "vedaops_mcp.github_collab.policy.current_runtime_identity",
        lambda: RuntimeIdentity(os.geteuid(), frozenset(os.getgroups()) | {os.getegid()}),
    )
    _chmod(binary, 0o555)
    _chmod(binary.parent, 0o555)
    with pytest.raises(GitHubPolicyError, match="must not be writable"):
        load_policy(path)


def test_create_does_not_succeed_when_body_or_draft_differs(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider.distort_body = "different body"
    wrong_body = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="intended body",
        draft=False,
    )
    assert wrong_body["outcome"] == "uncertain"
    assert wrong_body["outcome"] != "succeeded"
    for record in policy.journal_directory.glob("*.json"):
        record.unlink()

    provider = FakeGitHub(policy.journal_directory)
    provider.distort_draft = True
    wrong_draft = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="intended body",
        draft=False,
    )
    assert wrong_draft["outcome"] == "uncertain"
    for record in policy.journal_directory.glob("*.json"):
        record.unlink()

    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="other",
        head="feature",
        base="main",
        draft=False,
    )
    existing = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="intended body",
    )
    assert existing["outcome"] == "failed"
    assert existing["code"] == "open_pull_request_exists"
    assert "create_pull_request" not in provider.calls

    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="intended body",
        head="feature",
        base="main",
        draft=True,
    )
    wrong_existing_draft = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="intended body",
        draft=False,
    )
    assert wrong_existing_draft["outcome"] == "failed"
    assert "create_pull_request" not in provider.calls

    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="intended body",
        head="feature",
        base="main",
        draft=False,
    )
    satisfied = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="intended body",
        draft=False,
    )
    assert satisfied["outcome"] == "existing"
    assert "create_pull_request" not in provider.calls

    for record in policy.journal_directory.glob("*.json"):
        record.unlink()
    provider = FakeGitHub(policy.journal_directory)
    provider.transport_on = "create"
    provider.distort_body = "different body"
    recovered = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="intended body",
        draft=False,
    )
    assert recovered["outcome"] == "uncertain"
    assert recovered["uncertainty"]["matching_state"] is False
    assert recovered["uncertainty"]["retry_performed"] is False


def test_review_threads_use_cursor_pagination(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    with pytest.raises(GitHubPolicyError, match="pass after, not page"):
        read_pull_request(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            number=7,
            method="get_review_comments",
            page=2,
        )
    assert provider.calls == []
    with pytest.raises(GitHubPolicyError, match="after is only valid"):
        read_pull_request(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            number=7,
            method="get",
            after="CURSOR1",
        )
    observed = read_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        method="get_review_comments",
        after="CURSOR1",
    )
    assert provider.calls[-1] == ("read_pull_request", "get_review_comments", 1, 30, "CURSOR1")
    assert "pass after, not an ordinary page number" in " ".join(observed["limitations"])
    arguments = pull_request_read_arguments(
        "example-org",
        "alpha",
        7,
        "get_review_comments",
        1,
        30,
        "CURSOR1",
    )
    assert arguments["after"] == "CURSOR1"
    assert "page" not in arguments
    ordinary = pull_request_read_arguments("example-org", "alpha", 7, "get", 2, 30, None)
    assert ordinary["page"] == 2
    assert "after" not in ordinary
    reviews = pull_request_read_arguments("example-org", "alpha", 7, "get_reviews", 2, 10, None)
    assert reviews == {
        "method": "get_reviews",
        "owner": "example-org",
        "repo": "alpha",
        "pullNumber": 7,
        "page": 2,
        "perPage": 10,
    }
    with pytest.raises(GitHubPolicyError, match="cursor"):
        read_pull_request(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            number=7,
            method="get_review_comments",
            after="x" * 257,
        )


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


def _body_journal(policy) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in policy.journal_directory.glob("*.json")
    )


def test_body_evidence_omits_plaintext_and_fits_the_record(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="old",
        head="feature",
        base="main",
        draft=False,
    )
    body = "b" * 16384
    canary = "ghs_CANARYTOKENVALUE1234567890"
    secret_body = f"note {canary} end"
    updated = update_pull_request_body(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body=body,
    )
    assert updated["outcome"] == "succeeded"
    journal = _body_journal(policy)
    assert body not in journal
    assert "body_sha256" in journal
    assert len(journal.encode()) < 8192
    for record in policy.journal_directory.glob("*.json"):
        record.unlink()
    quoted = '"' * 9000 + "héllo\u200b"
    expanded = update_pull_request_body(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body=quoted,
    )
    assert expanded["outcome"] == "succeeded"
    uncertain = update_pull_request_body(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body=secret_body,
    )
    provider.transport_on = None
    lost = FakeGitHub(policy.journal_directory)
    lost._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="old",
        head="feature",
        base="main",
        draft=False,
    )

    def _lose(*_args, **_kwargs):
        raise ProviderCallError(f"failed {canary}", effect_uncertain=True)

    lost.update_pull_request_body = _lose  # type: ignore[method-assign]
    recovered = update_pull_request_body(
        policy,
        lost,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body=secret_body,
    )
    assert recovered["outcome"] == "uncertain"
    assert recovered["uncertainty"]["retry_performed"] is False
    combined = _body_journal(policy)
    assert canary not in combined
    assert secret_body not in combined
    assert quoted not in combined
    assert uncertain["outcome"] == "succeeded"


def test_terminal_journal_failure_after_dispatch_stays_unresolved(tmp_path: Path, monkeypatch):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="old",
        head="feature",
        base="main",
        draft=False,
    )
    original = GitHubJournal.terminal

    def _fail_terminal(self, state, **details):
        if self.payload.get("effect_dispatched"):
            from vedaops_mcp.github_collab.errors import GitHubPolicyError

            raise GitHubPolicyError(
                "VEDAOPS_OPERATION_RECORD_UNCERTAIN",
                "terminal evidence failed",
            )
        return original(self, state, **details)

    monkeypatch.setattr(GitHubJournal, "terminal", _fail_terminal)
    result = update_pull_request_body(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body="replacement",
    )
    assert result["outcome"] == "uncertain"
    assert result["effect_dispatched"] is True
    assert result["uncertainty"]["retry_performed"] is False
    assert result["code"] == "VEDAOPS_OPERATION_RECORD_UNCERTAIN"


def test_visible_content_contract_and_reviewer_identity(tmp_path: Path):
    assert visible_content("left\u200b right") == "left right"
    assert title_is_stable("can't \"quote\" AT&T")
    assert not title_is_stable("<b>bold</b>")
    assert not title_is_stable("Hello\u200b")
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    with pytest.raises(GitHubPolicyError, match="not stable"):
        create_pull_request(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            head="feature",
            base="main",
            expected_head_sha=HEAD,
            title="<b>bold</b>",
        )
    assert "create_pull_request" not in provider.calls
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="HelloWorld",
        head="feature",
        base="main",
        draft=False,
    )
    existing = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="Hello\u200bWorld",
    )
    assert existing["outcome"] == "existing"
    assert "create_pull_request" not in provider.calls
    with pytest.raises(GitHubPolicyError, match="team reviewers are unsupported"):
        request_reviewers(
            policy,
            provider,
            principal_id=PRINCIPAL,
            project_id="alpha",
            github_repository="example-org/alpha",
            number=7,
            reviewers=["example-org/team"],
        )
    assert not any(
        isinstance(call, tuple) and call[0] == "request_reviewers" for call in provider.calls
    )
    provider.reviews = [
        {
            "id": "1",
            "state": "COMMENTED",
            "body": "",
            "html_url": "https://github.com/example-org/alpha/pull/7#pullrequestreview-1",
            "user_login": "Example-App[bot]",
            "commit_id": OTHER,
        },
        {
            "id": "2",
            "state": "COMMENTED",
            "body": "",
            "html_url": "https://github.com/example-org/alpha/pull/7#pullrequestreview-2",
            "user_login": None,
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
    by_id = {item["id"]: item for item in reviews["native"]["reviews"]}
    assert by_id["1"]["provider_identity_match"] is True
    assert by_id["1"]["commit_id"] == OTHER
    assert by_id["2"]["provider_identity_match"] == "unknown"
    assert by_id["2"]["native_actor_distinct_from_provider"] == "unknown"


def test_base_sha_is_part_of_the_create_subject(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="body",
        head="feature",
        base="main",
        draft=False,
    )
    provider.pulls[0]["base_sha"] = OTHER
    existing = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        expected_base_sha=BASE,
        title="Candidate",
        body="body",
    )
    assert existing["outcome"] == "failed"
    assert existing["code"] == "open_pull_request_exists"
    assert "create_pull_request" not in provider.calls
    provider.pulls.clear()

    def _move_base(*_args, **kwargs):
        pull = provider._add_pull(
            "example-org",
            "alpha",
            title=kwargs["title"],
            body=kwargs["body"],
            head=kwargs["head"],
            base=kwargs["base"],
            draft=kwargs["draft"],
        )
        pull["base_sha"] = OTHER
        return {"id": str(pull["number"]), "url": pull["html_url"]}

    provider.create_pull_request = _move_base  # type: ignore[method-assign]
    drifted = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        expected_base_sha=BASE,
        title="Candidate",
        body="body",
    )
    assert drifted["outcome"] == "uncertain"
    assert drifted["uncertainty"]["retry_performed"] is False
    assert drifted["subject"]["pre_observed_base_sha"] == BASE
    assert drifted["subject"]["post_observed_base_sha"] == OTHER
    assert drifted["subject"]["expected_base_sha"] == BASE
    for record in policy.journal_directory.glob("*.json"):
        record.unlink()
    provider.pulls.clear()
    provider.base_sha = BASE

    def _move_without_expectation(*_args, **kwargs):
        pull = provider._add_pull(
            "example-org",
            "alpha",
            title=kwargs["title"],
            body=kwargs["body"],
            head=kwargs["head"],
            base=kwargs["base"],
            draft=kwargs["draft"],
        )
        pull["base_sha"] = OTHER
        return {"id": str(pull["number"]), "url": pull["html_url"]}

    provider.create_pull_request = _move_without_expectation  # type: ignore[method-assign]
    noted = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="body",
    )
    assert noted["outcome"] == "succeeded"
    assert "base SHA changed" in " ".join(noted["limitations"])
    assert noted["subject"]["expected_base_sha"] is None
    assert noted["subject"]["post_observed_base_sha"] == OTHER


def test_comment_verification_walks_bounded_pages(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="",
        head="feature",
        base="main",
        draft=False,
    )
    for index in range(100):
        provider.comments.append(
            {
                "id": str(index),
                "body": "old",
                "html_url": "https://github.com/example-org/alpha/pull/7#issuecomment-1",
                "user_login": "example-app[bot]",
                "created_at": "2000-01-01T00:00:00Z",
                "pull_number": 7,
            }
        )

    def _comment_on_second_page(*_args, **_kwargs):
        provider.comments.append(
            {
                "id": "later",
                "body": visible_content("noted"),
                "html_url": "https://github.com/example-org/alpha/pull/7#issuecomment-later",
                "user_login": "example-app[bot]",
                "created_at": "2099-01-01T00:00:00Z",
                "pull_number": 7,
            }
        )
        return {
            "id": "later",
            "url": "https://github.com/example-org/alpha/pull/7#issuecomment-later",
        }

    provider.add_pull_request_comment = _comment_on_second_page  # type: ignore[method-assign]
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
    comment_pages = [call for call in provider.calls if call[0] == "list_comments"]
    assert any(call[1] == 7 and call[2] == 2 for call in comment_pages)


def _handshake_script(mode: str) -> str:
    tools = json.dumps(list(PROVIDER_TOOLS))
    return f"""#!/usr/bin/env python3
import json, os, sys, time
MODE = {mode!r}
TOOLS = {tools}

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
                "serverInfo": {{"name": "github-mcp-server", "version": {PROVIDER_RELEASE!r}}},
            }},
        }})
    elif method == "tools/list":
        if MODE == "pipe":
            descriptor = sys.stdin.fileno()
            sys.stdin.close()
            try:
                os.close(descriptor)
            except OSError:
                pass
        send({{
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {{"tools": [{{"name": name}} for name in TOOLS]}},
        }})
        if MODE == "pipe":
            time.sleep(30)
            raise SystemExit(0)
    elif method == "tools/call":
        if MODE == "eof":
            break
        if MODE == "malformed":
            sys.stdout.write("{{not-json\\n")
            sys.stdout.flush()
            break
        if MODE == "length":
            sys.stdout.write("Content-Length: no\\r\\n\\r\\n")
            sys.stdout.flush()
            break
        if MODE == "huge":
            sys.stdout.write("Content-Length: 99999999\\r\\n\\r\\n")
            sys.stdout.flush()
            break
        if MODE == "short":
            sys.stdout.write("Content-Length: 80\\r\\n\\r\\n{{")
            sys.stdout.flush()
            break
        if MODE == "notice":
            send({{"jsonrpc": "2.0", "method": "notifications/message", "params": {{}}}})
        text = "validation failed status 422"
        if MODE == "explicit":
            text = json.dumps({{"effect": "none", "status": 422}})
        if MODE == "notice":
            text = json.dumps({{"sha": "{HEAD}", "html_url": "https://github.com/example-org/alpha/commit/{HEAD}"}})
        send({{
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {{
                "content": [{{"type": "text", "text": text}}],
                "isError": MODE != "notice",
            }},
        }})
        break
"""


def test_stdio_transport_failures_are_normalized(tmp_path: Path):
    assert _explicit_no_effect('{"effect":"none","status":422}')
    assert not _explicit_no_effect("validation failed status 422")

    def _script(source: str) -> Path:
        path = tmp_path / f"server-{len(list(tmp_path.iterdir()))}.py"
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
        return path

    early = _script("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n")
    policy, _path = _policy(tmp_path / "early", binary=early)
    with pytest.raises(ProviderTransportError):
        StdioGitHubProvider(policy)

    partial = _script(
        "#!/usr/bin/env python3\n"
        "import sys, time\n"
        "sys.stdout.write('{')\n"
        "sys.stdout.flush()\n"
        "time.sleep(30)\n"
    )
    policy, _path = _policy(tmp_path / "partial", binary=partial)
    from vedaops_mcp.github_collab import mcp_client as client_module

    original = client_module._CALL_DEADLINE_SECONDS
    client_module._CALL_DEADLINE_SECONDS = 0.2
    try:
        with pytest.raises(ProviderTransportError, match="timed out"):
            StdioGitHubProvider(policy)
    finally:
        client_module._CALL_DEADLINE_SECONDS = original

    expected_detail = {
        "eof": "stdout closed",
        "malformed": "not valid JSON",
        "length": "content-length",
        "huge": "size limit",
        "short": "stdout closed",
        "pipe": "pipe",
    }
    for mode, detail in expected_detail.items():
        binary = _script(_handshake_script(mode))
        mode_policy, _path = _policy(tmp_path / mode, binary=binary)
        provider = StdioGitHubProvider(mode_policy)
        try:
            with pytest.raises(ProviderTransportError, match=detail) as caught:
                provider.get_commit("example-org", "alpha", HEAD)
            assert caught.value.effect_possible is True
        finally:
            provider.close()

    notice = _script(_handshake_script("notice"))
    notice_policy, _path = _policy(tmp_path / "notice", binary=notice)
    provider = StdioGitHubProvider(notice_policy)
    try:
        assert provider.get_commit("example-org", "alpha", HEAD)["sha"] == HEAD
    finally:
        provider.close()

    explicit = _script(_handshake_script("explicit"))
    explicit_policy, _path = _policy(tmp_path / "explicit", binary=explicit)
    provider = StdioGitHubProvider(explicit_policy)
    try:
        with pytest.raises(ProviderCallError) as caught:
            provider.get_commit("example-org", "alpha", HEAD)
        assert caught.value.effect_uncertain is False
    finally:
        provider.close()

    textual = _script(_handshake_script("textual"))
    textual_policy, _path = _policy(tmp_path / "textual", binary=textual)
    provider = StdioGitHubProvider(textual_policy)
    try:
        with pytest.raises(ProviderCallError) as caught:
            provider.get_commit("example-org", "alpha", HEAD)
        assert caught.value.effect_uncertain is True
        assert "422" not in caught.value.detail or "status 422" in caught.value.detail
    finally:
        provider.close()


def _lost_create(provider: FakeGitHub, *, base_sha: str):
    def _dispatch(_owner, _repo, **kwargs):
        pull = provider._add_pull(
            "example-org",
            "alpha",
            title=kwargs["title"],
            body=kwargs["body"],
            head=kwargs["head"],
            base=kwargs["base"],
            draft=kwargs["draft"],
        )
        pull["base_sha"] = base_sha
        raise ProviderTransportError("connection reset")

    provider.create_pull_request = _dispatch  # type: ignore[method-assign]


def test_create_recovery_keeps_nonmatching_candidates(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    _lost_create(provider, base_sha=BASE)
    matched = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        expected_base_sha=BASE,
        title="Candidate",
        body="body",
    )
    assert matched["outcome"] == "uncertain"
    assert matched["uncertainty"]["matching_state"] is True
    assert matched["uncertainty"]["conflicting"] is False
    assert matched["uncertainty"]["causality"] == "unproven"
    assert matched["uncertainty"]["retry_performed"] is False
    assert matched["native"]["exact_match_count"] == 1
    assert matched["native"]["discovered"][0]["exact_subject_matched"] is True
    assert matched["native"]["discovered"][0]["base_drift"] is False
    assert matched["native"]["discovered"][0]["post_observed_base_sha"] == BASE
    assert matched["native"]["discovered"][0]["causality"] == "unproven"

    for record in policy.journal_directory.glob("*.json"):
        record.unlink()
    provider.pulls.clear()
    _lost_create(provider, base_sha=OTHER)
    drifted = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        expected_base_sha=BASE,
        title="Candidate",
        body="body",
    )
    candidate = drifted["native"]["discovered"][0]
    assert drifted["outcome"] == "uncertain"
    assert drifted["outcome"] != "succeeded"
    assert drifted["uncertainty"]["matching_state"] is False
    assert drifted["uncertainty"]["retry_performed"] is False
    assert candidate["exact_subject_matched"] is False
    assert candidate["pre_observed_base_sha"] == BASE
    assert candidate["post_observed_base_sha"] == OTHER
    assert candidate["expected_base_sha"] == BASE
    assert candidate["visible_title_matched"] is True
    assert candidate["causality"] == "unproven"
    assert drifted["native"]["nonmatching"]
    assert drifted["uncertainty"]["conflicting"] is False
    assert "expected_base_sha" in drifted["uncertainty"]["reason"]
    drifted_journal = _journals(policy)[0]["observed_after"]
    assert drifted_journal["exact_match_count"] == 0
    assert drifted_journal["candidates"][0]["post_observed_base_sha"] == OTHER
    assert drifted_journal["candidates"][0]["causality"] == "unproven"

    for record in policy.journal_directory.glob("*.json"):
        record.unlink()
    provider.pulls.clear()
    _lost_create(provider, base_sha=OTHER)
    noted = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="body",
    )
    noted_candidate = noted["native"]["discovered"][0]
    assert noted["outcome"] == "uncertain"
    assert noted_candidate["exact_subject_matched"] is True
    assert noted_candidate["base_drift"] is True
    assert noted["subject"]["expected_base_sha"] is None
    assert noted["uncertainty"]["conflicting"] is False
    assert "base SHA differs" in noted["uncertainty"]["reason"]
    assert _journals(policy)[0]["observed_after"]["candidates"][0]["base_drift"] is True

    for record in policy.journal_directory.glob("*.json"):
        record.unlink()
    provider.pulls.clear()
    existing_pull = provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="body",
        head="feature",
        base="main",
        draft=False,
    )
    existing_pull["base_sha"] = OTHER
    existing = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        title="Candidate",
        body="body",
    )
    assert existing["outcome"] == "existing"
    assert existing["subject"]["pre_observed_base_sha"] == BASE
    assert existing["subject"]["post_observed_base_sha"] == OTHER
    assert "base SHA differs" in " ".join(existing["limitations"])
    assert "create_pull_request" not in provider.calls

    provider.pulls.clear()
    attempts = {"count": 0}

    def _conflict(_owner, _repo, **kwargs):
        attempts["count"] += 1
        for _ in range(2):
            pull = provider._add_pull(
                "example-org",
                "alpha",
                title=kwargs["title"],
                body=kwargs["body"],
                head=kwargs["head"],
                base=kwargs["base"],
                draft=kwargs["draft"],
            )
            pull["base_sha"] = BASE
        raise ProviderTransportError("connection reset")

    provider.create_pull_request = _conflict  # type: ignore[method-assign]
    conflict = create_pull_request(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        head="feature",
        base="main",
        expected_head_sha=HEAD,
        expected_base_sha=BASE,
        title="Candidate",
        body="body",
    )
    assert conflict["outcome"] == "uncertain"
    assert conflict["uncertainty"]["conflicting"] is True
    assert conflict["uncertainty"]["matching_state"] is False
    assert conflict["native"]["discovered_count"] == 2
    assert conflict["native"]["exact_match_count"] == 2
    assert len(conflict["native"]["exact_matches"]) == 2
    assert conflict["uncertainty"]["retry_performed"] is False
    assert conflict["uncertainty"]["causality"] == "unproven"
    assert attempts["count"] == 1
    stored = _journals(policy)[0]["observed_after"]
    assert stored["discovered_count"] == 2
    assert stored["candidates_truncated"] is False
    assert stored["candidate_numbers_sha256"]
    assert all(item["causality"] == "unproven" for item in stored["candidates"])


def test_comment_recovery_evidence_stays_within_the_journal_ceiling(tmp_path: Path):
    policy, _path = _policy(tmp_path)
    provider = FakeGitHub(policy.journal_directory)
    provider._add_pull(
        "example-org",
        "alpha",
        title="Candidate",
        body="",
        head="feature",
        base="main",
        draft=False,
    )
    body = "COMMENTBODYCANARY"
    for index in range(500):
        provider.comments.append(
            {
                "id": str(1000 + index),
                "body": body,
                "html_url": f"https://github.com/example-org/alpha/pull/7#issuecomment-{index}",
                "user_login": "example-app[bot]",
                "created_at": "2099-01-01T00:00:00Z",
                "pull_number": 7,
            }
        )

    attempts = {"count": 0}

    def _lose(*_args, **_kwargs):
        attempts["count"] += 1
        raise ProviderTransportError("connection reset")

    provider.add_pull_request_comment = _lose  # type: ignore[method-assign]
    result = add_pull_request_comment(
        policy,
        provider,
        principal_id=PRINCIPAL,
        project_id="alpha",
        github_repository="example-org/alpha",
        number=7,
        body=body,
    )
    assert result["outcome"] == "uncertain"
    assert result["uncertainty"]["retry_performed"] is False
    assert result["uncertainty"]["matching_state"] is False
    assert result["subject"]["matching_comment_count"] == 500
    assert result["subject"]["conflicting"] is True
    assert result["subject"]["comment_scan_complete"] is False
    assert len(result["subject"]["matching_comment_id_sample"]) == 8
    assert result["subject"]["matching_comment_ids_truncated"] is True
    assert attempts["count"] == 1
    pages = [
        call
        for call in provider.calls
        if isinstance(call, tuple) and call[0] == "list_comments"
    ]
    assert [call[2] for call in pages] == [1, 2, 3, 4, 5]
    journal = _body_journal(policy)
    assert len(journal.encode()) <= MAX_OPERATION_RECORD_BYTES
    assert body not in journal
    recorded = json.loads(journal)
    observed = recorded["observed_after"]
    assert observed["matching_comment_count"] == 500
    assert observed["conflicting"] is True
    assert observed["comment_scan_complete"] is False
    assert observed["matching_comment_id_sample"] == [str(1000 + index) for index in range(8)]
    assert observed["matching_comment_ids_sha256"]
    assert "1499" not in observed["matching_comment_id_sample"]
    assert recorded["effect_dispatched"] is True
    assert recorded["state"] == "uncertain"


def test_modeled_terminal_records_fit_the_journal_ceiling() -> None:
    started = {
        "schema_version": 1,
        "domain": "f008",
        "operation_id": "f" * 32,
        "state": "started",
        "started_at": "2026-09-21T00:00:00Z",
        "principal_id": "p" * 64,
        "project_id": "a" * 128,
        "project_root": {
            "declared_path": "/" + ("d" * 512),
            "provenance": "operator_policy",
            "filesystem_verified": False,
        },
        "github_repository": ("o" * 39) + "/" + ("r" * 100),
        "kind": "pr_create",
        "target": {
            "base": "b" * 128,
            "draft": True,
            "head": "h" * 128,
            "observed_base_sha": "a" * 64,
            "observed_head_sha": "b" * 64,
            "pre_observed_base_sha": "c" * 64,
            "pre_observed_head_sha": "d" * 64,
            "expected_head_sha": "e" * 64,
            "expected_base_sha": "f" * 64,
            "body_sha256": "c" * 64,
            "body_characters": 16384,
            "body_bytes": 65536,
        },
        "intention_sha256": "e" * 64,
        "authorization_basis": (
            "operator-policy:"
            + ("a" * 64)
            + ":principal:"
            + ("p" * 64)
            + ":project:"
            + ("a" * 128)
            + ":operation:pr_request_reviewers"
        ),
        "provider_id": "github-mcp-server",
        "provider_release": PROVIDER_RELEASE,
        "provider_commit": PROVIDER_COMMIT,
        "provider_feature": PROVIDER_FEATURE,
        "effect_dispatched": False,
        "may_have_occurred": False,
        "pid": 2_000_000_000,
        "expected_source_sha": "a" * 64,
    }
    assert_journal_states_fit(started)
    for terminal in modeled_terminal_payloads(started):
        assert len(record_bytes(terminal)) <= MAX_OPERATION_RECORD_BYTES
    started["project_root"] = {
        "declared_path": "/" + ("d" * 8000),
        "provenance": "operator_policy",
        "filesystem_verified": False,
    }
    with pytest.raises(GitHubPolicyError, match="record ceiling"):
        assert_journal_states_fit(started)
