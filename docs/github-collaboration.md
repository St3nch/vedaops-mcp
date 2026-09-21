# F008 GitHub collaboration

**Status:** local implementation candidate. Not Product acceptance. Not pushed. Not merged. No live GitHub App, connector, or provider call is part of this change.

F008 is a separate collaboration boundary from VedaOps MCP Shadow. Shadow grants do not authorize GitHub. The official GitHub MCP Server is the provider. This repository does not embed GitHub credentials in Shadow and does not replace GitHub's pull request model.

```text
ChatGPT / Project Steward
        |
        +---- VedaOps MCP Shadow
        |       Orient / Inspect / Change / Check
        |
        +---- vedaops-github stdio
                authorization and operation evidence
                |
                +---- pinned github-mcp-server stdio
                        GitHub App installation token
                        |
                        +---- GitHub
```

The Steward connector must spawn `vedaops-github`, not the Shadow process and not the official server directly. The official server's HTTP mode cannot authenticate with a GitHub App key, so the App key stays with the stdio child.

## Pinned provider

| Item | Value |
| --- | --- |
| Repository | `github/github-mcp-server` |
| Release | `v1.12.2` |
| Commit | `85598ba6e1256f7ebf4867b95d63b833c4549264` |
| Feature | `pull_requests_granular` |
| API header sent by that server | `X-GitHub-Api-Version: 2022-11-28` |
| Linux x86_64 tarball SHA-256 | `95843162759da2c31dde082dd145be35db82164594796c294414b69790c2290e` |
| Linux arm64 tarball SHA-256 | `2b30f9fcc061b57456cbe38ddc0f13c88863bad49557508a9196f2d1c4cb17a5` |

The tarball digest is the release artifact identity. It is not the digest of the extracted binary. Do not use a floating `latest` image or tag. The current REST documentation examples also mention `2026-03-10` as an API version header. F008 does not override the pinned server's header. A provider upgrade is a code and policy change because the release, commit, digest, feature, and tool catalog must match together.

Authentication is GitHub App installation token mode (`--app-id`, `--app-installation-id`, `--app-private-key-path`). The private key is a file path. The PEM is not placed in argv or in `GITHUB_APP_PRIVATE_KEY`. A personal access token is not the design. Insiders mode and MCP App form deferral are not enabled. With only `--tools` set, upstream disables the default toolsets and registers that list. F008 still refuses to operate unless `tools/list` matches the allowlist exactly.

## Provider tools the child may expose

`actions_list`, `add_issue_comment`, `create_pull_request`, `get_commit`, `get_me`, `list_pull_requests`, `pull_request_read`, `request_pull_request_reviewers`, `update_pull_request_body`, `update_pull_request_title`.

VedaOps calls `get_commit` with `detail=none`. `pull_request_read` is limited to its read methods: `get`, `get_diff`, `get_status`, `get_files`, `get_commits`, `get_review_comments`, `get_reviews`, `get_comments`, `get_check_runs`. `actions_list` is limited to `list_workflows`, `list_workflow_runs`, and `list_workflow_jobs`. Artifact listing, log download, and workflow dispatch are rejected before a provider call.

`add_issue_comment` is used only after a pull request read succeeds, and only with a body. Reactions are not sent. `create_pull_request` is not given reviewers or `maintainer_can_modify`.

## Explicitly absent

The catalog check fails closed if any of these are advertised, and also if any other name appears or an expected name disappears:

`merge_pull_request`, `update_pull_request`, `update_pull_request_branch`, `update_pull_request_state`, `update_pull_request_draft_state`, `create_or_update_file`, `delete_file`, `push_files`, `create_branch`, `actions_run_trigger`, `pull_request_review_write`, `create_pull_request_review`, `submit_pending_pull_request_review`, `add_pull_request_review_comment`, `get_file_contents`, `issue_write`, `search_code`, `search_repositories`.

There is no generic REST tool, GraphQL tool, `gh` tool, shell, webhook receiver, or push tool in this boundary. Closing or reopening a pull request and changing its base are not exposed. The granular state and draft tools exist upstream and are not allowlisted. Review submission is not exposed. A review whose author login equals the configured provider login is marked `independent: false`. That flag is not Product acceptance, and a review from someone else is not Product acceptance either.

The client-facing tools are `github_server_info`, `github_identity_get`, `github_commit_get`, `github_pull_request_read`, `github_actions_list`, `github_pull_request_create`, `github_pull_request_update_title`, `github_pull_request_update_body`, `github_pull_request_comment`, and `github_pull_request_request_reviewers`.

## Permissions to request

Repository permissions for the App installation:

| Permission | Access | Why |
| --- | --- | --- |
| Metadata | read | App baseline |
| Contents | read | `get_commit` calls `GET /repos/{owner}/{repo}/commits/{ref}` |
| Pull requests | write | create, title, body, reviewer request, and pull request reads |
| Actions | read | workflow, run, and job lists |
| Checks | read | `GET /repos/{owner}/{repo}/commits/{ref}/check-runs` |
| Commit statuses | read | `GET /repos/{owner}/{repo}/commits/{ref}/status` |

Do not request Contents write, Administration, Workflows write, Checks write, commit-status write, Deployments, secrets, variables, or webhook administration.

### Unresolved: ordinary conversation comments

`add_issue_comment` calls `POST /repos/{owner}/{repo}/issues/{issue_number}/comments`. On 2026-09-21 the GitHub Apps permission table lists that endpoint under both Issues write and Pull requests write, and each row says multiple permissions may be required or a different permission may be used.

The accepted App design does **not** include Issues write. Do not add it while creating the App unless CHAZ explicitly reconciles that permission. Live comment calls may return 403 until that decision. Title updates and reviewer requests stay inside Pull requests write and can be the first live write. F008 still refuses to comment unless the number is an observable pull request.

## Authorization

Operator policy is a TOML file outside every project root it names. The example is `config/github-collaboration.toml.example`. Grants are the intersection of one principal, one VedaOps project, one `owner/repo`, and an operation class. The classes are only:

`read`, `pr_create`, `pr_update_title`, `pr_update_body`, `pr_comment`, `pr_request_reviewers`.

Any other class, including merge or push, makes the policy invalid. A file inside a managed project is not read for grants and cannot select the private-key path. Shadow project policy is not consulted. `VEDAOPS_AGENT_ID` does not name the F008 principal.

Standing collaboration authority, after a later Product acceptance, is an operator grant of those classes to the Steward principal. The software does not record a Product decision, and it does not treat a pull request, review, check, or merge as acceptance.

## Evidence and recovery

Before a GitHub write, F008 fsyncs a started journal record under the operator journal directory with `effect_dispatched` true. The record includes the operation id, time, principal, project, repository, kind, target, expected source SHA, intention digest, authorization basis, and provider release/commit. It does not store the comment or pull request body, and it does not store the private key.

After the provider returns, F008 re-reads the native object. Success requires that re-read to match. A lost response or an ambiguous provider error is `uncertain`: the journal says an effect may have occurred, native state is inspected, a matching object is reported as `causality: unproven`, and the write is not retried. GitHub does not provide compare-and-swap for these writes. A head or base SHA that changes between the pre-read and the post-read is recorded as a limitation, not hidden.

Pull request creation reads the live branch tip with `get_commit` and refuses to create when that SHA differs from `expected_head_sha`. A local remote-tracking ref is not consulted. An open pull request that already has the same head, base, and SHA is returned without a second create.

Journal files are mode `0600` in a directory mode `0700`. They are evidence of VedaOps calls. GitHub remains authoritative for pull request state.

## Credential isolation

Use a dedicated Unix account, `vedaops-github`, with no login shell. Suggested paths, all outside managed projects and outside Shadow's home:

| Path | Mode | Contents |
| --- | --- | --- |
| `/var/lib/vedaops-github` | `0700` | service home |
| `policy/policy.toml` | `0600` | operator grants, no PEM |
| `secrets/app.pem` | `0400` or `0600` | GitHub App private key |
| `operations/` | `0700` | journal |
| `bin/github-mcp-server` | `0755`, not group-writable | extracted pinned binary |

The private key must be owned by `vedaops-github` and must not be group- or world-accessible. The child environment is built from a fixed key list: `PATH`, `HOME` set to the service directory, locale, App id, installation id, key path, feature, and tool list. It does not inherit the parent environment. Shadow, check workers, and project worktrees do not receive this directory, the key, or the journal. Check mount policy is unchanged and does not name these paths.

Templates that are not applied by this change:

- `config/github-collaboration/vedaops-github.service`
- `config/github-collaboration/sysusers.conf`
- `config/github-collaboration/tmpfiles.conf`

Do not `systemctl enable` the unit. It is a sandbox profile for a foreground stdio process. Creating the user, directories, App, or connector is host and GitHub administration and needs a separate CHAZ action.

Disabling F008 is `enabled = false` in the operator policy, or not running `vedaops-github`. The Shadow tool catalog does not include these tools. Removing the package does not remove Orient, Inspect, Change, or Check.

Revocation is: set `enabled = false`, stop any F008 process, delete or shred `secrets/app.pem`, and uninstall or suspend the GitHub App installation in GitHub. Suspended installation tokens stop working on their own expiry as well. Shadow keeps running. The journal can remain for evidence; it does not contain the key.

## Local commands

```bash
export VEDAOPS_GITHUB_POLICY=/var/lib/vedaops-github/policy/policy.toml
export VEDAOPS_GITHUB_PRINCIPAL=example-steward
uv run vedaops-github validate-policy --policy "$VEDAOPS_GITHUB_POLICY"
uv run vedaops-github render-launch --policy "$VEDAOPS_GITHUB_POLICY"
uv run vedaops-github validate-artifact /path/to/github-mcp-server_Linux_x86_64.tar.gz \
  --name github-mcp-server_Linux_x86_64.tar.gz
uv run vedaops-github validate-catalog /path/to/tools-list.json
uv run vedaops-github stdio
```

`render-launch` prints argv and the child environment. It does not read the PEM. `validate-catalog` accepts either a JSON list of names or a `tools/list` result.

## Minimum human GitHub setup

These steps are not done by the implementation:

1. CHAZ creates a GitHub App owned by the intended account, with the permissions in the table above and without Issues write until that question is reconciled.
2. CHAZ generates a private key and places only the PEM at the service secret path.
3. CHAZ installs the App on the specific repositories that will appear in operator policy, not on all repositories.
4. CHAZ records the App id and installation id in the operator policy outside the repositories.
5. CHAZ, or an authorized operator, downloads the `v1.12.2` Linux tarball, checks the digest, and installs the binary for `vedaops-github`.
6. CHAZ creates the `vedaops-github` account and directories if they do not exist.
7. CHAZ sets `provider_login` to the App's bot login, commonly the App slug plus `[bot]`.
8. CHAZ authorizes a distinct ChatGPT connector whose command is `vedaops-github stdio` as `vedaops-github`. Do not reuse the Shadow connector.
9. Only after that connector exists does a Steward run the live verification below.

## Live verification

Run this once, against the configured App, after the setup above. Do not treat it as Product acceptance.

1. `github_server_info` shows release `v1.12.2`, commit `85598ba6…`, feature `pull_requests_granular`, and `shadow_coupled: false`.
2. The child initialize version and `validate-catalog` agree with the allowlist. `merge_pull_request` is absent.
3. `github_identity_get` on an authorized repository reports the App id and installation id. `get_me` may be unavailable for an installation token; that is a limitation, not success.
4. The same read against a repository that is not granted returns a denial and does not call the provider for that repository.
5. `github_commit_get` on the published head branch returns the live SHA. Compare it with the intended candidate. A local remote-tracking ref is not the source.
6. One authorized write that stays inside Pull requests write, preferably `github_pull_request_update_title` or `github_pull_request_request_reviewers` on a pull request CHAZ has designated for the tracer. Record the journal file's `effect_dispatched` record from before the call if you are watching the directory, then the terminal record and the re-read SHA, title, and URL.
7. Confirm the journal file exists outside the project root and does not contain the PEM.
8. For the uncertain-effect step, interrupt the child after dispatch only in a way CHAZ has allowed, then confirm the result is `uncertain`, `retry_performed` is false, and a second pull request or comment was not created. If no safe interrupt is available, skip this step and say it was not run.
9. `github_pull_request_read` method `get_reviews` shows reviewer logins. The provider login is not independent.
10. Start a new Steward session and reconstruct the candidate SHA, journal operation id, GitHub pull request number, and URL from the repository, the journal, and GitHub. Do not rely on the earlier chat.
11. Set `enabled = false`, restart only the F008 process, and confirm Shadow's tool list is unchanged and a GitHub write is refused.
12. Revoke by the procedure above only when CHAZ asks for revocation.

Conversation-comment proof waits on the Issues-write decision.

## Checks that this repository can run before that setup

`uv run pytest -q tests/test_github_collaboration.py` uses fakes. It does not contact GitHub and does not prove the live App, the real binary's catalog, or network behavior. `validate-artifact` proves a tarball only when an operator supplies that file.
