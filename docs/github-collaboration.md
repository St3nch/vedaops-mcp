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

The tarball digest is the published release-archive identity. GitHub does not publish a separate checksum of the extracted executable. After `validate-artifact` accepts the archive, the operator extracts it and records the installed file's SHA-256 with `vedaops-github hash-executable`. That locally derived digest is `executable_sha256` in operator policy. It is not a substitute for the archive digest, and the archive digest is not accepted as the executable digest.

Before every launch, `vedaops-github` hashes `binary_path` and refuses to start the child when the bytes differ from `executable_sha256`. A version string or `tools/list` result does not identify the executable. Do not use a floating `latest` image or tag. The current REST documentation examples also mention `2026-03-10` as an API version header. F008 does not override the pinned server's header. A provider upgrade is a code and policy change because the release, commit, archive digest, installed-file digest, feature, and tool catalog must match together.

Authentication is GitHub App installation token mode (`--app-id`, `--app-installation-id`, `--app-private-key-path`). The private key is a file path. The PEM is not placed in argv or in `GITHUB_APP_PRIVATE_KEY`. A personal access token is not the design. Insiders mode and MCP App form deferral are not enabled. With only `--tools` set, upstream disables the default toolsets and registers that list. F008 still refuses to operate unless `tools/list` matches the allowlist exactly.

## Provider tools the child may expose

`actions_list`, `add_issue_comment`, `create_pull_request`, `get_commit`, `get_me`, `list_pull_requests`, `pull_request_read`, `request_pull_request_reviewers`, `update_pull_request_body`, `update_pull_request_title`.

VedaOps calls `get_commit` with `detail=none`. `pull_request_read` is limited to its read methods: `get`, `get_diff`, `get_status`, `get_files`, `get_commits`, `get_review_comments`, `get_reviews`, `get_comments`, `get_check_runs`. `get_review_comments` pages with the upstream `after` cursor and `perPage`. An ordinary `page` value is rejected for that method and is not sent as a review-thread offset. The other read methods, including `get_reviews`, use `page` and `perPage`. `actions_list` is limited to `list_workflows`, `list_workflow_runs`, and `list_workflow_jobs`. Artifact listing, log download, and workflow dispatch are rejected before a provider call.

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

### Timeline comments

`add_issue_comment` calls `POST /repos/{owner}/{repo}/issues/{issue_number}/comments`. On 2026-09-21 the endpoint documentation says a GitHub App installation token needs at least one of Issues write or Pull requests write. F008 already grants Pull requests write, so ordinary pull request timeline comments do not need Issues write.

Issues write stays excluded. That avoids granting general issue authority. `github_pull_request_comment` still reads the pull request first and refuses the comment unless that number is an observable pull request.

## Authorization

Operator policy is a TOML file outside every project path it names. The example is `config/github-collaboration.toml.example`. Grants are the intersection of one principal, one VedaOps project id, one `owner/repo`, and an operation class. The classes are only:

`read`, `pr_create`, `pr_update_title`, `pr_update_body`, `pr_comment`, `pr_request_reviewers`.

Any other class, including merge or push, makes the policy invalid. A file inside a managed project is not read for grants and cannot select the private-key path, the provider executable, the journal, or the policy file. Shadow project policy is not consulted. `VEDAOPS_AGENT_ID` does not name the F008 principal.

Each project entry maps one VedaOps project id to one GitHub `owner/repo`. Its `root` value is the absolute path the operator declares for that checkout. F008 stores that string as provenance and uses it only as a lexical boundary: policy, the App key, the provider executable, and the journal must not lie inside a declared project path. The runtime does not stat, own, or traverse that path, and it does not claim to have verified the checkout. Local reads and edits of the repository belong to Shadow and the development account. `ProtectHome=yes` on the F008 service stays; do not mount `/home` into the sandbox and do not chown a development checkout to `vedaops-github`.

Standing collaboration authority, after a later Product acceptance, is an operator grant of those classes to the Steward principal. The software does not record a Product decision, and it does not treat a pull request, review, check, or merge as acceptance.

## Evidence and recovery

Before a GitHub write, F008 fsyncs a started journal record under the operator journal directory with `effect_dispatched` true. The record includes the operation id, time, principal, project, repository, kind, target, expected source SHA, intention digest, authorization basis, and provider release/commit. The project path in that record is the operator-declared path, with `filesystem_verified` false. It does not store the comment or pull request body, and it does not store the private key.

After the provider returns, F008 re-reads the native object. Success requires that re-read to match. A lost response or an ambiguous provider error is `uncertain`: the journal says an effect may have occurred, native state is inspected, a matching object is reported as `causality: unproven`, and the write is not retried. GitHub does not provide compare-and-swap for these writes. A head or base SHA that changes between the pre-read and the post-read is recorded as a limitation, not hidden.

Pull request creation reads the live branch tip with `get_commit` and refuses to create when that SHA differs from `expected_head_sha`. A local remote-tracking ref is not consulted. Success, an already-open match, and uncertain-effect recovery all require the same intended state: head ref, head SHA, base ref, title, body, draft flag, and open state. An open pull request that differs in body or draft is not reported as already satisfied and is not reported as a successful create.

Journal files are mode `0600` in a directory mode `0700`. They are evidence of VedaOps calls. GitHub remains authoritative for pull request state.

## Credential isolation

Use a dedicated Unix account, `vedaops-github`, with no login shell. Trusted configuration and the provider executable are root-owned and not writable by that account. The journal is the writable state directory.

| Path | Owner and mode | Contents |
| --- | --- | --- |
| `/etc/vedaops-github/` | `root:vedaops-github` `0750` | trusted configuration directory |
| `/etc/vedaops-github/policy.toml` | `root:vedaops-github` `0640` | operator grants, no PEM |
| `/etc/vedaops-github/app.pem` | `root:vedaops-github` `0440` | GitHub App private key |
| `/usr/local/lib/vedaops-github/github-mcp-server` | `root:root` `0755` | extracted provider executable |
| `/var/lib/vedaops-github/operations/` | `vedaops-github` `0700` | journal |

The F008 process must be able to read the policy, the key, and the executable. It must not be able to rewrite them. Owning the file is rewrite authority even when the write bit is clear, because that uid can chmod it. The same rule applies to every ancestor directory. A sticky directory does not let the runtime replace another user's entry. `ProtectSystem=strict` with `ReadWritePaths` limited to the journal is the host enforcement of that split. The supported deployment keeps policy, key, and executable owned by root. The hash is the file contents immediately before launch. It is not a kernel-enforced immutable binding.

The official GitHub MCP process is started as the same Unix user as `vedaops-github`. It is part of that runtime's trusted computing base. F008 does not claim a separate OS identity or mount namespace between the wrapper and the child. The hash check binds which executable that identity runs. It does not sandbox the child from the wrapper.

The child environment is a fixed key list: `PATH`, `HOME` set to the journal directory, locale, App id, installation id, key path, feature, and tool list. It does not inherit the parent environment. Shadow, check workers, and project worktrees do not receive the key or the journal. Check mount policy is unchanged and does not name these paths.

Templates that are not applied by this change:

- `config/github-collaboration/vedaops-github.service`
- `config/github-collaboration/sysusers.conf`
- `config/github-collaboration/tmpfiles.conf`

Do not `systemctl enable` the unit. It is a sandbox profile for a foreground stdio process. Creating the user, directories, App, or connector is host and GitHub administration and needs a separate CHAZ action.

Disabling F008 is `enabled = false` in the operator policy, or not running `vedaops-github`. The Shadow tool catalog does not include these tools. Removing the package does not remove Orient, Inspect, Change, or Check.

Revocation is: set `enabled = false`, stop any F008 process, delete or shred `/etc/vedaops-github/app.pem`, and uninstall or suspend the GitHub App installation in GitHub. Suspended installation tokens stop working on their own expiry as well. Shadow keeps running. The journal can remain for evidence; it does not contain the key.

## Local commands

```bash
export VEDAOPS_GITHUB_POLICY=/etc/vedaops-github/policy.toml
export VEDAOPS_GITHUB_PRINCIPAL=example-steward
uv run vedaops-github validate-policy --policy "$VEDAOPS_GITHUB_POLICY"
uv run vedaops-github render-launch --policy "$VEDAOPS_GITHUB_POLICY"
uv run vedaops-github validate-artifact /path/to/github-mcp-server_Linux_x86_64.tar.gz \
  --name github-mcp-server_Linux_x86_64.tar.gz
uv run vedaops-github hash-executable /usr/local/lib/vedaops-github/github-mcp-server
uv run vedaops-github validate-catalog /path/to/tools-list.json
uv run vedaops-github stdio
```

`render-launch` prints argv and the child environment. It does not read the PEM. `validate-catalog` accepts either a JSON list of names or a `tools/list` result.

## Minimum human GitHub setup

These steps are not done by the implementation:

1. CHAZ creates a GitHub App owned by the intended account, with the permissions in the table above, including Pull requests write and excluding Issues write.
2. CHAZ generates a private key and places only the PEM at the root-owned secret path.
3. CHAZ installs the App on the specific repositories that will appear in operator policy, not on all repositories.
4. CHAZ records the App id and installation id in the root-owned operator policy outside the repositories and outside the journal.
5. CHAZ, or an authorized operator, downloads the `v1.12.2` Linux tarball, checks the archive digest, installs the executable under `/usr/local/lib/vedaops-github/`, and records that file's SHA-256 as `executable_sha256`.
6. CHAZ creates the `vedaops-github` account and the trusted configuration and journal directories if they do not exist. Development checkouts stay on their existing paths and owners.
7. CHAZ sets `provider_login` to the App's bot login, commonly the App slug plus `[bot]`.
8. CHAZ authorizes a distinct ChatGPT connector whose command is `vedaops-github stdio` as `vedaops-github`. Do not reuse the Shadow connector.
9. Only after that connector exists does a Steward run the live verification below.

## Live verification

Run this once, against the configured App, after the setup above. Do not treat it as Product acceptance.

1. `github_server_info` shows release `v1.12.2`, commit `85598ba6…`, feature `pull_requests_granular`, and `shadow_coupled: false`.
2. The child initialize version and `validate-catalog` agree with the allowlist. `merge_pull_request` is absent. Independently hash the installed executable and confirm it matches `executable_sha256`. The child's version string is not that proof.
3. `github_identity_get` on an authorized repository reports the App id and installation id. `get_me` may be unavailable for an installation token; that is a limitation, not success.
4. The same read against a repository that is not granted returns a denial and does not call the provider for that repository.
5. `github_commit_get` on the published head branch returns the live SHA. Compare it with the intended candidate. A local remote-tracking ref is not the source.
6. One authorized write inside Pull requests write, such as a title update, a reviewer request, or one timeline comment, on a pull request CHAZ has designated for the tracer. Record the journal file before the call if you are watching the directory, then the terminal record and the re-read native state, including body and draft when the operation set them.
7. Confirm the journal file exists outside the project root and does not contain the PEM.
8. For the uncertain-effect step, interrupt the child after dispatch only in a way CHAZ has allowed, then confirm the result is `uncertain`, `retry_performed` is false, and a second pull request or comment was not created. If no safe interrupt is available, skip this step and say it was not run.
9. `github_pull_request_read` method `get_reviews` shows reviewer logins. The provider login is not independent.
10. Start a new Steward session and reconstruct the candidate SHA, journal operation id, GitHub pull request number, and URL from the repository, the journal, and GitHub. Do not rely on the earlier chat.
11. Set `enabled = false`, restart only the F008 process, and confirm Shadow's tool list is unchanged and a GitHub write is refused.
12. Revoke by the procedure above only when CHAZ asks for revocation.

## Checks that this repository can run before that setup

`uv run pytest -q tests/test_github_collaboration.py` uses fakes. It does not contact GitHub and does not prove the live App, the real binary's catalog, or network behavior. `validate-artifact` proves a supplied release archive. `hash-executable` and the launch check prove only the file whose path is hashed. A passing fake is not proof of the pinned GitHub MCP Server.
