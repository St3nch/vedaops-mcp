# VedaOps MCP Project Onboarding Guide

This guide is the canonical procedure for onboarding a repository into the VedaOps project workflow.

Onboarding covers two separate authority planes:

1. **VedaOps MCP Shadow** — local repository Orient, Inspect, Change, and Check.
2. **VedaOps GitHub / F008 GitHub Collaboration** — native GitHub collaboration through the separate `vedaops-github` process, when that plane is intended.

F008 is accepted, live, and part of normal project work. It is optional for each project. A repository that only needs local work is onboarded when Shadow represents it correctly. A repository that also needs pull-request collaboration is onboarded when both planes represent it correctly.

The Shadow goal is:

> A fresh Steward should be able to identify the project, read its accepted context, understand its effective authority, inspect Git state, make only explicitly delegated local changes, and run only operator-approved checks.

The F008 goal, when that plane is in scope, is:

> The same Steward, through the separate VedaOps GitHub client, should be able to read the granted repository and perform only the pull-request collaboration classes the operator granted.

Onboarding a repository does **not** grant Product authority, push permission, merge permission, deployment authority, provider spend, release authority, repository administration, or arbitrary execution.

---

## 1. Mental model

Project onboarding has two planes. They stay mechanically and conceptually separate.

```text
Project onboarding
├── Local development authority
│   └── VedaOps MCP Shadow
│       ├── read
│       ├── change
│       └── check
└── GitHub collaboration authority
    └── VedaOps GitHub / F008
        ├── read
        ├── PR create
        ├── title/body update
        ├── PR comments
        └── reviewer requests
```

| Plane | Process | Principal | Authority source |
| --- | --- | --- | --- |
| Local repository | VedaOps MCP Shadow | `chatgpt-shadow` | Shadow operator registry/policy, confirmed with `vedaops_server_info` |
| GitHub collaboration | `vedaops-github` | `project-steward` | `/etc/vedaops-github/policy.toml` |

These boundaries hold for every project:

- A Shadow grant does not authorize GitHub.
- An F008 grant does not authorize Shadow.
- Adding a repository to the VedaOps Steward GitHub App installation gives that installation credential reachability to the repository. It does not grant F008 authority.
- F008 authority comes from the external operator policy at `/etc/vedaops-github/policy.toml`.
- Shadow authority comes from its own external operator registry/policy.
- Repository files cannot enlarge either operator grant.
- The F008 principal is `project-steward`. The Shadow principal is `chatgpt-shadow`.
- An F008 project `root` is operator-declared provenance and a lexical trust boundary. F008 does not traverse or own the project checkout.
- Project development checkouts stay owned by the development user. Do not `chown` them to `vedaops-github`.
- The VedaOps Steward GitHub App stays installed only on selected repositories.
- Push, merge, Product acceptance, deployment, provider spend, release authority, and repository administration stay separately governed. Onboarding does not grant them.
- F008 has no merge class and no push class. Naming either class makes the F008 policy invalid.
- VedaOps does not keep a second copy of GitHub pull-request lifecycle state. GitHub remains authoritative for that state.
- Grant the smallest operation set the project actually needs.

### Shadow authority

VedaOps MCP Shadow separates four things that are easy to accidentally blur together:

1. **Project manifest** — what the repository declares it can support.
2. **Operator policy** — the external capability ceiling for that project.
3. **Principal grant** — what one launcher-bound principal is allowed to do.
4. **Operation restrictions** — hard rules enforced by the controller for the specific tool.

Effective authority is the intersection:

```text
principal grant
∩ operator project ceiling
∩ project-manifest narrowing
∩ operation restrictions
```

A repository cannot grant itself more authority by editing its manifest.

A tool appearing in the MCP catalog also does not mean that tool is authorized for every project. Always inspect the project's **effective capabilities**.

The Shadow capability vocabulary is:

- `read`
- `change`
- `check`

Unknown capability names fail closed.

### F008 authority

F008 evaluates a different intersection, and only inside `vedaops-github`:

```text
project-steward grant for that project
∩ project mapping to one github_owner/github_repo
∩ operation class
∩ App installation reachability for that selected repository
```

The operation classes are `read`, `pr_create`, `pr_update_title`, `pr_update_body`, `pr_comment`, and `pr_request_reviewers`.

The App installation and the policy grant answer different questions. Reachability means the installation token can address that selected repository. The grant means `project-steward` may ask F008 to perform those classes there. A call needs both. `VEDAOPS_AGENT_ID` does not name the F008 principal. Shadow project policy is not consulted.

The security model, provider pin, permission table, and one-time connector verification stay in [`github-collaboration.md`](github-collaboration.md). This guide is the per-project onboarding and migration procedure.

---

## 2. What belongs where

### Repository-owned

Typical repository-owned onboarding material:

- `.vedaops/project.toml`
- `README.md`
- `AGENTS.md`
- `CURRENT.md` or another current-state/authority entrypoint
- project code and tests

The manifest is readable project authority, but ordinary VedaOps Change operations cannot mutate it.

### Operator-owned, VedaOps MCP Shadow

The active Shadow registry/policy must live outside managed project roots.

Typical Shadow policy:

```text
~/.config/vedaops/mcp/projects-shadow.toml
```

The exact path is launcher/operator configuration. Confirm it with `vedaops_server_info`; do not assume it from this guide.

Shadow operator policy defines:

- registered project roots;
- workspace identity;
- project capability ceilings;
- context files;
- approved checks;
- principal grants.

### Operator-owned, VedaOps GitHub

F008 operator policy lives at `/etc/vedaops-github/policy.toml`. It holds project mappings and the grants under `project-steward`. The file is root-owned and readable by the `vedaops-github` account, which cannot rewrite it.

The VedaOps Steward GitHub App installation, limited to selected repositories, is credential reachability. It is a separate operator fact from the policy grant.

The App private key stays at its root-owned secret path. It does not belong in a project repository, a manifest, Shadow policy, or this guide.

F008 records each project `root` as declared provenance. The policy file, the App key, the provider executable, and the journal sit outside every declared project path. The development user keeps ownership of the checkout.

Do not place credentials, provider secrets, deployment secrets, or application DSNs in project manifests or either operator policy merely to make onboarding convenient.

---

## 3. Repository prerequisite

The repository must have a valid `.vedaops/project.toml`.

Minimal example:

```toml
schema_version = 1
id = "example-project"
name = "Example Project"
mutable = true
capabilities = ["read", "change", "check"]
```

Meaning:

- `id` is the stable project identifier used by MCP calls and operator policy.
- `name` is the human-readable project name.
- `mutable = true` means the project is willing to participate in Change. It does **not** grant Change.
- `capabilities` narrows what the repository supports. It does **not** grant those capabilities.

For a permanently read-only repository, use:

```toml
mutable = false
capabilities = ["read"]
```

A repository may declare `read/change/check` while the operator initially grants only `read`. That is useful when onboarding begins with verification before mutation authority is enabled.

---

## 4. Git author identity is a Change prerequisite

Shadow deliberately runs Git with global and system Git configuration disabled.

That means a user's normal global `user.name` and `user.email` are not sufficient for `project_git_commit`.

A mutable repository that will be committed through Shadow should have an intentional **repository-local** Git author identity:

```bash
git config --local user.name "Desired Name"
git config --local user.email "desired@example.com"
```

To reuse an already-established repository identity when appropriate:

```bash
git config --local user.name "$(git log -1 --format='%an')"
git config --local user.email "$(git log -1 --format='%ae')"
```

Then verify:

```bash
git config --local --get user.name
git config --local --get user.email
```

VedaOps allows these local Git configuration keys, but the identity is an operator/repository decision. Do not invent an identity merely to get a commit through.

If identity is missing, `project_git_commit` fails closed rather than falling back to ambient global configuration.

---

## 5. Add the project to Shadow operator policy

Use the active Shadow policy identified by `vedaops_server_info`.

Example registration:

```toml
[[projects]]
id = "example-project"
name = "Example Project"
status = "active"
root = "/absolute/path/to/example-project"
workspace_id = "primary"
mutable = true
capabilities = ["read", "change", "check"]
context_files = ["README.md", "AGENTS.md", "CURRENT.md"]
```

The root should be the canonical repository root.

The initial implementation uses one registered ordinary workspace per project. Do not point the policy at arbitrary Git administrative indirection or a guessed path.

### Start read-only when practical

For a new project, a useful first step is to register only:

```toml
mutable = false
capabilities = ["read"]
```

and grant the principal only `read`.

This lets the Steward verify identity, context, manifest validity, and Git state before mutation authority exists.

When Change/Check are later needed, deliberately widen the Shadow project ceiling and principal grant after the repository manifest already supports them.

This registration is the Shadow plane. It does not add a GitHub project mapping, an App installation, or an F008 grant.

---

## 6. Grant the Shadow principal

Example:

```toml
[[principals]]
id = "chatgpt-shadow"
projects = { "example-project" = ["read"] }
```

Later, when authorized:

```toml
[[principals]]
id = "chatgpt-shadow"
projects = { "example-project" = ["read", "change", "check"] }
```

The principal ID comes from the trusted launcher through `VEDAOPS_AGENT_ID`.

`chatgpt-shadow` is the Shadow principal. The table above is the Shadow registry shape. The F008 principal is `project-steward` in `/etc/vedaops-github/policy.toml`, and its grants use the separate shape in section 16. Grants are not copied from one file to the other.

Do not treat a model name, chat role, ticket, branch name, or prose statement as a mechanical grant.

---

## 7. Select context files deliberately

`context_files` are the bounded documents returned by `project_context_get`.

Good context files help a fresh Steward answer:

- What is this project?
- Who has Product authority?
- What rules govern agents?
- What is current?
- Where is accepted policy/specification?

A common set is:

```toml
context_files = ["README.md", "AGENTS.md", "CURRENT.md"]
```

Do not stuff the context list with the whole repository. Context files are orientation material, not a substitute for bounded file reads and search.

---

## 8. Configure checks only when the project has real checks

Checks live in **operator policy**, not caller arguments.

Example system-runtime check:

```toml
[[projects.checks]]
id = "syntax"
argv = ["/usr/bin/python3", "-m", "compileall", "-q", "src", "tests"]
timeout_seconds = 30
memory_mb = 512
runtime = "system"
```

Example project-venv check:

```toml
[[projects.checks]]
id = "test"
argv = ["/runtime/bin/uv", "run", "--offline", "--no-sync", "pytest", "-q"]
timeout_seconds = 120
memory_mb = 1024
runtime = "project_venv"
```

PostgreSQL-backed checks additionally declare:

```toml
substrate = "postgres18"
```

Important:

- callers select an approved check ID; they do not supply arbitrary argv;
- `project_venv` requires an already provisioned project `.venv`;
- VedaOps captures a sanitized runtime rather than mounting the live venv into the check worker;
- ordinary checks use `project_check_run`;
- `postgres18` checks use `project_postgres_check_run`;
- checks exercise an exact committed subject, not dirty working-tree bytes.

If a project has no meaningful configured check yet, report **no configured checks**. Do not invent a ceremonial check just to make onboarding look complete.

---

## 9. Read-only Shadow onboarding verification

This section verifies the Shadow plane. Before enabling mutation, verify the project from the client that will actually use Shadow.

### A. Verify the live controller

Inspect `vedaops_server_info` and record:

- principal ID;
- loaded controller artifact identity;
- Python/runtime identity;
- operator-policy path and digest;
- tool catalog identity;
- effective grants.

The installed detached runtime and the source checkout are separate facts.

`source_revision_state = "unavailable"` can be normal for an installed detached runtime with no nearby `.git`. The loaded package-tree identity is the important runtime observation.

### B. Verify registration

Use `projects_list` and/or `project_get`.

Confirm:

- correct project ID/name;
- status is active;
- canonical root;
- workspace ID/kind;
- manifest validity;
- registry capabilities;
- principal grant;
- effective capabilities;
- effective mutability;
- configured context files;
- configured checks.

### C. Read approved context

Use `project_context_get` and confirm each configured context document is accessible and not unexpectedly truncated.

### D. Inspect Git

Use `project_git_status` and establish:

- exact HEAD;
- branch;
- detached/non-detached state;
- clean/dirty state;
- visible status entries.

Do not mutate merely to prove that mutation exists.

A real later change is better evidence than a fake smoke edit.

---

## 10. Enabling Change and Check

Change requires all relevant layers to agree.

For Change, normally verify:

- project manifest: `mutable = true`;
- project manifest includes `change`;
- operator project registration: `mutable = true`;
- operator project capabilities include `change`;
- principal grant includes `change`;
- project is active;
- requested operation satisfies its own restrictions.

Check similarly requires `check` through the capability intersection **and** a configured approved check ID.

After policy changes, re-run `vedaops_server_info` / `project_get` and verify the effective result. Do not infer success from the policy file alone.

---

## 11. Change behavior

The Change plane supports bounded local repository work such as:

- create/replace/delete bounded UTF-8 files;
- exact hash-protected replacement;
- validated text patches;
- working-tree and staged Git diffs;
- exact-path local commits;
- ordinary local branch creation/switching;
- fast-forward-only local integration;
- safe deletion of an already-merged non-current local branch.

Important protections include:

- exact expected-HEAD preconditions;
- protected repository/control paths;
- no implicit stash;
- no force reset;
- no arbitrary caller-selected Git argv;
- no repository-controlled hooks during commit;
- no push/fetch/pull.

The manifest itself and Git administrative storage are not ordinary Change targets.

---

## 12. Exact commit behavior and MCP-05 recovery

`project_git_commit` requires an exact expected HEAD and commits exactly named changed paths.

It refuses a pre-existing dirty/staged index. This prevents Shadow from accidentally consuming staging created by a human or another tool.

MCP-05 adds bounded recovery for failures that occur **after Shadow itself staged the requested paths**.

### Proven non-commit

If Shadow can prove:

- HEAD is still the expected HEAD;
- branch is unchanged;
- staged paths are only paths from this invocation;
- restoring the index succeeds and postconditions prove it clean;

then it unstages only those paths, preserves working-tree edits, and returns the original commit failure. A later retry is possible after the underlying problem is fixed.

Example: missing Git author identity.

### Recovered success

If an exception occurs after Git actually created the commit, Shadow may return success only when it observes a matching child commit with the expected parent, branch, exact paths, commit message, and required clean-index evidence.

The journal records that success was recovered after an exception. This is matching-state observation under the VedaOps project lock, not cryptographic proof that one particular process created the commit.

### Uncertain effect

If state cannot be proven safely — for example HEAD drift, branch drift, unrelated staged paths, failed state observation, or failed/incomplete index restore — the result remains:

`VEDAOPS_GIT_EFFECT_UNCERTAIN`

Do not blindly retry an uncertain Git effect.

Inspect HEAD, branch, index, and working tree first.

### Previous-process staged state

MCP-05 recovery is same-invocation recovery.

If an older process already left staged state behind, a new invocation cannot prove whether those staged entries belong to Shadow or a human. It correctly refuses them as pre-existing index state.

Operator inspection/recovery is then required.

---

## 13. Check behavior

Checks run against exact committed source captured into disposable restricted execution.

That has an important workflow consequence:

```text
edit
→ inspect diff
→ commit exact candidate
→ run checks against that commit
→ review / accept / integrate as applicable
```

Running a check while the desired changes are only dirty working-tree files checks the previous committed subject, not those dirty bytes.

Check evidence should identify the actual captured subject, check definition, runtime/substrate, result, truncation, cleanup, and limitations.

Large or many-minute suites that would make ordinary MCP requests unreliable should remain operator-run until a separately justified asynchronous mechanism exists.

---

## 14. What Shadow deliberately does not provide

Core Shadow does **not** provide:

- a general shell;
- caller-selected arbitrary commands;
- caller-selected arbitrary Git argv;
- fetch/pull/push;
- force reset/rebase/history rewriting;
- implicit stash;
- GitHub PR/review/merge/release writes;
- deployment/runtime administration;
- provider/model invocation or spend;
- persistent application database administration;
- project Product decisions.

Bounded pull-request collaboration, when the project needs it, is the F008 plane in the sections below. F008 can read a granted repository and can create a pull request, update its title or body, comment on it, and request reviewers. F008 still has no merge, no push, no review submission, and no Product acceptance. Widening Shadow does not turn those GitHub classes on.

Absence of a capability from Shadow is a boundary. Add it on the F008 plane only when that plane is intended, using the F008 grant procedure below.

---

## 15. Common onboarding failures

### `VEDAOPS_PROJECT_NOT_AUTHORIZED`

The principal does not have an effective grant for that project.

Inspect the operator project entry, principal grant, project status, and manifest. Do not widen permissions until Product/operator authorization exists.

### Manifest invalid / unknown capabilities

Current next-generation manifests understand:

`read`, `change`, `check`

Old vocabulary such as `write`, `patch`, or `execute` belongs to the legacy controller and is not valid next-generation manifest vocabulary.

### `VEDAOPS_GIT_INDEX_DIRTY`

The Git index already contains staged state before the commit operation.

Do not let Shadow guess who owns it. Inspect and reconcile it explicitly.

### `VEDAOPS_GIT_UNAVAILABLE: Author identity unknown`

Configure an intentional repository-local `user.name` and `user.email`.

Do not rely on global Git config; Shadow intentionally ignores it.

### `VEDAOPS_GIT_EFFECT_UNCERTAIN`

A Git operation may have changed state, but Shadow cannot prove the terminal result safely.

Inspect:

- current HEAD;
- branch;
- staged/index state;
- working-tree state;
- operation evidence.

Do not automatically retry.

### Check unavailable

Confirm:

- effective `check` capability;
- check ID exists in operator policy;
- the requested tool matches its substrate;
- required project `.venv` exists for `project_venv`;
- required host isolation/runtime prerequisites are available.

Do not silently fall back to unsafe execution.

### `source_revision_state = unavailable`

For a detached installed runtime, this can be expected. Verify the loaded package artifact identity instead of assuming the running controller came from the current development checkout.

---

## 16. F008 operator policy

F008 grants live in `/etc/vedaops-github/policy.toml`, outside every project root it names. The repository schema example is [`config/github-collaboration.toml.example`](../config/github-collaboration.toml.example). The live file already contains the provider pin, the journal, the `enabled` flag, and one principal. Per-project onboarding adds a project mapping and a grant. It leaves that surrounding policy in place.

The live policy supports multiple project mappings and multiple grants under one principal.

Project mapping:

```toml
[[projects]]
id = "example-project"
root = "/home/chaz/projects/vedaops/example-project"
github_owner = "St3nch"
github_repo = "example-project"
```

`id` is the VedaOps project id. When both planes name the project, use the same id as `.vedaops/project.toml` and the Shadow registration.

`root` is the absolute path the operator declares for that checkout. F008 stores the string as provenance and uses it as a lexical boundary: the policy file, the App private key, the provider executable, and the journal must sit outside every declared project root. F008 does not stat, own, or traverse the checkout. Local reads and edits stay with Shadow and the development user. `ProtectHome=yes` stays on the F008 service. Do not mount `/home` into the F008 sandbox, and do not `chown` the checkout to `vedaops-github`.

`github_owner` and `github_repo` name the real GitHub repository. Each GitHub repository belongs to only one F008 project. Project ids are unique.

The principal remains the single existing entry. The block below is that entry. Add grants beneath it. Pasting a second copy makes the policy invalid:

```toml
[[principals]]
id = "project-steward"
```

Additional projects are additional grants under that same principal:

```toml
[[principals.grants]]
project = "example-project"
operations = [
  "read",
  "pr_create",
  "pr_update_title",
  "pr_update_body",
  "pr_comment",
  "pr_request_reviewers",
]
```

The parser requires principal ids to be unique. A second `[[principals]]` table with `id = "project-steward"` makes the policy invalid. The parser also permits only one grant per principal/project pair. To change what an existing project may do, edit that project's existing grant. A second `[[principals.grants]]` for the same project is invalid.

A normal collaboration grant is the six classes above: read, pull-request creation, title update, body update, timeline comment, and reviewer request. Merge and push are not operation classes.

A read-only grant is valid, and it is the appropriate grant for a completed, archival, or observation-only project. For that project the one grant is:

```toml
[[principals.grants]]
project = "example-project"
operations = ["read"]
```

That list is the whole grant. It is not appended beside the six-class list. Choose one operation list on purpose. Active pull-request collaboration uses the six classes when that authority has been authorized. Observation uses `["read"]`.

`project-steward` is the principal named by `VEDAOPS_GITHUB_PRINCIPAL` on the VedaOps GitHub launcher. It is a different principal from `chatgpt-shadow`.

Repository files, including `.vedaops/project.toml`, are not an F008 grant. Shadow's project map is not an F008 grant. Installing the VedaOps Steward GitHub App on the repository is not an F008 grant. The installation lets the installation token reach that selected repository. The grant in this file is what `project-steward` may ask F008 to do.

---

## 17. New project onboarding

Use this sequence for a repository that is missing the planes you intend to use. Stop after the last plane that is in scope.

1. Establish and inspect the real repository and its Git state. Record the canonical root, current branch, HEAD, and whether the worktree is clean. When GitHub collaboration is in scope, confirm `github_owner` and `github_repo` from the real GitHub repository.
2. Create or verify `.vedaops/project.toml` as in section 3. The manifest narrows what the repository can support. It grants nothing by itself.
3. When Shadow will commit, set a repository-local Git author identity as in section 4.
4. Select context files as in section 7. Keep the list to orientation documents.
5. Add the project to the Shadow operator policy identified by `vedaops_server_info`, as in section 5.
6. Grant `chatgpt-shadow` `read` first when practical, as in section 6.
7. Configure only real checks, as in section 8. When the project has no meaningful check, leave the check list empty and say so.
8. Verify the project through the live Shadow client, as in section 9. Record principal, runtime, policy, effective authority, context, and exact Git state.
9. When Change and Check are authorized, widen the Shadow project ceiling and the `chatgpt-shadow` grant, then verify the effective intersection again, as in section 10. Leave the project at `read` when mutation is not authorized.
10. When GitHub collaboration is needed, add the repository to the existing VedaOps Steward GitHub App installation as a selected repository. Keep the installation on selected repositories, and add this repository only. This step creates credential reachability. It does not write an F008 grant.
11. Add the project mapping to `/etc/vedaops-github/policy.toml` as in section 16. Leave the provider pin, journal, `enabled` flag, and the existing `project-steward` principal id in place.
12. Add one grant under that existing principal. Choose `operations = ["read"]` or the normal pull-request collaboration list on purpose.
13. Validate the F008 policy, then restart only `vedaops-github`, as in section 19.
14. Verify from the real VedaOps GitHub MCP client with the read-only checks in section 19.
15. Let genuine later project work exercise Shadow writes and F008 writes. Onboarding does not require a manufactured file edit or a manufactured pull request.

Push, merge, Product acceptance, deployment, provider spend, release, and repository administration remain separate authorizations after this sequence.

---

## 18. Existing project onboarding

Onboarding an existing project reconciles what is missing. Inventory the current planes, then add only the absent piece. Keep a correct Shadow manifest, a correct Shadow policy entry, a correct F008 mapping, and a correct grant.

Inventory:

- Shadow manifest: `.vedaops/project.toml` present, next-generation capabilities, and the intended mutability.
- Shadow policy: project id, canonical root, ceiling, context files, checks, and the `chatgpt-shadow` grant.
- Live Shadow view: `project_get` effective capabilities match that intent.
- App reachability: whether this repository is one of the selected repositories on the existing VedaOps Steward GitHub App installation.
- F008 policy: one `[[projects]]` entry for this id and `owner/repo`, and one `[[principals.grants]]` under `project-steward`.
- Checkout ownership: the development user owns the working tree.
- Project posture: active collaboration, or completed, archival, or observation-only.

Then apply the matching case.

**Already in Shadow, absent from F008.** Keep the Shadow manifest and Shadow policy. When the App installation does not yet include the repository, add it as a selected repository. Then add the F008 project mapping and one grant, validate, restart only `vedaops-github`, and run the F008 read-only verification.

**The App already reaches the repository, and F008 policy has no mapping or grant.** Add only the F008 mapping and one grant. Leave the App installation and the Shadow registration as they are.

**F008 policy already maps the project, and the App is not installed on that repository.** Add selected-repository installation access for that repository. Leave unrelated repositories unchanged, and leave the App on selected repositories. Keep the existing mapping and grant when they already match the intended operations.

**A historical repository is not in Shadow yet.** Perform the missing Shadow steps from section 17: manifest, local Git identity when Shadow will commit, context files, Shadow policy, `read` first, real checks, and live Shadow verification. Widen Shadow only when that authority is authorized. An older repository has Shadow coverage only after those steps exist.

**The project is completed, archival, or observation-only.** Use an F008 grant of `operations = ["read"]`. When a broader grant is already present and observation is now the remaining need, edit that existing grant down to `["read"]` as a deliberate operator change. A second grant for the same project is invalid. Keep Shadow at `read` when the repository should stay read-only, and align the manifest and the Shadow ceiling with that choice.

**Both intended planes already match.** Verify them. Recreating an entry that is already correct adds nothing.

A Shadow registration leaves F008 unchanged. An F008 grant leaves Shadow unchanged. Add each plane only when that plane is intended.

---

## 19. Validate, reload, and verify F008

Validate the live policy as `vedaops-github` before any restart. On the accepted live installation:

```bash
sudo -u vedaops-github \
  /usr/local/bin/vedaops-github validate-policy \
  --policy /etc/vedaops-github/policy.toml
```

When validation succeeds, restart only the VedaOps GitHub user service so that process loads the new policy:

```bash
systemctl --user restart vedaops-github.service
```

The running process keeps the policy it loaded at start. The restart above is what loads the edited file, and it restarts `vedaops-github` only. An F008 policy change is not a reason to restart Shadow. When validation fails, correct the policy and validate again before restarting.

After the reload, verify from the real VedaOps GitHub MCP client with reads:

- `github_server_info` — `enabled` is true, `principal_id` is `project-steward`, and the provider release and commit match the pinned provider in [`github-collaboration.md`](github-collaboration.md). `shadow_coupled` is false.
- `github_identity_get` — call it with the project's id and `owner/repo`. A successful read confirms that pair is granted. Report the configured App id, installation id, and `provider_login` as separate facts, and report the provider release and commit returned with that identity. `github_identity_get` may report authenticated-user lookup unavailable (`authenticated_user_lookup_unavailable`; an installation token may have no user). That limitation is expected for an installation token. Report it. Onboarding can still succeed with that limitation. The configured App id, installation id, and `provider_login` do not identify which actor authenticated a native request.
- `github_commit_get` — pass the repository's default or published branch as `ref` and record the live SHA. The result comes from GitHub. A local remote-tracking ref is a different fact.
- `github_actions_list` — use this when workflow, run, or job visibility matters for that repository. The accepted methods list workflows, runs, and jobs.

A later native pull-request write, made because the project actually needs one, can establish the visible bot actor. That actor is still not Product acceptance. Product acceptance remains a human decision.

Onboarding verification stops at these reads. A smoke write, smoke comment, or smoke reviewer request is not the proof. The one-time connector tracer in [`github-collaboration.md`](github-collaboration.md) remains a separate CHAZ-designated check.

A repository with no F008 grant fails closed before a provider call. That denial is the correct result for a project that was left off the F008 plane.

---

## 20. Minimal onboarding checklist

Use this as the short path across both planes. Skip steps 13–16 when the project is Shadow-only.

1. Confirm the canonical repository root, the GitHub `owner/repo` when collaboration is in scope, and the current Git state.
2. Create or verify `.vedaops/project.toml` with next-generation capabilities.
3. Identify useful authority and current context files.
4. Configure repository-local Git author identity if Shadow will commit.
5. Add the project to the external Shadow operator policy, or keep the existing Shadow entry when it is already correct.
6. Grant `chatgpt-shadow`, preferably `read` first for a new onboarding.
7. Configure only real checks the project actually needs.
8. From the real Shadow client, inspect `vedaops_server_info`.
9. Verify registration and effective authority with `projects_list` / `project_get`.
10. Read the approved context.
11. Inspect exact Git status and HEAD.
12. If authorized, enable Shadow `change` / `check` and verify the effective intersection again.
13. If GitHub collaboration is intended, add the repository to the existing VedaOps Steward GitHub App as a selected repository when it is not already selected.
14. If GitHub collaboration is intended, add the F008 project mapping and one grant under the existing `project-steward` principal. Use `["read"]` for an observation-only project.
15. Validate `/etc/vedaops-github/policy.toml`, then restart only `vedaops-github`.
16. From the real VedaOps GitHub client, read `github_server_info`, `github_identity_get`, and `github_commit_get` for the published branch.
17. Let the first genuine project task exercise writes. Do not manufacture a smoke mutation on either plane.
18. Keep push, merge, Product acceptance, deployment, provider spend, release, and repository administration separately authorized.

---

## 21. Fresh-session verification prompts

Use the prompt that matches the plane just onboarded. Use both when both planes were in scope.

### Shadow onboarding verification

```text
Verify the newly onboarded "<project-id>" project through VedaOps MCP Shadow.

This is read-only verification. Do not mutate files, Git state, policy,
runtime configuration, or external systems.

1. Inspect vedaops_server_info and report principal/runtime/policy identity.
2. Confirm the project is registered and active.
3. Report canonical root, workspace, manifest validity, declared/operator/
   effective capabilities, effective mutability, context files, and checks.
4. Read the approved project context.
5. Inspect Git status and HEAD.
6. Report exact observations and uncertainty.
7. Do not broaden permissions or perform a smoke mutation.
```

### VedaOps GitHub / F008 onboarding verification

```text
Verify the "<project-id>" project through VedaOps GitHub / F008.

This is read-only verification. Do not change policy, restart services,
edit GitHub objects, or perform a smoke write.

1. Inspect github_server_info.
2. Confirm collaboration is enabled and the principal is project-steward.
3. Confirm the exact project and owner/repo mapping through an authorized read.
4. Report the App id, installation id, configured provider login, and the
   provider release and commit.
5. Read the live default or published branch SHA with github_commit_get.
6. Report granted-visible behavior and limitations, including an unavailable
   authenticated-user lookup when github_identity_get reports one.
7. Do not perform a smoke write, comment, reviewer request, or pull request.
```

After read-only verification succeeds, widening either plane is a separate deliberate operator action.

---

## 22. Reality check

Success means the project is correctly represented on each authority plane the onboarding was intended to include.

For VedaOps MCP Shadow, that means:

- the right repository is registered;
- `chatgpt-shadow` can see only the capabilities it was granted;
- context is reconstructable;
- effective authority is explicit;
- Git state is observable;
- Change and Check work only when deliberately granted;
- failures preserve uncertainty.

For VedaOps GitHub, that means:

- the VedaOps Steward App installation reaches that selected repository;
- one F008 mapping names the real `owner/repo` and a declared root;
- one grant under `project-steward` lists only the intended operation classes;
- a fresh client can read server identity, the configured App facts, and the live published-branch SHA;
- onboarding stood on those reads.

A project intended for one plane is onboarded when that plane is correct. The other plane stays absent until someone deliberately adds it.

Push, merge, Product acceptance, deployment, provider spend, release authority, and repository administration remain outside onboarding.

The boring version is the good version: two small surfaces, explicit authority on each, exact subjects, native Git and GitHub semantics, and no copied lifecycle state.

