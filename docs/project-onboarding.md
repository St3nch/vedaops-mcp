# VedaOps MCP Project Onboarding Guide

This guide describes how to onboard a repository into VedaOps MCP Shadow without turning onboarding into a permission shortcut.

The goal is simple:

> A fresh Steward should be able to identify the project, read its accepted context, understand its effective authority, inspect Git state, make only explicitly delegated local changes, and run only operator-approved checks.

Onboarding a repository does **not** grant Product authority, push permission, deployment authority, provider access, or arbitrary execution.

---

## 1. Mental model

VedaOps MCP separates four things that are easy to accidentally blur together:

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

The current capability vocabulary is:

- `read`
- `change`
- `check`

Unknown capability names fail closed.

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

### Operator-owned

The active registry/policy must live outside managed project roots.

Typical Shadow policy:

```text
~/.config/vedaops/mcp/projects-shadow.toml
```

The exact path is launcher/operator configuration. Confirm it with `vedaops_server_info`; do not assume it from this guide.

Operator policy defines:

- registered project roots;
- workspace identity;
- project capability ceilings;
- context files;
- approved checks;
- principal grants.

Do not place credentials, provider secrets, deployment secrets, or application DSNs in project manifests or MCP policy merely to make onboarding convenient.

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

## 5. Add the project to operator policy

Use the active policy identified by `vedaops_server_info`.

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

When Change/Check are later needed, deliberately widen the operator project ceiling and principal grant after the repository manifest already supports them.

---

## 6. Grant the principal

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

## 9. Read-only onboarding verification

Before enabling mutation, verify the project from the client that will actually use Shadow.

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

Those may exist elsewhere under separate authority. Their absence from Shadow is usually a boundary, not a missing onboarding step.

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

## 16. Minimal onboarding checklist

Use this as the short operational path:

1. Confirm the canonical repository root and current Git state.
2. Create/verify `.vedaops/project.toml` with next-generation capabilities.
3. Identify useful authority/current context files.
4. Configure repository-local Git author identity if Shadow will commit.
5. Add the project to the external operator policy.
6. Grant the intended principal, preferably `read` first for a new onboarding.
7. Configure only real checks the project actually needs.
8. From the real Shadow client, inspect `vedaops_server_info`.
9. Verify registration/effective authority with `projects_list` / `project_get`.
10. Read approved context.
11. Inspect exact Git status/HEAD.
12. If authorized, enable `change/check` and verify the effective intersection again.
13. Let the first genuine project task exercise Change/Check; do not manufacture pointless mutations.
14. Keep push, deployment, provider spend, and other external effects separately authorized.

---

## 17. Fresh-session verification prompt

A useful verification request for a newly onboarded project is:

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

After read-only verification succeeds, capability widening should be a separate deliberate operator action.

---

## 18. Reality check

A successful onboarding means:

- the right repository is registered;
- the right principal can see only what it should;
- context is reconstructable;
- effective authority is explicit;
- Git state is observable;
- Change and Check work only when deliberately granted;
- failures preserve uncertainty instead of guessing;
- external effects remain separate.

It does **not** mean every VedaOps capability belongs inside MCP.

The boring version is the good version: small surface, explicit authority, exact subjects, native Git semantics, and no magic.

