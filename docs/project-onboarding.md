# Project Onboarding

This guide registers one existing Git repository with the Shadow VedaOps MCP.
Registration grants mechanical authority; finding a repository or adding a
manifest does not.

The legacy `linux-vedaops-mcp` onboarding guide is historical evidence only.
Shadow has no discovery-based authorization and does not recognize the legacy
`write`, `patch`, or `execute` capabilities.

## Authority model

Effective authority is the intersection of three independently reviewed
sources:

1. The launcher's `VEDAOPS_AGENT_ID` selects one principal.
2. The external operator registry grants that principal capabilities for one
   exact project root.
3. The repository's `.vedaops/project.toml` may accept or narrow those
   capabilities, but cannot enlarge them.

The only capabilities are:

| Capability | Meaning |
|---|---|
| `read` | Orient, inspect bounded files, and observe native Git state |
| `change` | Perform bounded, preconditioned local file and Git mutations |
| `check` | Run only operator-defined checks in the restricted runner |

`change` also requires `mutable = true` in both the registry and manifest.
There is no general shell, caller-selected command, generic Git interface,
remote Git mutation, deployment authority, or implicit Product acceptance.

## Prerequisites

Before editing either authority source, confirm:

- CHAZ has authorized this onboarding and its intended capability ceiling;
- the project is an ordinary Git worktree with a real in-root `.git`
  directory, not a linked worktree or `gitdir:` file;
- the root is a stable, canonical absolute path owned by the deployment plan;
- the project ID is unique and matches `^[a-z0-9][a-z0-9._-]*$`;
- the repository has no unsafe local Git configuration or unsupported Git
  administrative indirection;
- context files are small, authoritative, tracked or intentionally visible,
  and contain no secrets;
- each proposed check has deterministic argv and can run within the restricted
  execution boundary;
- the working tree is clean or every existing change is understood.

Operator policy, settings, credentials, controller installation data, and the
operation journal must remain outside every managed project root.

## Legacy-controller coexistence

Before placing a Shadow manifest, inspect the live legacy controller's
discovery roots. Both generations use `.vedaops/project.toml`, but the legacy
parser recognizes `read/write/patch/execute` while Shadow recognizes only
`read/change/check`. A Shadow manifest discovered by the legacy controller can
therefore make legacy project enumeration fail closed; using legacy
capabilities instead makes Shadow reject the manifest.

During coexistence, place Shadow-only project roots outside every legacy
discovery root, or first make a separately authorized legacy discovery/cutover
change. Do not invent a dual-capability manifest, weaken either parser, or
assume the failure affects only the newly discovered project. Verify both
controllers after any coexistence change.

## Step 1: Record the onboarding decision

Write down the exact project ID, name, canonical root, workspace ID, intended
principal, context files, checks, initial capabilities, and whether mutation is
intended. Treat each as an authorization input rather than inferring it from a
branch name, ticket, repository file, or prior registration.

Use `workspace_id = "primary"` for the single ordinary workspace unless the
operator has accepted a more specific stable identifier. Shadow does not yet
support linked-worktree lifecycle.

## Step 2: Add the project manifest

Create and review `.vedaops/project.toml` in the project:

```toml
schema_version = 1
id = "example-project"
name = "Example Project"
mutable = false
capabilities = ["read"]
```

The manifest declares no root, context paths, principal grants, check argv, or
credentials. Those remain operator policy. Unknown fields and capabilities are
rejected.

Commit the manifest through the project's normal native Git workflow before
using exact-commit checks. The Shadow Change plane deliberately protects
`.vedaops/project.toml`, so later manifest changes require a separately
authorized operator or native repository change; the project cannot grant
itself more authority through MCP.

## Step 3: Add the external registry entry

The default registry is
`~/.config/vedaops/mcp/projects.toml`. A deployment may instead set
`VEDAOPS_PROJECTS_REGISTRY` to another operator-owned absolute path, such as a
separate Shadow policy file. Do not reuse the legacy
`~/.config/vedaops/projects.toml` by accident.

The registry must be a regular non-symlink file, owned by the controller
service user, not group- or world-writable, and outside every managed project.

For a first-time deployment, prepare a private candidate outside every managed
project. Copying the example creates only a candidate; replace every sample
project, root, principal, grant, and check before validation:

```bash
install -d -m 700 ~/.config/vedaops/mcp
install -m 600 config/projects.toml.example ~/.config/vedaops/mcp/projects.candidate.toml
```

Validate the complete candidate with a disposable controller process using the
intended `VEDAOPS_AGENT_ID` and `VEDAOPS_PROJECTS_REGISTRY`. Confirm the
authoritative destination does not exist, then install the validated candidate
as `projects.toml` with mode `0600`. Stop if the destination exists; do not
overwrite it from this first-time path.

For an existing deployment, do not copy the example. Make a private backup and
a mode-`0600` candidate from the complete current live registry, preserve every
unrelated project and principal, edit and validate the candidate, then replace
the live file atomically while preserving service-user ownership. Retain the
backup until the live client path verifies the new policy fingerprint and
effective grants.

Add one exact project entry:

```toml
[[projects]]
id = "example-project"
name = "Example Project"
status = "active"
root = "/absolute/path/to/example-project"
workspace_id = "primary"
mutable = false
capabilities = ["read"]
context_files = ["AGENTS.md", "README.md"]
```

Requirements:

- `root` must be absolute, exist, and identify the intended ordinary worktree;
- only `status = "active"` grants current authority;
- project IDs, workspace IDs, context paths, and check IDs must be normalized;
- context paths must be unique normalized relative paths and are limited to 16;
- project entries and check definitions must be unique;
- the registry capability list is a ceiling, not an instruction to the
  repository.

Preserve existing projects and principals when updating a live registry. Use
an atomic replacement that retains service-user ownership and mode `0600`.

## Step 4: Grant the launcher-bound principal

Add the project to the exact principal used by the Shadow launcher. For the
dedicated ChatGPT Shadow deployment this is normally `chatgpt-shadow`; verify
the service configuration instead of assuming it.

```toml
[[principals]]
id = "chatgpt-shadow"

[principals.projects]
example-project = ["read"]
```

Do not create a generic or caller-selected identity. The launcher binds the
whole MCP process using `VEDAOPS_AGENT_ID`; the server does not independently
authenticate the person or model behind that launcher.

If the principal already exists, extend its existing `projects` table rather
than creating a duplicate principal. A principal grant for an unknown project
is invalid and prevents registry loading.

## Step 5: Verify read-only onboarding

Verify through the same running Shadow MCP instance and principal that the
client will use:

1. `vedaops_server_info` reports the expected principal, policy fingerprint,
   runtime artifact, source observation, and tool-contract fingerprint.
2. `projects_list` contains the project once and reports the expected root,
   workspace, manifest state, and effective `read` capability.
3. `project_get` reports the exact branch, full Git HEAD, dirtiness, context
   list, and capability intersection. During read-only onboarding its
   `check_ids` and check descriptors are empty even if the registry already
   contains definitions, because effective `check` has not been granted.
4. `project_context_get` returns only the selected context documents.
5. `project_tree`, `project_file_read`, `project_search`,
   `project_git_status`, `project_git_compare`, and the read-only Change-plane
   Git observations stay inside the project boundary and return bounded data.
6. Secret-like, ignored, `.git`, out-of-root, and symlink-escape paths are
   refused.

Shadow has no legacy `project_health` tool and no discovery/unregistered state.
If a project does not have an explicit registry entry and principal grant, it
is absent from the caller's authorized project list.

Resolve every unexpected root, identity, manifest, context, Git, or path result
before adding `check` or `change`.

## Step 6: Configure approved checks

Checks are operator policy. The caller selects a check ID, exact current Git
HEAD, and optionally a shorter timeout; it never supplies argv.

Example system-runtime check:

```toml
[[projects.checks]]
id = "syntax"
argv = ["/usr/bin/python3", "-m", "compileall", "-q", "src", "tests"]
timeout_seconds = 30
memory_mb = 512
runtime = "system"
```

Use `runtime = "project_venv"` only when the project has an already provisioned
`.venv` that must be captured into a sanitized temporary runtime. PostgreSQL
checks additionally set `substrate = "postgres18"` and require
`runtime = "project_venv"`.

Check definitions must satisfy the current hard limits: absolute sandbox
executable path, at most 32 bounded arguments, timeout from 1 through 120
seconds, and memory from 64 through 1024 MiB. Network is denied by default.
Never place tokens, passwords, caller-controlled values, or deployment actions
in a check definition.

To authorize a normal check, add `check` to all three capability lists:

```toml
# .vedaops/project.toml
capabilities = ["read", "check"]

# matching [[projects]] entry
capabilities = ["read", "check"]

# matching [principals.projects] table
example-project = ["read", "check"]
```

After committing the manifest change, run `project_check_run` against that
exact full HEAD. Confirm the receipt identifies the captured commit subject,
approved check and definition, runner profile, bounded output, cleanup,
limitations, and uncertainty state. Use `project_postgres_check_run` only for a
check whose operator definition selects the PostgreSQL substrate.

Very large or many-minute suites remain an operator-run `tmux` responsibility;
do not widen the MCP runner to accommodate them.

## Step 7: Enable bounded Change when intended

Only after read/check behavior is accepted, set both authority sources to:

```toml
mutable = true
capabilities = ["read", "change", "check"]
```

and grant the same required subset to the intended principal. A project may
omit capabilities it does not need.

Commit the manifest's Change-enabling edit through the separately authorized
native/operator workflow before attempting the MCP smoke test. The Change
plane cannot edit its own `.vedaops/project.toml` authority source.

Perform a harmless ticket-branch smoke test using exact preconditions:

1. Read `project_get`, `project_git_status`, and `project_git_branches`; record
   the exact current branch and full HEAD.
2. Create a dedicated local ticket branch from that exact HEAD.
3. Write or patch one non-protected documentation file.
4. Inspect the native working-tree diff.
5. Commit exactly the intended path against the unchanged expected HEAD.
6. Run one approved bounded check against the resulting exact candidate commit.
7. Obtain any required independent review and Product acceptance for that
   exact revision.
8. Only then switch to the intended target branch and perform a
   fast-forward-only local integration under exact preconditions.
9. Optionally delete the non-current ticket branch only after Git proves it is
   merged.
10. Inspect final Git state and the corresponding operation records under the
    registry's sibling `operations/` directory.

The MCP does not push. Publication remains a separate, explicit operator action
with fresh authorization.

## Common refusals

| Error code | Meaning and response |
|---|---|
| `VEDAOPS_IDENTITY_UNAVAILABLE` / `VEDAOPS_IDENTITY_INVALID` | Fix the launcher-bound `VEDAOPS_AGENT_ID`; do not accept a caller-supplied identity |
| `VEDAOPS_PRINCIPAL_UNKNOWN` | Add or correct the exact operator principal |
| `VEDAOPS_PROJECT_NOT_AUTHORIZED` | Add the explicit project entry and matching principal grant |
| `VEDAOPS_PROJECT_INACTIVE` | Review the lifecycle decision before setting the registry status to `active` |
| `VEDAOPS_MANIFEST_UNAVAILABLE` / `VEDAOPS_MANIFEST_INVALID` | Restore a valid, bounded schema-version-1 manifest |
| `VEDAOPS_PROJECT_ID_COLLISION` | Make the manifest ID match the unique registry ID and intended root |
| `VEDAOPS_CAPABILITY_DENIED` | Inspect all three capability lists and mutability; do not broaden them reflexively |
| `VEDAOPS_REGISTRY_INVALID` / `VEDAOPS_REGISTRY_INSECURE` | Correct schema, ownership, mode, type, or symlink use before restarting or retrying |
| `VEDAOPS_TRUSTED_PATH_INSIDE_MANAGED_PROJECT` | Move policy or operation state outside every managed project root |
| `VEDAOPS_PROJECT_CONFIG_UNSAFE` | Correct unsafe Git configuration or administrative indirection |
| `VEDAOPS_PATH_FORBIDDEN` / `VEDAOPS_PATH_ESCAPE` | Correct the requested path; do not weaken path policy |
| `VEDAOPS_STALE_GIT_HEAD` | Re-read current Git state and decide whether retrying is still authorized |
| `VEDAOPS_CHECK_NOT_AUTHORIZED` | Select an existing operator-defined check ID or review policy deliberately |
| recovery-required or uncertain effect | Inspect the named operation record and native repository/runtime state before any retry |

Do not solve a refusal by widening roots, grants, capabilities, check argv, or
execution authority. Establish the exact failing invariant first.

## Updating, suspending, or retiring a project

- Narrow or remove the principal grant first when immediate access revocation
  is required.
- Set registry `status` to a non-active value to revoke project operations
  while preserving the entry for inspection and recovery.
- Review context and check definitions whenever project authority or the build
  system changes.
- Change the manifest and registry independently; the more restrictive source
  continues to win.
- Confirm no operation is active or uncertain before removing the project.
- Preserve operation records needed for recovery and audit.
- Before removing a registry project entry, remove its key from every
  `[principals.projects]` table in the same validated candidate. Otherwise the
  dangling principal grant makes the complete registry invalid. Once both are
  removed, Shadow retains no discoverable unregistered project record.
- Retirement, policy removal, repository deletion, and legacy-controller
  cutover are separate decisions.

## Completion checklist

- CHAZ authorization recorded for the intended scope
- Unique project ID and exact canonical ordinary-worktree root
- Valid committed schema-version-1 manifest
- External service-user-owned registry, mode `0600`, outside all managed roots
- Exact launcher-bound principal grant
- Minimal effective capability intersection verified
- Minimal secret-free context set verified through the live client path
- Native Git identity, branch, HEAD, and dirty state inspected
- Bounded read and refusal behavior verified
- Every check is operator-defined, deterministic, isolated, and proven against
  an exact committed subject
- `change` and `mutable` enabled in both sources only when intended
- Harmless exact-precondition Change lifecycle proven when Change is granted
- Operation records and uncertainty handling inspected
- Server policy/tool fingerprints and client-visible catalog observed
- No general shell, caller-selected argv, remote Git mutation, deployment
  authority, or project-supplied privilege expansion introduced
