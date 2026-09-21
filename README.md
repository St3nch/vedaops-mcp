# VedaOps MCP

Repository: `https://github.com/St3nch/vedaops-mcp`

Status: bootstrap project for the next-generation VedaOps development control plane.

VedaOps MCP is a small, capability-limited interface for capable LLMs and development agents to orient to registered projects, inspect repository truth, make explicitly delegated local changes, and run accurately scoped development checks.

The core Product has four responsibilities:

1. **Orient** — identify the project/workspace, authority pointers, principal permissions, and observable state.
2. **Inspect** — expose bounded repository and native Git facts with provenance and limitations.
3. **Change** — perform explicitly delegated local file and Git mutations against checked preconditions.
4. **Check** — run approved checks in restricted execution environments and report what was actually exercised.

The MCP is not a general shell, workflow database, GitHub replacement, project Product authority, autonomous manager, or institutional-memory system.

For project onboarding and Shadow registration, see [`docs/project-onboarding.md`](docs/project-onboarding.md).

For this repository's Workflow v1 pilot profile and verification route, see [`docs/engineering-profile.md`](docs/engineering-profile.md).

## MCP-01 read/orientation plane

MCP-01 established the stdio controller foundation: deterministic start, launcher-bound principal identity, external operator policy, project-manifest narrowing, bounded project/Git reads, and exact commit comparison.

Operator policy defaults to `~/.config/vedaops/mcp/projects.toml`, which is distinct from the live legacy registry. See `config/projects.toml.example`.

```bash
export VEDAOPS_AGENT_ID=your-agent
export VEDAOPS_PROJECTS_REGISTRY=/absolute/path/to/projects.toml
uv run vedaops-mcp stdio
```

The trusted launcher sets `VEDAOPS_AGENT_ID`. That binds this MCP process to a configured principal in operator policy. The controller does not independently cryptographically authenticate the human or model behind the launcher.

## MCP-02 restricted checks

MCP-02 adds one execution surface: `project_check_run`. Callers select only an operator-approved check ID, an exact current Git HEAD, and optionally a shorter timeout. They cannot supply argv.

The runner materializes a bounded snapshot directly from Git tree/blob objects and executes it under the `linux-bwrap-systemd-tmpfs-v3` profile with network denied, a synthetic home, no controller or SSH environment, no other project mounts, no Docker socket, per-process limits, aggregate systemd-scope memory/task limits, bounded output, and explicit cleanup evidence. All worker-writable scratch (`/workspace`, `/tmp`, `/home/worker`, and `/dev/shm`) is disposable tmpfs memory charged to the same no-swap systemd memory cgroup rather than host-backed disk. Project code receives no mount capability. The receipt reports `exact_commit_snapshot` only when every supported commit entry was materialized; otherwise it reports explicit exclusions. Dirty and untracked working-tree content is never part of the exercised commit subject.

## MCP-03 disposable PostgreSQL checks

MCP-03 adds `project_postgres_check_run` for operator-approved checks whose policy selects `substrate = "postgres18"`. The controller starts only the fixed locally available `postgres:18-alpine` image with Docker networking disabled and tmpfs-backed database state. The restricted check worker receives no Docker control or IP network; it receives only a temporary PostgreSQL Unix socket.

PostgreSQL readiness uses `pg_isready`, major version 18 is verified independently, and the receipt identifies the image, image ID, server version, captured runtime, outcome, truncation, and cleanup. Project virtual environments are not mounted from operator home: installed packages and bounded console executables are copied into a sanitized temporary venv built from trusted system Python and identified in the receipt. Editable-install path metadata that points inside the registered project is retargeted to the disposable `/workspace` snapshot, preserving installed-project behavior without exposing the live worktree. Temporary PostgreSQL DSNs/passwords are scrubbed from returned stdout/stderr.

## MCP-04 bounded Change plane

MCP-04 adds the missing core Change responsibility. A project must be mutable and grant `change` through the principal, operator policy, and project-manifest intersection before any mutation is available. The ordinary Change plane can create/write/delete bounded UTF-8 files, perform exact hash-protected text replacement, apply validated bounded patches to existing regular UTF-8 files, inspect native working-tree/index diffs and local branch tips, and commit exactly named paths.

Local Git lifecycle operations are deliberately narrow: create/switch ordinary local branches, fast-forward-only local integration, and safe deletion of an already-merged non-current branch. Branch/ref mutations refuse dirty state, exact commits refuse pre-existing staged state, repository-controlled hooks are disabled, and post-effect verification failures return an explicit recovery-required uncertainty rather than inviting an automatic retry. Branch switching/integration also refuses any commit-tree transition that would change a mutation-protected path. `.vedaops/project.toml` remains readable authority but is not writable directly or indirectly through ordinary Change.

The MCP does not expose shell access, caller-selected Git argv, fetch, pull, push, force operations, rebase, stash, or remote Git mutation. `git push` remains an explicit CHAZ/operator action outside the MCP.

Effecting file, Git, and check operations record a minimal durable operation journal outside managed project roots. A started operation is recorded before its first externally visible effect and reaches `succeeded`, `failed`, or `uncertain` only after terminal evidence. This is recovery evidence, not workflow state.

`vedaops_server_info` distinguishes observed source-checkout revision from the runtime artifact actually loaded. It reports a deterministic loaded-package digest, Python executable path/digest, process ID, instance/start identity, one exact validated operator-policy byte snapshot and its effective grants, plus a fingerprint of the complete FastMCP-advertised tool contracts rather than names alone. Client-advertised catalog state must still be independently observed during cutover.

Because Check intentionally exercises an exact committed subject, the normal local development order is:

`edit -> inspect intended diff -> exact local candidate commit -> run approved checks against that candidate -> independent review -> CHAZ acceptance -> fast-forward integration -> optional local branch cleanup -> operator push when authorized`

The candidate commit is neither Product acceptance nor publication. Running a check before the candidate commit would exercise the previous HEAD, not dirty working-tree bytes.

Effective permission is the intersection of the principal grant, operator project ceiling, project-manifest narrowing, and operation-specific restrictions.

## Development principle

VedaOps uses **VedaOps Discipline** (internally nicknamed **VedaOps Disapline™**):

> Use Git, GitHub, project authority, checks, reviews, and development tooling according to their native semantics, while recording development activity consistently enough that fresh capable LLMs can interpret what happened without guessing.

Skills teach judgment and convention. MCP enforces boundaries and exposes facts that should not depend on a model remembering instructions.

## Bootstrap sequence

The intended early sequence is:

1. `MCP-01` — core foundation and read/orientation plane.
2. `MCP-02` — restricted development-check runner.
3. `MCP-03` — disposable PostgreSQL check substrate, exercised immediately against Discrepancy Desk.
4. `MCP-04` — bounded local Change plane, including the ordinary native Git lifecycle while remote push remains operator-controlled.

After MCP-04 acceptance, the declared Orient / Inspect / Change / Check core is complete. Whole-Product review and explicit cutover assessment follow; future capability is not unfinished core work.

Substantive capabilities are developed on dedicated ticket branches/workspaces and are merged only after verification, independent review, and native acceptance.

The legacy `linux-vedaops-mcp` remains evidence and the live control plane until CHAZ deliberately authorizes a cutover. This repository does not inherit old implementation merely because it existed.
