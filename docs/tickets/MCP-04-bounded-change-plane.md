# MCP-04 — Bounded Change Plane

Status: Astra whole-system audit rejected candidate `634635388837d39e1f1c9f33e2a20d8e2121c81d`; bounded remediation implemented on `ticket/MCP-04-bounded-change-plane`; verification green; independent remediation review pending Product acceptance.

## Product reason

The accepted MCP-01 through MCP-03 implementation can Orient, Inspect, and Check, but the Product also promises Change.

Routine local repository development should not require CHAZ to act as the Steward's Git keyboard. After cutover, the MCP should be able to perform the ordinary local file and Git lifecycle needed for governed VedaOps development. Remote publication remains separate: `git push` stays under explicit CHAZ/operator control and is not part of this ticket.

## Objective

Add the smallest preconditioned local Change plane that can:

1. create, replace, patch, and delete bounded project text files;
2. show the resulting native Git diff;
3. commit exactly named local changes;
4. create and switch ordinary local branches;
5. fast-forward an accepted ticket branch into the current target branch;
6. safely remove an already-merged local ticket branch;
7. preserve native Git state and refuse ambiguous or unsafe transitions.

This is local repository mutation, not a general filesystem surface, arbitrary Git interface, remote Git interface, or workflow engine.

## Normal local lifecycle to support

```text
orient / inspect
    ->
create local ticket branch
    ->
bounded file changes
    ->
inspect native diff
    ->
run approved checks
    ->
commit exactly named paths
    ->
independent review / CHAZ acceptance
    ->
switch to target branch
    ->
fast-forward-only local merge
    ->
optional safe local branch deletion
```

CHAZ may then perform `git push` separately when publication is explicitly authorized.

## Authority

Introduce `change` as a mechanically enforced capability.

Effective permission remains:

`principal grant ∩ operator project ceiling ∩ project-manifest narrowing ∩ operation restrictions`

The repository may not enlarge its own authority.

The project mechanical authority file `.vedaops/project.toml` is not writable through the ordinary Change plane. `.git` administrative storage and any controller/operator policy, audit, credential, or installation paths are likewise outside the writable project surface.

Caller-supplied ticket names, prose, branch names, or paths do not create authority.

## Intended tool semantics

The implementation should expose small goal-oriented operations rather than `git <args>` or shell passthrough.

### File mutations

- create/write one bounded UTF-8 project file with explicit existence/hash preconditions;
- exact text replacement with file hash and occurrence-count preconditions;
- apply one bounded Git-compatible patch after validating represented operations and paths;
- delete one bounded project file with exact file/hash preconditions.

All mutations remain inside the registered ordinary workspace, reject protected paths, preserve unrelated user changes, and return bounded effect evidence.

### Git observation needed by Change

- bounded working-tree diff;
- bounded staged/index diff if useful to explain native state;
- local branch/ref observation sufficient to establish branch existence and exact tip identity.

Do not invent shadow staging, branch, merge, or workflow state.

### Exact local commit

Commit exactly named changed paths against an exact expected current HEAD.

The operation must not accidentally include unrelated dirty or staged paths, must not execute repository-controlled hooks, and must verify the resulting commit/parent/path set before claiming success.

The receipt should identify at minimum the prior HEAD, resulting commit, committed paths, and any remaining working-tree/index changes.

### Local branch create/switch

Support ordinary local branch creation from an exact expected current HEAD and safe switching among ordinary local branches.

No detached-HEAD workflow, orphan branches, implicit stash, force checkout, or overwrite of conflicting local changes.

Branch names must be validated as native Git refs and bounded by operation policy.

### Fast-forward-only local merge

Support one local fast-forward-only integration operation.

Requirements:

- exact expected current target branch and HEAD;
- exact expected source branch tip;
- clean/safe local state as required by native Git semantics;
- source must be an ancestor-descendant fast-forward of target;
- no merge commit;
- no conflict resolution;
- no strategy selection;
- no remote access;
- verify final HEAD equals the expected source tip.

This is a local ref/history update, not GitHub merge publication and not Product acceptance.

### Safe local branch deletion

Deletion is optional only after its value is proven by the ordinary lifecycle, but if implemented it must be narrow: non-current local branch only, no force delete, and only when Git establishes it is merged into the intended current target.

## Refusals / out of scope

Do not add:

- general shell execution;
- caller-selected Git subcommands or argv;
- push, fetch, pull, remote mutation, or credentialed network Git;
- force push;
- force checkout/reset;
- rebase;
- cherry-pick;
- revert as a generic mutation primitive;
- stash machinery;
- arbitrary merge strategies or merge commits;
- automatic conflict resolution;
- submodule mutation;
- linked-worktree lifecycle;
- GitHub PR/review/merge/release writes;
- ticket/workflow state beyond native project files and Git history.

Future capability is not unfinished MCP-04 work.

## Acceptance cases

Prove at minimum:

1. `change` authority is required and cannot be enlarged by repository content;
2. protected authority/Git paths cannot be mutated;
3. create/write requires explicit safe preconditions and cannot escape the project root;
4. exact replacement fails on stale hash or unexpected occurrence count;
5. patch validation rejects out-of-scope paths and unsupported Git operations;
6. delete requires exact preconditions and preserves unrelated files;
7. diff evidence is bounded and describes native working-tree/index state honestly;
8. exact commit cannot include an unrelated dirty or pre-staged path;
9. repository-controlled hooks/config cannot turn commit into arbitrary code execution;
10. branch creation is exact, local, and refuses an existing/conflicting ref;
11. branch switching refuses unsafe dirty-state overwrite and performs no implicit stash;
12. fast-forward integration succeeds only for a true FF relation and verifies the resulting HEAD;
13. non-fast-forward integration is refused without changing refs or worktree state;
14. branch operations do not contact remotes or use credentials;
15. safe branch deletion, if implemented, cannot force-delete unmerged work;
16. ordinary Orient/Inspect/Check/PostgreSQL behavior remains intact;
17. tool catalog exposes no general shell, arbitrary Git, or push capability;
18. a complete local ticket cycle can be performed through the MCP without CHAZ typing routine local Git commands.

## Astra whole-system audit remediation

Astra's whole-system review of candidate `634635388837d39e1f1c9f33e2a20d8e2121c81d` found real cutover blockers rather than missing Product scope. The remediation remains MCP-04 work and does not add a new core capability ticket.

The repaired implementation now includes:

- complete patch-effect authorization using Git's parsed effect set, including mixed/traditional diff cases;
- fail-closed Git administrative confinement for refs indirection, alternates, promisor/partial-clone configuration, and protocol/network behavior;
- exact FF integration against the validated source commit object rather than an ambiguous short ref;
- stronger path/inode handling for manifest aliases, ignored checkout collisions, and same-open file content/hash identity;
- a shared sanitized `project_venv` runtime for ordinary and PostgreSQL checks, built with trusted system Python in isolated mode, including bounded console executables and editable-install path retargeting into the disposable snapshot;
- aggregate hostile-check containment through a bounded user systemd scope plus a global concurrent-check admission ceiling;
- durable operation start/terminal evidence outside managed repos, with explicit uncertain-effect states for interrupted or unverifiable file/Git/check effects;
- PostgreSQL cleanup failures preserved as structured uncertainty rather than escaping and discarding cleanup evidence;
- LLM-visible approved check descriptors in project orientation;
- server diagnostics that distinguish observed source revision from loaded runtime artifact/Python/process identities.

## Remediation evidence

- `ruff check .`: pass.
- Permanent repository suite: 96 passed after the final editable-runtime repair.
- Astra-derived adversarial regressions cover hidden patch targets, manifest aliases, ignored checkout collisions, branch/tag ambiguity, Git refs indirection, promisor/partial-clone refusal, Git alternates refusal, same-inode content/hash binding, controller-side Python shadowing, post-commit wrapper failure, PostgreSQL cleanup uncertainty, aggregate scope limits, and global check admission.
- The complete local ticket lifecycle remains exercised without operator Git commands: create/switch ticket branch, edit, exact commit, switch target, refuse premature deletion, fast-forward-only integration, and safe merged-branch deletion.
- Real Discrepancy Desk tracer at exact HEAD `73941507f2511aca3af8abcf47799bd016c687bf`: ordinary lint passed under the sanitized `project_venv` runtime; full PostgreSQL-backed pytest passed with 356 tests; PostgreSQL 18 Unix-socket connectivity and both container/workspace cleanup were verified with `uncertain_effects = false`.
- Real Discrepancy Desk `format-check` passed through the ordinary runner, and `postgres-foundation-proofs` returned PASS through the disposable PostgreSQL 18 runner with verified cleanup.
- The server catalog still exposes no general shell, caller-selected Git argv, fetch, pull, or push surface. Remote publication remains outside MCP-04.
- The live `.vedaops/project.toml` remains an intentional legacy-control-plane working-tree change and is excluded from the remediation candidate commit.

## Completion / cutover relevance

MCP-04 still closes the declared core responsibility gap: Orient, Inspect, Change, Check. Astra's audit did not justify a fifth core capability.

After an exact remediation revision passes independent review and CHAZ acceptance, perform explicit cutover verification of source -> loaded artifact -> running process -> policy -> server catalog -> client catalog, prove one real Discrepancy Desk development cycle, then retire the legacy controller. Stop adding core MCP capability unless a future real trigger earns it.

No push without separate fresh CHAZ authorization.
