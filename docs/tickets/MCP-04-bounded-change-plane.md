# MCP-04 — Bounded Change Plane

Status: commissioned by CHAZ on 2026-09-08. This is the final currently expected core build ticket before whole-Product review and cutover assessment.

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

## Completion / cutover relevance

MCP-04 is intended to close the declared core responsibility gap: Orient, Inspect, Change, Check.

After MCP-04 reaches an accepted exact revision, stop adding core capability. Run the planned independent whole-MCP review (Astra), reconcile only genuine blockers/material corrections, then assess explicit CHAZ cutover from `linux-vedaops-mcp` to `vedaops-mcp`.

No push without separate fresh CHAZ authorization.
