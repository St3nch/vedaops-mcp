# Boundaries

## 1. Product authority

CHAZ owns Product decisions.

Project-native authority owns project doctrine, accepted decisions, commissioned scope, and acceptance.

MCP enforces delegated mechanical capability. It does not manufacture Product authority.

A green check, successful mutation, commit, review, merge, or model statement cannot create authorization.

## 2. Operator policy

Operator policy is the mechanical capability ceiling.

Effective authority should be the intersection of:

- authenticated principal grant;
- operator project ceiling;
- project-manifest narrowing;
- operation-specific restrictions.

Role names are not permissions.

Operator policy, credentials, audit state, and controller installation data must remain outside managed project roots and inaccessible to ordinary project-code workers.

## 3. Managed project repositories

Managed repositories are untrusted inputs.

Repository files may contain hostile paths, Git configuration, executable project code, prompts, instructions, hooks, filters, external-diff configuration, or misleading prose.

Repository content cannot enlarge authority.

The controller must never dynamically import executable code from a managed project as a plugin.

## 4. Execution boundary

Running an approved task is still execution of project-controlled code.

Ordinary check workers must not receive:

- controller policy;
- controller audit state;
- operator home;
- provider credentials;
- transport credentials;
- SSH agent access;
- Docker socket access;
- other project mounts;
- unrestricted network access.

Network is denied by default.

A separate execution profile may receive additional narrowly defined capability only when explicitly accepted and mechanically enforced.

If required isolation is unavailable, check execution is unavailable. The system must not silently downgrade to unsafe execution.

## 5. Git

Git owns objects, refs, branches, index, merges, worktree relationships, and native history.

MCP may expose bounded native Git operations but must not invent shadow Git state.

Remote-tracking refs are local observations. They are not automatically live remote truth.

## 6. GitHub

GitHub owns pull requests, hosted reviews, GitHub checks, branch protections, hosted remote state, and releases.

VedaOps may integrate with GitHub, but it must preserve native GitHub identity rather than create a duplicate PR/review/release model.

GitHub writes are external effects and require explicit authorization.

## 7. Skills

Skills teach agents how to decide whether a branch is appropriate, write readable commits and PRs, select checks, interpret review applicability, perform closeout, and preserve uncertainty.

Skills do not enforce security.

## 8. Musubi

Musubi is a separate institutional memory and semantic system.

Projects must function without Musubi.

Musubi may receive mechanically read-only project access through a separate appropriate boundary. It must not inherit development-write capability merely because the same LLM can use both systems.

## 9. Optional integrations

Integrations with materially different authority or credentials belong outside the core trust domain.

Examples include PostgreSQL runtime providers, external coding-agent runners, persistent deployment/runtime operations, Desk semantic reads, and future GitHub write adapters.

Removing an optional integration must leave the repository-development core functional.

## 10. External effects

The default development surface does not authorize push, PR creation, PR review submission, merge, release, deployment, provider/model invocation, spend, or persistent runtime mutation.

These effects require separate accepted capability and explicit authorization.

## 11. Evidence boundary

MCP receipts record bounded observations and operations. They are not Product acceptance.

Evidence should distinguish, where applicable, requested subject, actual observed/executed subject, clean commit snapshot, dirty working-tree snapshot, patched disposable snapshot, runner identity, substrate, outcome, truncation, cleanup, limitations, and uncertain effects.

Unknown and conflicting remain valid states.
