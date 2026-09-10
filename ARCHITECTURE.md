# Architecture

Status: bootstrap target architecture derived from the 2026-09-08 independent architecture review and CHAZ's current Product direction.

The target is intentionally smaller than the legacy `linux-vedaops-mcp`.

## 1. Architectural shape

The Product has three primary responsibility boundaries:

```text
Authenticated client
        |
        v
Transport + principal
        |
        v
Authorization <----- operator policy
        |
        +-------------------+
        |                   |
        v                   v
Repository operations   Restricted check runner
        |                   |
        v                   v
Native Git/workspace    Disposable execution subject
        |
        v
Operation evidence
```

Optional integrations sit outside the core controller when their authority, credentials, or lifecycle materially differ.

This does not require a fleet of microservices. It requires clear authority boundaries.

## 2. Controller

The controller owns transport, authenticated principal derivation, authorization, registered project/workspace orientation, bounded reads, bounded filesystem mutation, bounded local Git mutation, check commissioning, operation receipts, and stable error/result contracts.

It does not run general caller-selected shell commands.

## 3. Identity and authorization

Authentication and authorization are separate.

A principal must be mechanically limited by project and operation.

Target evaluation:

```text
principal grant
∩ operator project ceiling
∩ project-manifest narrowing
∩ operation/profile restrictions
```

No caller-supplied role or ticket field creates authority.

## 4. Repository/workspace model

Repository identity and workspace identity are distinct.

The architecture must support disciplined branch-based work without accepting arbitrary Git-directory indirection.

Initial implementation may support one registered ordinary workspace per project.

Native linked worktrees are a later capability after the trust model for shared Git administrative storage is explicitly designed.

## 5. Repository operations

Internally separate orientation, bounded file/tree/search reads, Git observation, filesystem mutation, and Git mutation.

All use shared path, Git, and authorization policy rather than integration-specific copies.

## 6. Restricted check runner

Project checks are untrusted code execution.

The runner must demonstrate:

- no controller policy or audit access;
- no operator home;
- no provider/transport credentials;
- no SSH agent;
- no Docker socket;
- no other project access;
- network denied by default;
- bounded process lifetime;
- bounded memory;
- bounded output storage;
- worker-writable scratch on disposable tmpfs charged to the same no-swap memory cgroup;
- explicit writable paths;
- explicit dependency/runtime identity where relevant.

If those guarantees are unavailable, agent-facing check execution is unavailable.

Very large or many-minute validation does not run through ordinary MCP calls. CHAZ runs heavy suites directly in `tmux` until a separately justified asynchronous system exists.

## 7. Check evidence

An execution receipt should identify, as applicable:

- operation ID;
- principal;
- project/workspace;
- requested base/HEAD;
- subject kind;
- actual captured-input identity;
- patch identity;
- exclusions;
- approved check ID;
- check-definition identity;
- runner/profile identity;
- substrate identity;
- outcome;
- bounded output;
- truncation;
- cleanup;
- limitations;
- uncertain effects.

A digest identifies material. It does not prove correctness or reproducibility.

When exact exercised bytes are not established, say so explicitly.

## 8. Git operations

Core Git support covers branch/ref observation, status, working-tree/index diffs, exact commit comparison, bounded branch creation, bounded safe switch, exact local commit, fast-forward-only local integration, and safe deletion of an already-merged non-current local branch.

No force reset, implicit stash, history rewriting, generic remote command, or automatic conflict resolution is required in the core.

Push, merge publication, release, and deployment remain outside the default development authority.

## 9. GitHub

Use native GitHub concepts.

Potential integration may read actual remote state, PR identity/head, checks, reviews, and protection state.

Writes such as PR creation, review submission, merge, or release are external effects requiring explicit authorization.

Do not create VedaOps shadow objects for GitHub objects.

## 10. PostgreSQL

PostgreSQL is an early optional capability because Discrepancy Desk is an immediate real consumer.

The first target is **disposable PostgreSQL-backed check execution**, not persistent database administration.

Conceptual flow:

```text
exact candidate
    ->
restricted check worker
    ->
operator-defined disposable PostgreSQL 18 substrate
    ->
approved DD check
    ->
scoped execution receipt
    ->
verified cleanup
```

Project code must not receive Docker control.

The operator/runtime provider owns substrate creation and destruction.

The project owns migrations and test expectations.

No arbitrary SQL, persistent role administration, backup/restore, reset, or persistent commissioning belongs in the core.

## 11. External coding agents

Governed Grok Build or other external coding-agent control remains worthwhile future capability.

It should use a separately deployed agent runner with provider-specific implementation behind a small VedaOps-facing contract.

Potential earned semantics are start bounded run, status, result, cancel, and resume only if subject and authority preservation can be proven.

The controller should not know Grok marketplace internals, user configuration layers, or Observatory-specific dispatcher conventions.

Reviewer results remain advisory. Writer output remains an isolated candidate.

## 12. Extension model

Three allowed levels:

### Declarative configuration

Data only. Operator-reviewed.

### Reviewed static module

Small deterministic behavior shipped with the accepted controller.

No dynamic project code loading.

### Separate process/service

Use when the integration has different credentials, persistent runtime authority, provider spend, deployment effects, or independently evolving vendor behavior.

Avoid a generic `extension_call(name, payload)` escape hatch.

## 13. Deployment identity

Source truth, installed artifact, running process, operator policy, server catalog, and client-advertised catalog are separate observations.

Server diagnostics should eventually expose package/build version, source revision if embedded, artifact digest, runtime instance/process start identity, loaded tool/schema fingerprint, policy fingerprint/revision, extension identities, and caller effective permissions.

A server cannot certify what a client cached. Deployment acceptance requires client-side observation too.

## 14. Audit

Audit records operational facts, not Product meaning.

Keep durable start evidence before effects.

If an operation may have produced effects but terminal evidence fails, return an uncertain/recovery-required state and do not automatically retry.

Do not preserve expensive integrity mechanisms merely because they existed; preserve the required guarantee and choose the smallest implementation that honestly provides it.

## 15. Core-removal test

The core architecture is acceptable only if PostgreSQL, Grok/external-agent runner, Desk domain operations, GitHub write integration, and persistent runtime/deployment adapters can all disappear without damaging ordinary repository development.
