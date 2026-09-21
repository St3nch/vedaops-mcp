# Deferred Capabilities

Deferred means worth remembering and reconsidering under an observable trigger.

Deferred does not mean backlog, promise, or implementation authorization.

## Deferred-feature lifecycle

Deferred capability records preserve architectural memory. They are **not a backlog, ticket queue, or implementation authority**.

Lifecycle:

1. **Deferred** — the capability, problem, boundary, and review trigger are recorded.
2. **Trigger observed** — evidence may show that the review trigger has become true.
3. **Steward reassessment** — the Project Steward decides whether the capability still fits the architecture and whether it is mature enough to commission.
4. **Product commissioning** — CHAZ explicitly authorizes the work to become active engineering.
5. **Ticket/spec creation** — only then is a bounded implementation artifact created with subject, scope, acceptance evidence, and authority.
6. **Implementation/review/integration** — work proceeds under ordinary VedaOps engineering governance.
7. **Close, revise, split, or defer again** — implementation experience may change the deferred design.

A satisfied review trigger does **not** silently commission work. A deferred item may remain deferred indefinitely, be revised, be split, or be dropped.

Do not create implementation branches, tickets, runtime services, credentials, provider integrations, or external side effects merely because an item appears in this file.

## F001 — External coding-agent runner

**Problem:** reduce manual burden for bounded external-model review and later isolated Writer work.

**Why not now:** the core identity, workspace, and restricted execution boundaries should be proven first.

**Review trigger:** repeated accepted development work is materially delayed by manual launch/recovery of external reviewers.

**Boundary:** separate runner identity and provider credentials; exact subject; explicit spend/network authorization; no accepted-main integration authority.

## F002 — External-agent Writer control

**Problem:** produce bounded implementation candidates using an external coding agent.

**Why not now:** reviewer/control tracer must prove isolation, session ownership, cancellation, and result semantics first.

**Review trigger:** repeated accepted Writer assignments justify controlled launch/resume.

**Boundary:** dedicated candidate workspace; no push, merge, Product acceptance, or production authority.

## F003 — Native Git worktree lifecycle support

**Problem:** reduce collisions and support parallel ticket workspaces.

**Why not now:** standard worktrees introduce shared Git administrative storage and require an explicit trust model.

**Review trigger:** concurrent accepted tickets make manual workspace management materially costly.

**Boundary:** verified repository relationship; no arbitrary `.git` pointer acceptance; no force cleanup.

## F004 — Live remote observation / fetch

**Problem:** distinguish local remote-tracking knowledge from actual remote state.

**Why not now:** remote identity, credentials, network authority, and effect semantics are not yet part of the accepted core.

**Review trigger:** repeated reviews cannot safely resolve local/remote divergence.

**Boundary:** approved remote; timestamped observation; fetch never implies push.

## F005 — Push / merge / release automation

**Problem:** reduce repeated operator work for deterministic external effects.

**Why not now:** external-effect authorization, scoped credentials, failure recovery, and exact candidate binding must be separately proven.

**Review trigger:** repeated stable operations create measurable operator burden.

**Boundary:** exact operation, exact candidate/ref, scoped credentials, fresh explicit authorization.

## F006 — Persistent runtime/deployment adapters

**Problem:** repeatable persistent service/database/runtime operations.

**Why not now:** no shared lifecycle contract has earned a place in the development controller.

**Review trigger:** repeated project-specific operations become stable, common, and costly enough to justify a separate runtime boundary.

**Boundary:** separate service identity, explicit effect grant, project-owned recovery semantics.

## F007 — Desk semantic read adapter

**Problem:** let authorized models inspect Discrepancy Desk Record/evidence semantics without CHAZ relaying commands.

**Why not now:** the first new-MCP milestones are core foundation and restricted checking.

**Review trigger:** current DD investigation repeatedly benefits from direct semantic reads after the new controller foundation is stable.

**Boundary:** dedicated read capability; least-privilege runtime principal; no human Decision/admission authority.

## F008 — GitHub write integration

**Problem:** allow the Project Steward to perform bounded native GitHub PR/review/check operations without CHAZ manually relaying routine GitHub actions.

**Trigger state:** satisfied during the Workflow v1 pilot. Manual PR creation, PR-body maintenance, check inspection, and review-state handling created repeated operator burden.

**Commissioning state:** deferred. Trigger satisfaction records need and maturity; it does not itself authorize implementation.

**Architectural direction:** prefer a least-privilege GitHub App with short-lived installation tokens, exact typed operations, source-subject binding, post-effect verification, and GitHub remaining authoritative for native lifecycle state.

**First-slice boundary:** PR/read-check operations only; no generic GitHub API or `gh` surface, branch push, merge, release, deployment, repository administration, or workflow mutation.

**Webhooks:** explicitly deferred within F008 until repeated event-driven need earns the additional persistent-ingress/runtime boundary.

**Detailed deferred brief:** [`docs/deferred/F008-github-integration.md`](../docs/deferred/F008-github-integration.md)

## F009 — Asynchronous heavy-check service

**Problem:** safely run long suites without MCP request timeout or control-plane instability.

**Why not now:** current Product need is satisfied by CHAZ running heavy suites in `tmux`.

**Review trigger:** heavy operator-run validation becomes frequent enough to create material burden.

**Boundary:** separate durable job execution; bounded resources; exact subject; no hidden provider/network effects; cancellation does not imply rollback.
