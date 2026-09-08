# Deferred Capabilities

Deferred means worth remembering and reconsidering under an observable trigger.

Deferred does not mean backlog, promise, or implementation authorization.

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

**Problem:** allow native PR/review/merge actions without leaving the governed environment.

**Why not now:** VedaOps must first establish disciplined native Git/GitHub practice and a clean external-effect authorization boundary.

**Review trigger:** repeated PR/review operations create real manual burden and the semantics are stable.

**Boundary:** native GitHub objects only; explicit authorization; no shadow workflow state.

## F009 — Asynchronous heavy-check service

**Problem:** safely run long suites without MCP request timeout or control-plane instability.

**Why not now:** current Product need is satisfied by CHAZ running heavy suites in `tmux`.

**Review trigger:** heavy operator-run validation becomes frequent enough to create material burden.

**Boundary:** separate durable job execution; bounded resources; exact subject; no hidden provider/network effects; cancellation does not imply rollback.
