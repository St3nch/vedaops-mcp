# Vision

## Product

VedaOps MCP is the governed development control plane for VedaOps projects.

It exists to make repository development safe, inspectable, and legible to replaceable capable LLMs without turning the control plane into a general shell or a second project-management system.

## Core Product statement

> A small, identity-bound gateway for inspecting registered development workspaces, making explicitly delegated local changes, and running isolated development checks—with results tied to the actual subject observed or exercised.

## Four core responsibilities

### Orient

A fresh capable model can establish:

- which project/workspace it is operating on;
- which native sources are authoritative;
- what the authenticated principal may do;
- what Git state is observed;
- what checks are available;
- what observations are unavailable or conflicting.

### Inspect

The MCP exposes bounded repository and Git facts with explicit subject identity, completeness, truncation, and provenance.

### Change

The MCP performs only narrow, preconditioned local mutations explicitly delegated by operator policy and project restrictions.

### Check

The MCP runs approved project checks in restricted execution environments and reports the actual exercised subject, execution substrate, outcome, cleanup, and limitations.

## Non-goals

VedaOps MCP is not:

- a remote shell;
- an unrestricted filesystem proxy;
- Product authority;
- a ticket or workflow-state database;
- a Git or GitHub replacement;
- an autonomous acceptance engine;
- an institutional-memory system;
- a generic agent platform;
- a persistent database administration system;
- a deployment/orchestration platform.

## LLM-native objective

LLM-native means the semantically correct and safest reasoning path is the easiest path for a fresh capable model.

That requires:

- small goal-oriented tool surfaces;
- meaningful descriptions;
- stable structured results where structure improves correctness;
- exact identities;
- explicit effects and limitations;
- clear authority facts;
- first-class unknown/conflict states;
- progressive disclosure rather than historical context dumps.

LLM-native does **not** mean broad shell access or more tools.

## Development objective

Use native Git and GitHub correctly and consistently under VedaOps Discipline.

Development history should be understandable without old chat context. Humans are also allowed to benefit.

## Success criteria

The Product succeeds when:

- the core remains useful with all optional integrations removed;
- narrow tools cannot be bypassed by broader agent-facing authority;
- project code cannot reach control-plane secrets or other projects during ordinary checks;
- fresh models can understand what a result proves and does not prove;
- project authority remains native and explicit;
- substantial experimental capabilities can be isolated on branches/workspaces and deleted cleanly if they fail;
- source, installed artifact, running process, policy, and client-advertised catalog can be distinguished;
- PostgreSQL and external-agent capabilities can be added behind removable boundaries rather than fused into the core.

## Completion principle

Build narrow → build correctly → prove → stop.

Future capability is not unfinished work.
