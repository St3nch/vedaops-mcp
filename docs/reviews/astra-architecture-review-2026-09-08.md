# Independent Architecture Review — 2026-09-08

Status: review evidence, not Product authority.

Source: Astra review supplied by CHAZ during bootstrap planning for the new `vedaops-mcp` repository.

## Executive architecture finding

The legacy Linux VedaOps MCP contains a useful repository-control core, but its execution authority became broader than its governance language suggested.

The review proposed the next-generation Product as:

> A small, identity-bound gateway for inspecting registered repositories, making explicitly delegated local changes, and running isolated development checks—with results tied to the actual subject observed or exercised.

The review explicitly did **not** make CHAZ's repair/refactor/rewrite decision.

## Highest-leverage findings

1. Remove general shell execution from the development-control surface.
2. Separate project-code execution from controller credentials, policy, installation, and other projects.
3. Make permissions specific to authenticated principal, project, and operation.
4. Identify actual execution inputs rather than treating expected HEAD as sufficient evidence.
5. Support native Git branches/workspaces without building a workflow engine.
6. Move runtime and external-agent integrations behind independently removable boundaries.
7. Make source, installed artifact, running process, policy, and client-advertised catalog separately observable.

## Strong existing ideas worth preserving

- external operator registry as authority ceiling;
- manifest narrowing;
- shared filesystem/Git policy;
- bounded reads;
- exact-text replacement;
- exact-path commits;
- hostile Git-configuration/path tests;
- explicit disposable-copy semantics;
- separation between inspection and admission;
- refusal-oriented testing.

These are behaviors/invariants to re-prove. They are not reasons to copy the legacy implementation wholesale.

## Key failure lessons

### Generic commands

The old `host_command_run` / `project_command_run` model executed caller text through `/bin/bash -lc`.

The review found that this could bypass narrower governance depending on service-account authority.

Bounded output and audit do not turn a general shell into a semantic development operation.

### Named tasks

A named task is safer than caller-selected argv, but project code was still executed with service-user authority.

The next architecture needs a true execution boundary.

### PostgreSQL

The review did not conclude PostgreSQL was the wrong need.

It separated disposable PostgreSQL test substrate — valuable — from persistent runtime commissioning — a different operational responsibility.

The next design should keep PostgreSQL-backed checks narrow and removable.

### Grok / external agents

The review did not conclude independent external-agent control was a bad need.

It found that vendor-specific CLI/config/session machinery became too central.

The preferred future shape is a separately deployed agent runner with a small semantic contract.

## Deployment/catalog discrepancy observed during review

The review observed a substantive mismatch between current source registrations, client-advertised tools, callable Grok behavior, and effective capability reporting.

This reinforced the need to distinguish source revision, installed artifact, running process, policy, server catalog, and client-advertised catalog.

## Project consequence

The new `vedaops-mcp` project should treat the legacy repository as hard-earned evidence.

It should preserve proven invariants only after restating and re-proving them under the new authority/execution architecture.
