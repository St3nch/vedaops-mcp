# MCP-01 — Core Foundation

Status: bootstrap current candidate ticket. Requires CHAZ commissioning before implementation.

## Problem

The new repository needs a minimal trustworthy controller foundation before optional runtimes or integrations are added.

## Objective

Establish the smallest read/orientation plane and the authority skeleton required for later governed mutation and restricted checking.

## Scope

Design and implement only the minimum accepted foundation needed to:

- start the MCP deterministically;
- identify build/server instance information;
- derive authenticated principal identity;
- load operator-approved project policy;
- apply project-manifest narrowing;
- discover authorized registered projects;
- orient to one registered project/workspace;
- expose bounded tree/file/search reads;
- expose native Git status and exact commit comparison;
- return stable structured refusals and truncation/completeness information.

## Required architectural properties

- no general shell;
- no project-code execution;
- no PostgreSQL;
- no Grok/external-agent runner;
- no GitHub writes;
- no push;
- no persistent runtime control;
- no dynamic executable plugins;
- no project imports;
- no workflow-state database.

## LLM-facing acceptance

A fresh model should be able to determine which project/workspace it is reading, which native authority sources matter, which permissions this principal has, observed Git branch/HEAD/dirty state, whether results are complete/truncated, and what is unavailable or conflicting.

## Development discipline

Implement on a dedicated branch such as:

`ticket/MCP-01-core-foundation`

Use coherent semantic commits.

Use targeted checks only.

If validation grows into a many-minute/heavy suite, CHAZ runs it directly in `tmux`.

Independent review must bind to the exact candidate revision.

No push without fresh CHAZ authorization.

## Out of scope

Mutation, commits, branch creation/switch, check execution, PostgreSQL, external agents, Desk operations, remote observation/fetch, GitHub integration, and deployment/cutover of the legacy MCP.

## Exit condition

Stop when the minimal foundation is coherent, independently reviewed, and accepted.

Do not widen MCP-01 merely because later capabilities are already known.
