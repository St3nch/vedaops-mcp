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

## MCP-01 read/orientation plane

This repository currently implements the MCP-01 foundation: a stdio MCP server that can start deterministically, identify the running instance and authenticated principal, load operator policy from outside managed project roots, apply project-manifest narrowing, and expose bounded project/Git reads.

It does not execute project code, accept caller-selected commands, mutate repositories, push, talk to GitHub, or replace the live `linux-vedaops-mcp` control plane.

Operator policy defaults to `~/.config/vedaops/mcp/projects.toml`, which is distinct from the live legacy registry. See `config/projects.toml.example`.

```bash
export VEDAOPS_AGENT_ID=your-agent
export VEDAOPS_PROJECTS_REGISTRY=/absolute/path/to/projects.toml
uv run vedaops-mcp stdio
```

A declared principal must exist in operator policy. Effective permission is the intersection of that principal's grant, the operator project ceiling, and the untrusted project manifest.

## Development principle

VedaOps uses **VedaOps Discipline** (internally nicknamed **VedaOps Disapline™**):

> Use Git, GitHub, project authority, checks, reviews, and development tooling according to their native semantics, while recording development activity consistently enough that fresh capable LLMs can interpret what happened without guessing.

Skills teach judgment and convention. MCP enforces boundaries and exposes facts that should not depend on a model remembering instructions.

## Bootstrap sequence

The intended early sequence is:

1. `MCP-01` — core foundation and read/orientation plane.
2. `MCP-02` — restricted development-check runner.
3. `MCP-03` — disposable PostgreSQL check substrate, exercised immediately against Discrepancy Desk.
4. Later capabilities are commissioned only after the core boundary is proven.

Substantive capabilities are developed on dedicated ticket branches/workspaces and are merged only after verification, independent review, and native acceptance.

The legacy `linux-vedaops-mcp` remains evidence and the live control plane until CHAZ deliberately authorizes a cutover. This repository does not inherit old implementation merely because it existed.
