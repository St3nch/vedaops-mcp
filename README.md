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
