# Accepted Bootstrap Decisions

These decisions define the initial Product direction for the new `vedaops-mcp` project.

They do not declare the legacy system retired or authorize production cutover.

## D001 — Next-generation repository

The new `St3nch/vedaops-mcp` repository is the bootstrap home for the next-generation VedaOps MCP design and implementation.

The legacy `linux-vedaops-mcp` remains live evidence and the current control plane until CHAZ explicitly authorizes migration/cutover.

## D002 — Core Product boundary

The core MCP is limited to four responsibilities: Orient, Inspect, Change, and Check.

The core must remain useful when optional integrations are removed.

## D003 — No general shell in the target development surface

The target agent-facing development MCP will not expose a general caller-selected shell or arbitrary command surface.

Operator terminal use remains separate.

## D004 — VedaOps Discipline applies from bootstrap

Substantive capability, security, execution, transport, and runtime work uses dedicated ticket branches/workspaces.

Git and GitHub retain native semantics.

Development records are written for reliable interpretation by fresh capable LLMs.

A branch, commit, check, review, merge, or push does not become Product authority by implication.

## D005 — Heavy-test operator boundary

Ordinary MCP-driven checks must remain predictably bounded.

When a validation suite becomes very large, many minutes long, likely to time out, or likely to destabilize the control plane, CHAZ runs it directly in `tmux`.

The MCP/Steward supplies the exact command and records the result honestly as operator-run evidence.

No fixed permanent numeric threshold is adopted.

## D006 — Restricted execution precedes project-code checks

Project-code checks must not execute with controller policy, credentials, other-project access, Docker control, SSH-agent access, or unrestricted network authority.

If the accepted isolation boundary is unavailable, agent-facing check execution is unavailable.

## D007 — PostgreSQL is an early real capability

A disposable PostgreSQL-backed check capability is an early priority after the restricted check runner exists.

Discrepancy Desk is the first intended real consumer.

The first capability is test substrate, not persistent database administration.

## D008 — External coding-agent control remains future capability

Governed Grok Build or similar external-agent control remains a worthwhile future capability.

It will not be rebuilt inside the core as a large vendor-specific subsystem.

The preferred future shape is a separately removable external-agent runner with a small VedaOps-facing contract, developed only after explicit commissioning.

## D009 — Legacy retirement remains a separate CHAZ decision

The new project may reuse proven invariants and test ideas from `linux-vedaops-mcp`.

Historical investment alone does not create architecture authority.

CHAZ retains the final decision about legacy retirement and cutover.

## D010 — F008 is a separate GitHub collaboration boundary

F008 is commissioned as a removable provider boundary beside Shadow, not as a Shadow tool expansion.

The provider is the official GitHub MCP Server, pinned in the implementation rather than floated as `latest`. The VedaOps process in front of it owns principal, project, repository, and operation-class grants, the tool allowlist, exact-subject checks, and the pre-effect journal. Shadow grants do not authorize GitHub. Repository files cannot grant GitHub authority. GitHub remains authoritative for pull request state. The journal is not a pull request database.

Ordinary collaboration classes are read, pull request create, title update, body update, conversation comment, and reviewer request. Push, merge, ref mutation, repository file writes, workflow mutation, review submission, release, deployment, administration, and webhooks are outside this boundary.

Issues write is not part of the accepted App permission set. Ordinary timeline comments use the issue-comment endpoint. Current GitHub documentation says an installation token needs at least one of Issues write or Pull requests write, so the accepted Pull requests write permission is sufficient. The operation still comments only after the number is observed to be a pull request.

The provider executable and operator policy are outside the service-writable state tree. Ownership by the runtime uid is rewrite authority even without a write bit. Before launch, the boundary hashes the executable and requires the operator-recorded installed-file digest. That digest is not the published release-archive digest. The official GitHub MCP child shares the F008 Unix identity and is part of that runtime's trusted computing base.

This decision records the commissioned architecture. It is not Product acceptance of a live App, connector, or runtime, and it does not authorize push, merge, host provisioning, or provider calls.
