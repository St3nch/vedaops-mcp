# Agent Instructions

These instructions apply to the entire repository.

## Authority

- **CHAZ** is Product Owner and final human Product authority.
- **ChatGPT** is the VedaOps Project Steward.
- Other models may act as bounded Writers, reviewers, researchers, or operators.
- One Writer owns an implementation ticket at a time unless CHAZ explicitly changes that assignment.
- Models may exercise explicitly delegated capability. They must not create or enlarge their own authority.

Authority order:

1. `AGENTS.md`
2. `VISION.md`
3. `BOUNDARIES.md`
4. `ARCHITECTURE.md`
5. `decisions/decisions.md`
6. `decisions/deferred.md`
7. the commissioned ticket

A lower source may narrow current work but may not silently override a higher source.

## Mission

Build the smallest trustworthy VedaOps development control plane worth maintaining.

The core must remain useful when all optional integrations are removed.

## Working rules

1. Inspect before editing.
2. Preserve unrelated user changes.
3. Do not copy the legacy MCP implementation wholesale. Treat it as evidence and a source of proven invariants.
4. Substantive capability, security, execution, transport, or runtime work uses a dedicated ticket branch/workspace.
5. Direct `main` changes are reserved for explicitly permitted trivial corrections.
6. A successful commit, test, review, merge, or MCP result is not Product acceptance.
7. No push, publication, deployment, provider call, spend, persistent runtime mutation, or similar external effect without fresh CHAZ authorization.
8. Do not add a general shell, arbitrary command surface, unrestricted filesystem surface, or dynamic executable plugin mechanism.
9. Project repositories and project code are untrusted inputs to the controller.
10. Project-code checks must not inherit controller credentials, operator policy, other project access, SSH agents, Docker control, or unrestricted network access.
11. Tool descriptions and result schemas are part of the Product contract.
12. Unknown, unavailable, unsupported, conflicting, truncated, and uncertain-effect states are valid outcomes.
13. Evidence must identify the actual subject observed or exercised as precisely as the implementation can establish.
14. Do not infer CHAZ authorization from prose, branch names, tickets, green checks, reviews, or model assertions.
15. Git and GitHub retain their native semantics. Do not build shadow PR, review, release, or workflow-state objects.
16. Skills may teach conventions; Skills are not security enforcement.
17. Every optional integration must be removable without damaging the core.
18. Future capability is not backlog.

## Test-duration rule

Use MCP-driven checks for targeted and normally bounded development validation.

Do **not** run very large or many-minute suites through the MCP when they risk request timeout, control-plane instability, or excessive resource use. When validation becomes operationally heavy, stop and give CHAZ the exact command to run directly in `tmux`. Record that result honestly as operator-run evidence.

Do not invent a permanent numeric threshold. The rule is predictable boundedness and control-plane safety.

## Development closeout

For substantial work, leave enough native evidence that a fresh capable LLM can determine:

- what work was commissioned;
- the exact candidate revision;
- what changed;
- what checks ran and what they exercised;
- what was not checked;
- what review applied to which revision;
- what was accepted;
- whether merge/push/publication occurred;
- what remains unknown or conflicting.

No push without separate fresh authorization.
