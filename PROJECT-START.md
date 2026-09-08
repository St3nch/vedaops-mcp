# Project Start — Late Morning

This file is an operational bootstrap checklist, not Product authority.

## Before implementation

1. Clone `https://github.com/St3nch/vedaops-mcp`.
2. Place this bootstrap document pack into the repository.
3. Review the files as CHAZ Product Owner.
4. Make one clean bootstrap baseline commit.
5. Register the new project with the current legacy VedaOps MCP under a distinct project ID such as `vedaops-mcp`.
6. Confirm the legacy `linux-vedaops-mcp` remains live and independently identifiable.
7. Inspect branch, HEAD, working tree, effective capabilities, and configured tasks.
8. Do not copy old implementation into the new repo.

## First implementation work

After CHAZ commissions MCP-01:

1. Create `ticket/MCP-01-core-foundation` from the exact accepted baseline.
2. Assign one Writer.
3. Implement only MCP-01 scope.
4. Run targeted checks.
5. Inspect the exact diff/candidate.
6. Obtain independent review bound to the exact commit.
7. Reconcile findings.
8. Record native acceptance.
9. Integrate using native Git/GitHub semantics.
10. Push only under fresh CHAZ authorization.

## Early next capabilities

After MCP-01:

- MCP-02 — restricted development check runner.
- MCP-03 — disposable PostgreSQL check substrate, tested immediately with Discrepancy Desk.

Do not begin Grok/external-agent work until separately commissioned.

## Heavy tests

If a validation suite becomes large or many minutes long, do not run it through ordinary MCP calls.

Give CHAZ the exact command and run it directly in `tmux`.

## Legacy relationship

The legacy repository is evidence.

Use it to recover proven security invariants, useful refusal tests, exact-mutation behavior, Git hardening lessons, and transport/identity lessons.

Do not preserve code or abstractions solely because they already exist.
