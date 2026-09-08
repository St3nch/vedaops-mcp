# MCP-03 — Disposable PostgreSQL Check Substrate

Status: Product accepted by CHAZ on 2026-09-08.

Accepted candidate: `ff1ab6439d51489eadae64faed61f86674bce83e`

Independent review verdict: `READY WITH NON-BLOCKING NOTES`; no acceptance blockers remain.

## Product reason

Discrepancy Desk currently needs real PostgreSQL-backed development checks.

PostgreSQL therefore provides an immediate real consumer for the new execution architecture.

## Objective

Run one approved project check against one disposable PostgreSQL 18 substrate, return scoped evidence, and clean up the disposable runtime.

This is test infrastructure, not persistent database administration.

## Intended first consumer

`discrepancy-desk`

Use an existing accepted DD PostgreSQL foundation/proof check as the first real tracer rather than synthetic demo code.

## Core flow

```text
exact candidate
    ->
restricted check worker
    ->
operator-defined disposable PostgreSQL 18 substrate
    ->
approved DD check
    ->
scoped execution receipt
    ->
verified cleanup
```

## Authority boundary

The LLM does not supply Docker argv, arbitrary SQL, image choice, role names, persistent credentials, host paths, arbitrary ports, or backup/restore behavior.

Operator/runtime policy owns the substrate definition.

Project code receives only the minimum temporary database connectivity needed for the accepted check.

Project code must not receive Docker control.

## Evidence

Return, as available, candidate/input identity, check ID, PostgreSQL version, substrate/image identity, outcome, duration, bounded output, truncation, cleanup outcome, and limitations.

Never return database passwords or private DSNs.

## Acceptance cases

Prove:

1. no implicit provider activity or unrelated network access;
2. isolation from persistent databases and operator credentials;
3. explicit PostgreSQL/substrate identity;
4. correct readiness behavior;
5. correct version behavior;
6. cleanup after success;
7. cleanup after failure;
8. cleanup after timeout/interruption where technically supportable;
9. no credentials in tool results or audit;
10. correct source/runtime/client catalog exposure;
11. removal of the PostgreSQL component leaves ordinary MCP core operations working.

## Candidate evidence

- `ruff check .`: pass.
- Full repository suite: 67 passed.
- MCP-03 focused suite: 4 passed, covering success, check failure, timeout cleanup, ordinary-runner refusal, Unix-socket-only worker connectivity, denied IP network, Docker-socket absence, PostgreSQL 18 identity, and credential scrubbing.
- The first real tracer used Discrepancy Desk exact HEAD `73941507f2511aca3af8abcf47799bd016c687bf` in an automatically removed local clone, with DD's real provisioned dependency environment as runtime input and its accepted `postgres-foundation-proofs` argv. The check exited 0 against PostgreSQL 18.6 (`180006`) through the MCP-03 Unix socket; PostgreSQL and host-workspace cleanup both reported `removed`; `uncertain_effects` was false.
- The live DD working tree remained clean. Its legacy `.vedaops/project.toml` was not cut over; the tracer used a temporary new-MCP `read/check` manifest only in the disposable clone because the legacy controller remains live until explicit cutover.
- The FastMCP contract test exposes `project_postgres_check_run` as non-read-only, non-idempotent, non-open-world execution and keeps Docker control absent from the tool catalog.

The DD proof report intentionally names the environment-variable identifier `VEDAOPS_POSTGRES_URL`; that identifier is not a credential. Raw temporary DSNs and passwords are scrubbed from MCP-returned stdout/stderr.

## Out of scope

Persistent Desk database commissioning, arbitrary SQL, backup, restore, destructive reset, persistent role management, universal database abstraction, and a generic runtime-provider framework unless this tracer proves it is needed.

## Development discipline

Implement on a dedicated branch such as:

`ticket/MCP-03-postgres-check-substrate`

Do not generalize from PostgreSQL before the first real DD tracer proves the actual reusable semantics.

No push without fresh CHAZ authorization.
