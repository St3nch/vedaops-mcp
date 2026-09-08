# MCP-03 — Disposable PostgreSQL Check Substrate

Status: early NEXT direction. Not commissioned until MCP-02's restricted runner is accepted.

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

## Out of scope

Persistent Desk database commissioning, arbitrary SQL, backup, restore, destructive reset, persistent role management, universal database abstraction, and a generic runtime-provider framework unless this tracer proves it is needed.

## Development discipline

Implement on a dedicated branch such as:

`ticket/MCP-03-postgres-check-substrate`

Do not generalize from PostgreSQL before the first real DD tracer proves the actual reusable semantics.

No push without fresh CHAZ authorization.
