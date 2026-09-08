# MCP-02 — Restricted Development Check Runner

Status: NEXT direction. Not commissioned until MCP-01 is accepted.

## Problem

Running an approved check is still execution of project-controlled code.

The legacy MCP constrained task selection but did not sufficiently separate project execution from controller/service-user authority.

## Objective

Create the minimum execution boundary required to run approved development checks without exposing controller policy, credentials, other projects, Docker control, or unrestricted network access.

## Required isolation

The ordinary check worker must not receive operator home, controller policy, controller audit store, provider credentials, transport credentials, SSH agent, Docker socket, other project mounts, or unrestricted network.

Network denied by default.

## Check contract

A check result should identify, as available:

- project/workspace;
- requested base/HEAD;
- subject kind;
- actual captured-input identity;
- exclusions;
- check ID;
- check-definition identity;
- runner/profile identity;
- outcome;
- duration;
- bounded output;
- truncation;
- cleanup;
- limitations;
- uncertain effects.

If exact exercised bytes cannot be established, say so explicitly.

## Heavy-test boundary

Do not design MCP-02 around very long suites.

Targeted and normally bounded checks run through MCP.

Large/many-minute validation remains operator-run in `tmux`.

An asynchronous heavy-check service is deferred until measured pressure justifies it.

## Out of scope

PostgreSQL substrate, provider/model calls, arbitrary network, general shell, persistent runtime mutation, Grok/external-agent control, push/merge/release.

## Exit condition

The runner proves the intended isolation mechanically and can execute at least one real approved project check with honest subject/evidence semantics.
