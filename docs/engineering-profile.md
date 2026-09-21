# VedaOps MCP Engineering Profile

**Project:** VedaOps MCP  
**Workflow adoption:** VedaOps Engineering Workflow v1
**Profile status:** active; first adoption pilot complete
**Product Owner:** CHAZ  
**Project Steward:** ChatGPT

## Purpose

This profile is the compact engineering routing record for `vedaops-mcp`.

It does not replace `AGENTS.md`, `VISION.md`, `BOUNDARIES.md`, `ARCHITECTURE.md`, accepted decisions, commissioned tickets, or Product authority.

## Project identity and maturity

VedaOps MCP is the governed VedaOps development control plane.

The accepted core responsibilities are:

- Orient;
- Inspect;
- Change;
- Check.

The source repository and the accepted running Shadow controller are deliberately separate subjects. Source changes do not become live merely because they are committed, pushed, reviewed, or merged.

## Authority entrypoints

Read, in order as relevant:

1. `AGENTS.md`
2. `VISION.md`
3. `BOUNDARIES.md`
4. `ARCHITECTURE.md`
5. `decisions/decisions.md`
6. `decisions/deferred.md`
7. the commissioned ticket/change artifact

CHAZ remains final Product authority.

A successful commit, check, review, merge, push, or deployment does not create Product authority.

## Workflow adoption

This repository is the first VedaOps Engineering Workflow v1 adoption pilot.

The pilot is intentionally limited to repository delivery mechanics and one small genuine maintenance change.

The pilot must not be used to introduce, as part of the same experiment:

- controller privilege expansion;
- Shadow registry migration;
- live-runtime deployment;
- worktree orchestration;
- new MCP core capability;
- optional provider/tool integrations.

The accepted live Shadow runtime remains outside the pilot subject unless CHAZ separately authorizes runtime work.

## Canonical verification

Local admission verification:

```bash
uv run ruff check .
uv run pytest -q --tb=short
```

Hosted pull-request verification:

- `.github/workflows/ci.yml`

The hosted workflow is a credential-free **portable admission layer** on GitHub-hosted Ubuntu 24.04. It proves clean checkout/setup, locked dependency installation, lint, Python compilation, wheel construction, and a small portable test slice.

The full canonical suite remains:

```bash
uv run ruff check .
uv run pytest -q --tb=short
```

That full suite includes Linux isolation and substrate behavior that depends on host primitives such as Bubblewrap/user namespaces, systemd user scopes, and local Docker/PostgreSQL support. GitHub-hosted CI does not claim those proofs when its runner substrate cannot support them faithfully.

A green hosted check therefore means **portable admission passed**, not **full isolation/substrate verification passed**. Full-suite evidence must be recorded separately on a compatible trusted development/check substrate.

Checks prove only the exact source subject they exercised. Dirty local working-tree content is not implied to have been checked.

## Validation and execution substrates

Important substrates include:

- Python 3.12+;
- `uv`-managed project dependencies;
- Git and native repository history;
- Linux isolation primitives used by VedaOps restricted checks;
- disposable PostgreSQL 18 where an operator-approved MCP check explicitly selects that substrate;
- detached installed Shadow runtime for live controller operation.

Disposable check infrastructure is not the same as a persistent application/runtime database.

## Sensitive-change triggers

Increase review and verification rigor for changes affecting:

- authorization or capability intersection;
- principal identity or operator policy;
- protected paths or filesystem confinement;
- Git mutation semantics;
- uncertain-effect or recovery behavior;
- check isolation;
- credentials or environment propagation;
- PostgreSQL/Docker isolation;
- tool/result schemas;
- runtime/package identity;
- deployment or Shadow cutover;
- persistent external effects;
- dependency/supply-chain state.

A small diff may still be high consequence.

## Review and authorization

Default review and authorization rules are defined by `AGENTS.md` and accepted VedaOps authority.

Substantive security/control-plane changes require independent review appropriate to their consequence.

Routine repository mechanics remain distinct from:

- Product acceptance;
- push/publication;
- merge;
- release;
- runtime promotion;
- provider spend;
- production mutation.

Current project rules requiring fresh authorization for external effects remain in force until deliberately superseded.

## GitHub and CI boundary

GitHub carries native hosted lifecycle state such as Pull Requests, hosted checks, review discussion, and merge history.

The pilot CI workflow:

- uses a pinned GitHub-hosted Ubuntu 24.04 runner label;
- grants `GITHUB_TOKEN` only `contents: read`;
- uses no repository/provider/deployment secret;
- uses no `pull_request_target`;
- pins external actions to full commit SHAs;
- disables persisted checkout credentials;
- performs no push, release, deployment, or runtime mutation;
- reports only portable admission, not full Linux isolation/substrate proof.

The live Steward VPS is not used as a normal GitHub self-hosted PR runner. Any future self-hosted or custom-runner path requires a separately reviewed containment model.

Workflow-file changes are executable-infrastructure changes and should be reviewed accordingly.

## Delivery, release, and recovery

Ordinary source merge does not deploy VedaOps MCP.

The live Shadow controller is promoted separately from a reviewed exact source revision into a detached installed runtime.

Runtime promotion requires separate authorization and runtime verification.

Recovery must preserve the previously accepted runtime until the replacement is verified.

## Project-local methods and skills

No project-local skill is mandatory for this pilot.

Methods may be selected proportionately under accepted authority. Skills do not grant mechanical or Product authority.

## Pilot exit evidence

The Workflow v1 pilot is complete only after native records show:

1. this profile and credential-free CI path were reviewed and integrated;
2. one small genuine maintenance change used the PR/CI path;
3. checks are bound to a precise candidate subject;
4. required failed/unavailable evidence cannot masquerade as green;
5. findings and remediation are visible;
6. the live Shadow runtime remained outside the pilot;
7. a fresh session can reconstruct candidate, evidence, review, acceptance/integration state, and unresolved limitations;
8. useful friction/lessons are recorded before expanding adoption.

Pilot evidence, review persistence, reconstruction findings, and lessons are recorded in
[`docs/workflow-v1-pilot-closeout.md`](workflow-v1-pilot-closeout.md).

