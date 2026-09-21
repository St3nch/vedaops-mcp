# F008 — GitHub write integration

**Status:** commissioned architecture, with a local implementation candidate  
**Trigger state:** satisfied during the Workflow v1 pilot  
**Commissioning state:** commissioned for the F008 implementation. Not Product acceptance of a live App or connector.  
**Product Owner:** CHAZ  
**Project Steward:** ChatGPT

This document preserves the architectural direction and ecosystem research that led to F008.

The commissioned boundary is D010 and [`docs/github-collaboration.md`](../github-collaboration.md). This brief remains historical research. It is not a credential grant or a runtime specification. Where the implementation is narrower, the runbook and the code pin win.

## F008 — GitHub write integration

**Problem:** allow the Project Steward to perform bounded native GitHub PR/review/check operations without CHAZ manually relaying routine GitHub actions.

**Trigger state:** satisfied during the Workflow v1 pilot. Manual PR creation, PR-body maintenance, check inspection, and review-state handling created repeated operator burden.

**Commissioning state:** the pilot trigger did not itself authorize implementation. The later F008 assignment commissioned the separate-boundary implementation. Live App, connector, and Product acceptance remain separate.

### Architectural direction

Prefer a dedicated **GitHub App** identity rather than a classic PAT or an arbitrary `gh`/shell surface.

Use short-lived installation access tokens and install the App only on explicitly authorized repositories.

The GitHub provider boundary should remain optional and removable. Core VedaOps Orient/Inspect/Change/Check behavior must remain useful without GitHub integration.

GitHub remains authoritative for native GitHub objects:

- Pull Requests;
- reviews and review requests;
- PR conversation/comments;
- check runs;
- workflow runs;
- commit statuses;
- merge state.

VedaOps must not create a competing shadow PR/review/workflow database.

### Candidate first-slice permissions

Revalidate the exact minimum against current GitHub endpoint documentation before implementation. The expected starting set is:

- Metadata: read / App baseline;
- Contents: **read** — required to resolve remote refs and bind branch names to exact SHAs;
- Pull requests: **write** — create/update PRs, PR comments, and review requests;
- Actions: **read** — inspect workflow runs/jobs;
- Checks: **read** — inspect check runs/suites;
- Commit statuses: **read** — inspect combined/status contexts.

Do not grant merely for convenience:

- Contents: write;
- Workflows: write;
- Administration;
- Checks: write;
- deployment authority;
- release authority;
- repository-hook administration.

GitHub permission groupings may make a credential technically capable of an endpoint that VedaOps does not expose. Tool-surface policy must therefore narrow the credential further.

### Candidate first-slice tool surface

Possible bounded operations:

- `github_pr_get`
- `github_pr_create`
- `github_pr_update`
- `github_pr_comment`
- `github_pr_review_request`
- `github_pr_checks_get`

Exact names and schemas are implementation decisions, not commitments in this deferred record.

Do **not** expose a generic GitHub request primitive, arbitrary REST/GraphQL endpoint caller, or arbitrary `gh` argument surface.

The first slice should not expose:

- PR merge;
- branch push;
- Git ref mutation;
- repository file writes;
- workflow dispatch/rerun/cancel;
- check/status writes;
- release creation;
- deployment actions;
- repository administration.

Those require separate earned need and authority even if the GitHub App credential could technically reach them.

### Subject binding and effect semantics

GitHub writes should follow the same evidence discipline as governed Git effects.

For PR creation, prefer inputs that bind the operation to an exact source subject, for example:

- authorized VedaOps project;
- repository identity;
- head branch;
- expected remote head SHA;
- base branch;
- title/body.

Before creating a PR, verify the remote head ref resolves to the expected SHA.

After a GitHub write:

1. perform the bounded native operation;
2. re-read the native GitHub object;
3. verify the intended resulting state;
4. return stable native identifiers/URL and relevant source SHA;
5. if the request outcome is ambiguous, attempt state reconstruction before reporting success;
6. represent unresolved ambiguity as an uncertain-effect outcome rather than inventing success.

Operation journals may record evidence about VedaOps calls, but must not become shadow copies of GitHub lifecycle state.

### API compatibility

Use documented GitHub APIs with an explicit supported API version rather than silently floating behavior.

At implementation time:

- pin a currently supported `X-GitHub-Api-Version`;
- send the recommended GitHub media type;
- verify required GitHub App permissions against current endpoint documentation and, where useful, `X-Accepted-GitHub-Permissions`;
- test against exact native object semantics used by the adapter.

Do not hard-code today's API version into this deferred architectural record as though it were permanent.

### Reference implementations

Useful ecosystem references include:

- GitHub's official MCP server — especially exact tool/toolset allow-list and exclusion patterns;
- GitHub Apps documentation and REST permission tables;
- Octokit / Probot — GitHub App and installation-scoped automation patterns;
- Renovate — mature GitHub App automation and permission experience;
- PyGithub — Python GitHub App authentication/token handling.

These are reference implementations and compatibility evidence, not VedaOps authority. Do not copy their permission sets wholesale.

### Webhooks — explicitly deferred extension

Webhooks are **not required for F008 v1** because the initial problem is synchronous Steward-initiated operations and state inspection.

A webhook receiver would introduce a different operational boundary:

- publicly reachable HTTPS ingress;
- webhook secret/HMAC verification;
- delivery-ID deduplication;
- retries and idempotency;
- event filtering and authorization;
- persistent receiver/runtime monitoring;
- possible queue/background processing;
- recovery when GitHub delivery and VedaOps processing diverge.

**Webhook promotion trigger:** a repeated real need appears for event-driven behavior such as immediate CI-state notification, review-event intake, or post-merge reconciliation without Steward polling.

If that trigger is satisfied, reassess the architecture before implementation. If webhook handling grows into a persistent listener/queue/service with materially different runtime, credential, or recovery requirements, the Steward should decide whether it has earned a separate runtime boundary or deferred item.

A GitHub event is evidence that something happened on GitHub. It is not Product authorization for an unrelated VedaOps action.

### Boundary

Native GitHub objects only; explicit project/principal authorization; least-privilege GitHub App installation; exact typed operations; source-subject binding; post-effect verification; no shadow workflow state; no generic GitHub shell/API escape hatch; merge/release/deploy authority remains separate.
