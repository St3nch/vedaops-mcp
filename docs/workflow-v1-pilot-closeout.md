# Workflow v1 pilot closeout

**Project:** VedaOps MCP  
**Date:** 2026-09-21  
**Product Owner:** CHAZ  
**Project Steward:** ChatGPT

## Integrated subject

The first VedaOps Engineering Workflow v1 adoption pilot was integrated through GitHub Pull Request
#1, `pilot: establish Workflow v1 engineering profile and CI`.

- base: `13608a4994f1ee471de89c9d92b38ce802f39bdb`
- reviewed PR head: `05405df955eb257aadabed7fbcb0fe7e6c211303`
- merge commit / integrated main: `013ae0746f3c0da26330a8377633eae12c6283e6`
- integrated paths:
  - `.github/workflows/ci.yml`
  - `README.md`
  - `docs/engineering-profile.md`
  - `tests/test_change.py`

No production `src/` path changed in the pilot.

## Verification and evidence

### Local canonical verification

During remediation, after the deterministic journal-evidence test fix, the repository passed:

- `uv run ruff check .`
- full pytest: **137 passed**

That evidence was produced on candidate `5e3110cbbb03ca02cc8f057cf3a02d14041412a5`.
The final reviewed PR head `05405df955eb257aadabed7fbcb0fe7e6c211303` changed only the hosted
workflow and engineering-profile documentation after that local full-suite run; it did not change
production code or tests.

### Hosted CI

The first two hosted runs failed and remain useful evidence:

1. `2bd911e8126ed5194b9d0e58c5d292e66761abf2`: the full suite exposed that the
   GitHub-hosted runner did not provide the same isolation substrate as the VPS.
2. `5e3110cbbb03ca02cc8f057cf3a02d14041412a5`: adding Bubblewrap/PostgreSQL provisioning
   still did not make the hosted runner equivalent to the trusted development/check substrate.

The final design therefore made GitHub-hosted CI an explicit **portable admission** layer on
`ubuntu-24.04`, rather than claiming full isolation/substrate equivalence.

Portable admission passed on:

- PR head `05405df955eb257aadabed7fbcb0fe7e6c211303`;
- merged main `013ae0746f3c0da26330a8377633eae12c6283e6`.

A green hosted result proves only the checks named in `.github/workflows/ci.yml`; it does not prove
Bubblewrap/user-namespace isolation, systemd-scope limits, Docker/PostgreSQL substrate behavior, or
the complete canonical pytest suite.

## Independent review

Grok independently reviewed the exact range
`13608a4994f1ee471de89c9d92b38ce802f39bdb..05405df955eb257aadabed7fbcb0fe7e6c211303`.

Verdict: **ACCEPT**  
Blocking findings: none.

The durable review record is:
[`docs/reviews/grok-workflow-v1-pilot-review-2026-09-21.md`](reviews/grok-workflow-v1-pilot-review-2026-09-21.md).

## Fresh-session reconstruction proof

After merge, a new Grok session was instructed to reconstruct engineering state from durable
repository, Git, GitHub, and observed runtime evidence without being given the expected answer.

It correctly reconstructed:

- PR #1 and the exact merged source identities;
- the hosted-CI failure/remediation history and portable-admission semantics;
- source/runtime separation and the still-live MCP-05 detached runtime;
- the unrelated dirty `.vedaops/project.toml`;
- the independent review subject and verdict from host evidence.

Its verdict was that durable evidence was sufficient to reconstruct the **mechanical engineering
state**, while identifying three material persistence/currency gaps:

1. the independent ACCEPT review was not yet in the repository or native GitHub review objects;
2. the full-suite local record was not bound in durable PR text to the final reviewed head;
3. some older ticket status text is stale relative to later Git/runtime truth.

This closeout persists the independent review and records the exact local-evidence limitation rather
than pretending the earlier full-suite run exercised a later commit.

## Runtime separation

The pilot did not deploy or promote VedaOps MCP.

The live Shadow runtime remained the detached MCP-05 runtime rooted at
`10952033e74124005cc71cfd02ebfc7605716a93`. Source integration of PR #1 did not make
`05405df` or `013ae07` live.

## Friction and lessons

### 1. GitHub PR administration became real manual burden

CHAZ had to create/manage the PR and inspect GitHub state manually. That repeated friction satisfies
the review trigger for deferred item **F008 — GitHub write integration**. F008 remains a separate
post-pilot capability task; it was not smuggled into this pilot.

### 2. Hosted CI is a distinct substrate

Installing the same tools did not make GitHub-hosted Ubuntu equivalent to the trusted VPS for
low-level namespace/isolation behavior. The correct response was to narrow the hosted claim, not
weaken VedaOps isolation or turn the live Steward VPS into a normal PR runner.

### 3. Evidence tests must not depend on incidental filesystem ordering

The pilot exposed a journal test that assumed glob order meant newest operation. The repair binds
records by `operation_id` and checks cardinality.

### 4. Legacy manifest vocabulary creates onboarding confusion

The working tree still carried old `write/patch/execute` capability vocabulary while the
next-generation controller uses `read/change/check`. The closeout migrated the repository
declaration deliberately; the manifest remains a narrowing declaration, not an authority grant.

After migration, the legacy VOMCPLINUX controller correctly refused the repository because its
manifest parser does not recognize next-generation `change/check` vocabulary. `vedaops-mcp` is not
yet registered in Shadow, so the remaining closeout verification and Git operations are
operator-run rather than weakening or reverting the next-generation manifest.

### 5. Review evidence should persist with the project

The independent review existed but was not in GitHub or the repository. This closeout adds a durable
review record so a future fresh agent does not need session-history archaeology.

## Known limitations / follow-up

- Older ticket status text can be stale relative to later accepted Git/runtime evidence; future
  cleanup should correct it deliberately rather than rewriting history during this closeout.
- F008 GitHub write integration is the next separately governed capability task.
- The repository manifest was migrated to valid next-generation `read/change/check` vocabulary;
  operator policy and principal grants remain separate mechanical authority.
- No runtime promotion is part of this closeout.
