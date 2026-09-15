# DOC-01 — Shadow Project Onboarding

Status: first candidate `e5ae1a36408486bdb9dfe11673e4f12511b6ac09`
and first remediation `20b8929acd4431ab4bda28399f0b33f1c3abbcac`
received Astra `RECONCILE`; a second bounded documentation remediation is in
progress on `ticket/DOC-01-project-onboarding`. Exact remediation candidate
review and Product acceptance remain pending.

## Product reason

Shadow VedaOps MCP has a complete `read/change/check` authority model but no
operator guide for admitting a new repository. The legacy guide describes a
different discovery and capability model, making an improvised migration likely
to misconfigure authority.

## Objective

Add one current project-onboarding procedure grounded in Shadow's implemented
manifest, external registry, launcher principal, check runner, Change plane,
operation journal, and native Git boundaries.

## Required outcomes

- Distinguish legacy discovery and `read/write/patch/execute` from Shadow.
- Explain `principal grant ∩ registry ceiling ∩ manifest narrowing`.
- Document exact manifest, project, principal, context, and check schemas.
- Start with read-only verification before optional Check and Change grants.
- Preserve external operator policy and operation-state boundaries.
- Describe exact-commit checks and exact-precondition Change smoke testing.
- Make push, deployment, Product acceptance, and legacy cutover separate
  explicit decisions.
- Provide safe suspension, retirement, refusal, and recovery guidance.

## Scope limits

This ticket adds documentation only. It does not change controller behavior,
policy schema, tool contracts, deployment state, live registries, managed
projects, or legacy-controller status.

## Verification

- Review examples against `src/vedaops_mcp/authority.py`,
  `src/vedaops_mcp/settings.py`, `src/vedaops_mcp/server.py`, and
  `config/projects.toml.example`.
- Run formatting/lint and the repository test suite.
- Inspect the exact candidate diff and obtain independent review if required by
  the onboarding project's acceptance process.

## First-candidate review

Astra reviewed exact commit
`e5ae1a36408486bdb9dfe11673e4f12511b6ac09` read-only and returned
`RECONCILE`. The review identified three blockers: unsafe replacement of an
existing registry, invalid principal-grant example syntax, and incomplete
cross-principal cleanup when retiring a project. It also requested clearer
read-only `check_ids`, manifest-commit, and closeout wording. This remediation
addresses those findings without changing controller behavior or scope.

Astra reviewed exact first-remediation commit
`20b8929acd4431ab4bda28399f0b33f1c3abbcac` read-only and confirmed the
principal, retirement, read-only check, and manifest-commit corrections. It
returned `RECONCILE` because the remaining first-time command still installed
an unedited example directly to the authoritative path and could overwrite an
existing registry. The second remediation makes the example a private
candidate only, requires complete replacement and validation of sample values,
requires an absent first-time destination, and gives existing registries a
separate preserve-and-atomically-replace path.

## Live coexistence finding

After Astra returned `READY` for exact documentation candidate
`5c70dc4a128c0bbaf96dc3cabb70043793f74acc`, live read-only inspection found
the legacy controller degraded with `VEDAOPS_MANIFEST_INVALID` when it
encountered Shadow capabilities `change` and `check`. The next documentation
candidate adds the missing coexistence rule: a Shadow-only project root must
remain outside legacy discovery roots unless a separate legacy
discovery/cutover change is authorized and verified. The prior `READY` verdict
does not apply to this later candidate.
