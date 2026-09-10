# VedaOps Discipline

Internal nickname: **VedaOps Disapline™**.

## Purpose

Use Git, GitHub, project authority, checks, reviews, and development tooling according to their native semantics while making development history reliably understandable to fresh capable LLMs.

The goal is consistency and legibility, not ceremony.

## Native semantics remain native

- A commit is a Git history event.
- A branch is a Git ref/line of work.
- A pull request is a hosted proposed-change/review surface.
- A check is execution evidence.
- A review is a judgment bound to a subject.
- A merge is integration.
- A push is publication to a remote.
- A release is publication of a version/artifact.
- Product acceptance is project authority.

Do not collapse these meanings.

## Branch discipline

Use a dedicated ticket branch/workspace for new capabilities, security changes, execution changes, transport changes, runtime integrations, experimental work, and substantial refactors.

Trivial explicitly permitted corrections may go directly to `main`.

A branch is candidate isolation, not Product authority.

## Commit discipline

Consequential commits should explain meaningful intent without relying on chat history.

Prefer messages that identify the coherent change rather than generic text such as `fix`, `update`, or `tests`.

A commit does not mean the work was accepted or pushed.

For MCP-driven development, the exact candidate commit normally precedes execution checks because the restricted Check plane deliberately exercises committed Git objects, not dirty working-tree bytes.

The normal local order is:

`edit -> inspect intended diff -> exact local candidate commit -> run approved checks against that candidate -> independent review -> CHAZ acceptance -> fast-forward integration -> optional local branch cleanup -> operator push when authorized`

Creating the candidate commit establishes the exact check/review subject. It does not imply acceptance, integration, or publication.

If a check is run before the intended changes are committed, record that it exercised the previous committed HEAD rather than the dirty edits.

## Check discipline

Never write only `tests passed` when more precise information is available.

Record exact candidate/subject when established, check/task identity, execution substrate, outcome, important exclusions, whether output was truncated, and whether the check was independently rerun or only reported by another actor.

If exact exercised bytes were not established, say so.

## Long-test rule

MCP runs targeted and normally bounded checks.

If a suite becomes very large, many minutes long, likely to exceed request limits, or likely to destabilize the control plane, CHAZ runs it directly in `tmux`.

The Steward supplies the exact command.

The result is recorded as operator-run evidence.

Do not build an asynchronous test platform merely because heavy tests may exist later.

## Review discipline

Consequential review should identify exact reviewed revision/diff, reviewer identity/role, scope, exclusions, findings, and whether later changes invalidate applicability.

Review is advisory evidence unless project authority says otherwise.

Review does not imply CHAZ authorization.

## PR discipline

Use GitHub PRs when they materially improve collaboration, review, or proposed-change visibility.

A PR should reference native project authority rather than replace it.

Useful stable sections include:

```markdown
## Authority
Native ticket / decision reference

## Proposed change
What becomes true if accepted

## Evidence
Checks and exact subjects

## Limits
What was not established

## Review target
Exact candidate revision
```

Do not require PR theater for trivial corrections.

## Push and external effects

Push, PR creation, review submission, merge, release, deployment, provider calls, spend, and persistent runtime mutation are external effects.

They require appropriate mechanical capability and fresh CHAZ authorization where VedaOps governance requires it.

Do not infer permission from branch names, tickets, green checks, or previous similar actions.

## Closeout

A meaningful work unit should leave a fresh model able to answer:

1. What work was commissioned?
2. What exact candidate represents it?
3. What changed?
4. What checks ran?
5. What did those checks actually exercise?
6. What did they not establish?
7. What review applied to which revision?
8. What was accepted?
9. Was it integrated?
10. Was it pushed/published?
11. What remains unknown or conflicting?

## Remote hygiene

Do not let local and GitHub history drift accidentally.

At closeout, deliberately inspect branch, HEAD, working tree, known local upstream relationship, whether remote truth has actually been observed, and whether push is authorized.

A local remote-tracking ref is not automatically live remote truth.

## LLM readability

Prefer stable headings, exact IDs, exact revisions, explicit scope, explicit limitations, explicit unknown/conflict states, and concise prose.

Avoid `looks good`, `ready`, `approved`, `tests pass`, `fixed`, or `current` unless the subject, actor, scope, or meaning is already explicit.
