---
title: Effort Routing and Agent Quality Playbook
kind: guide
status: active
updated: 2026-05-24
scope: docs/agents
---

# Effort Routing and Agent Quality Playbook

Use this playbook to choose the right level of process for drafting, review, and cleanup.

Keep the process practical: add structure when it reduces risk or ambiguity, not as ceremony.

## Base principles

- **Interactive-first**: confirm intent and scope before drafting.
- **Harness-agnostic**: describe work in terms of roles and artifacts, not specific tooling brands.
- **Single-writer**: one artifact, one active editor.
- **Escalate early on ambiguity**: do not let reviewers silently make architecture or scope decisions.
- **Respect repo layers**: service, proto, sdk, cli, docs/ops.

## Effort routing by task tier

### Tier 0: direct answer or tiny local edit

Use when the task is:

- purely informational
- a wording cleanup
- a small local correction with no cross-layer effect

Typical routing:

- one person/agent
- no formal ADR/spec/proto artifact
- optional quick self-check

### Tier 1: bounded doc or implementation slice

Use when the task is clear and local but still worth a written artifact or careful review.

Examples:

- updating one spec section
- tightening an ADR after feedback
- a small proto comment or additive local adjustment with obvious behavior impact

Typical routing:

- one drafter / implementer
- one reviewer if the change affects a durable artifact
- one reconciliation pass

### Tier 2: cross-layer phase change

Use when the task crosses layer boundaries or changes behavior across producer/consumer seams.

Examples in this repo:

- service + proto + sdk changes
- well-known discovery changes consumed by the SDK
- KAS, platform core, or modular-binary ownership changes
- operator-visible behavior that needs docs/ops updates

Typical routing:

- interactive clarification first
- spec required
- ADR required if direction is not already settled
- proto work only for seams that actually change
- reviewer plus reconciler required before implementation proceeds

### Tier 3: architectural or multi-phase direction-setting

Use when the task:

- sets repo direction across multiple phases
- changes ownership or boundaries between service areas
- could force multiple later specs
- carries meaningful compatibility, rollout, or public-contract risk

Typical routing:

- interactive clarification first
- ADR first
- one or more follow-on specs
- proto only after the relevant phase spec is ready
- explicit human escalation when architecture, scope, or product intent is still unsettled

## Routing heuristics for this repo

Prefer the higher tier when any of the following are true:

- the change touches more than one of `service`, `proto`, `sdk`, `cli`, `docs/ops`
- the change affects runtime modes or service namespaces
- the change alters a public or generated contract
- the change could confuse modular-binary ownership
- the change needs rollout or compatibility guidance

Prefer the lower tier when:

- the behavior is already settled
- the scope is phase-local and concrete
- no new durable seam is being introduced

## Quality bars by artifact and role

### ADR quality bar

A good ADR:

- captures the durable **why** and directional choice
- states the decision drivers and rejected alternatives
- preserves ownership clarity across platform/service boundaries
- allows open questions only when they do not undercut the chosen direction
- is broad enough to outlive one implementation pass, but not vague hand-waving

ADR is not ready if readers still cannot tell who owns the behavior, what direction was chosen, or what later specs must preserve.

### Spec quality bar

A good spec:

- is scoped to a concrete phase or behavioral slice
- names the impacted repo layers explicitly
- describes current behavior with file references
- states proposed behavior in reviewable terms
- calls out compatibility, rollout, and validation
- separates current-phase contract from future-phase ideas

Spec is not ready if implementation would still require making hidden product, scope, or ownership decisions.

### Proto quality bar

A good proto:

- encodes only the current seam contract
- is narrower and tighter than the spec
- uses stable naming and comments
- prefers additive evolution where possible
- avoids placeholder roadmap fields and future-phase leakage
- accounts for generated downstream artifacts and compatibility burden

Proto is not ready if it includes speculative fields, collapses ownership boundaries, or hard-codes behavior the spec has not actually settled.

### Reviewer quality bar

A good reviewer:

- checks the artifact against the approved direction, not personal preference
- flags concrete mismatches, missing constraints, and compatibility risks
- distinguishes local cleanup from true architecture or scope ambiguity
- avoids rewriting the artifact in parallel with the current writer
- produces actionable findings, not vague unease

Reviewers should escalate instead of “fixing by assumption” when a finding would force a new product, architecture, or scope decision.

### Reconciler quality bar

A good reconciler:

- preserves single-writer discipline
- folds in valid findings without broadening scope
- resolves concrete conflicts between reviewer comments and the current draft
- keeps the artifact concise and phase-true
- re-escalates when reviews expose unresolved direction, not just missing polish

## Review-cleanup loop rule

Use the cleanup loop for **concrete, local** findings.

Allowed pattern:

1. reviewer identifies concrete/local issues
2. single writer performs cleanup
3. reviewer re-checks the revised artifact

Rules:

- maximum **3** cleanup + re-review cycles
- keep the loop for local correctness, clarity, or consistency findings
- escalate to a human **earlier** when the issue is really about architecture, scope, ownership, or spec ambiguity
- single-writer discipline still applies throughout the loop

If the third cycle still does not converge, stop looping and escalate.

## Escalate instead of iterating when

- the ADR direction is not actually settled
- the spec still hides a product or scope choice
- proto shape depends on unresolved behavior
- service ownership is unclear in the modular-binary model
- reviewer feedback conflicts at an architectural level
- a change would break compatibility or public expectations without explicit approval

## Practical completion standard

Before calling a drafting or review task complete, confirm:

- the tier matched the real task complexity
- the right artifact level was used: ADR, spec, proto, or none
- repo layers and ownership were named clearly
- future-phase ideas did not leak into the current contract
- review findings were either reconciled or explicitly escalated
