---
title: ADR / Spec / Proto Orchestration Playbook
kind: guide
status: active
updated: 2026-05-24
scope: docs/agents
---

# ADR / Spec / Proto Orchestration Playbook

Use this playbook when a change needs durable written intent before or alongside implementation.

Keep the process **harness-agnostic**: these rules describe roles and artifact boundaries, not any specific chat, agent, or tool product.

## Core operating rules

### 1. Start interactive, not draft-first

Before drafting an ADR, spec, or proto:

- confirm the user goal in plain language
- restate the current repo behavior and affected layers
- surface obvious scope, ownership, and compatibility questions
- agree on the artifact sequence needed for the change

Do not jump straight into drafting when the request is still ambiguous. A short interactive pass is expected first.

### 2. Keep orchestration harness-agnostic

Use stable role names such as:

- **orchestrator / lead**: manages flow, sequencing, and reconciliation
- **drafter / implementer**: produces the current artifact revision
- **reviewer**: checks the artifact against repo rules and the approved direction
- **reconciler**: folds approved review findings back into the single canonical draft

Do not write process docs that depend on a specific vendor, runtime, or command surface.

### 3. Preserve single-writer discipline

At any moment, one artifact should have one writer.

Parallel review is fine. Parallel edits to the same ADR/spec/proto are not.

## Artifact hierarchy

Treat the three artifact types as different levels of commitment.

### ADR: broader, looser, directional

ADR work answers: **why this direction, and what durable constraints should later work preserve?**

Use an ADR when the change:

- sets architecture or ownership direction
- spans multiple future phases
- needs tradeoff discussion or rejected alternatives
- affects how later specs or protos should be framed

ADRs may intentionally leave open questions when those questions do not invalidate the chosen direction.

### Spec: phase-scoped behavioral contract

Spec work answers: **what changes in this phase, in which layers, and how should it behave?**

A spec should usually cover one execution phase or one reviewable behavioral slice. It should be narrower than the ADR and concrete enough to guide implementation and review.

Specs may proceed while an ADR still has open questions, but only when those questions do **not** materially block the current phase.

### Proto: tight seam contract

Proto work answers: **what exact wire or schema contract crosses a service boundary?**

A proto is:

- narrower than the spec
- durable across generated clients and docs
- a seam artifact, not a roadmap placeholder

Do not create proto surface area just to “reserve space” for a future idea that is not ready.

## Relationship model

Use the following default model:

- **one ADR may lead to many specs**
- **one spec may require zero or more proto changes**
- **a proto change should trace back to a concrete spec need, not a speculative future phase**

In shorthand:

```text
ADR -> spec(s) -> proto change(s, when needed) -> implementation
```

That flow is directional, not mechanically rigid. A small spec may have no proto work. A proto-only change without a clear behavioral spec is usually a smell unless the change is purely local and already fully understood.

## Readiness gates

Advance only when the current artifact is ready enough for the next one.

### ADR ready for spec

The ADR is ready for spec drafting when it clearly states:

- the decision or directional choice
- the problem being solved
- the main tradeoffs and rejected alternatives
- durable constraints that follow-on work must preserve
- which open questions remain, if any

A spec should not start if the ADR still leaves unresolved architecture or ownership ambiguity that materially affects the current phase.

### Spec ready for proto

The spec is ready for proto drafting when it clearly states:

- the current behavior with repo references
- the proposed phase-scoped behavior
- affected monorepo layers
- runtime mode and namespace impact where relevant
- compatibility and rollout expectations
- exactly which seam needs a wire contract and which do not

If the behavior, ownership, or compatibility story is still fuzzy, do not freeze proto too early.

### Proto ready for reconciliation / review

The proto is ready for final review when it:

- encodes only the agreed seam for the current phase
- uses stable naming and comments
- follows additive evolution when possible
- avoids future-phase leakage in fields or RPCs
- accounts for generated downstream artifacts and docs

## Approval and execution gate

Drafting and execution are different states.

Recommended default meanings:

- `draft` — exploratory or still being shaped
- `proposed` — review-ready, awaiting human approval
- `accepted` — approved for the current phase and eligible for execution
- `implemented` — materially realized in code/docs/tests
- `superseded` — replaced by a newer accepted artifact

Practical orchestration rule:

- ADRs and specs may be drafted and reviewed while still `draft` or `proposed`.
- Implementation-oriented agents should execute only from an `accepted` current-phase spec, or from an explicit human instruction that overrides status conservatively.
- Proto drafts may appear before acceptance, but they should be treated as review material until the linked spec is accepted.

## Monorepo layer model

Every ADR/spec/proto discussion should name the impacted layer or layers explicitly.

- **service**: `service/` runtime behavior, service registration, handlers, config, modular-binary wiring
- **proto**: `service/**/*.proto`, `protocol/**/*.proto`, generated outputs, gRPC/OpenAPI docs
- **sdk**: `sdk/` discovery, client behavior, request/response handling, defaults, compatibility
- **cli**: `otdfctl/` command UX, flags, operator workflows
- **docs/ops**: `docs/`, `examples/`, configs, rollout guidance, operator notes

### Modular-binary ownership rule

This repo’s service layer is modular. When writing ADRs or specs, be explicit about:

- which runtime modes are affected: `core`, `kas`, `ers`, `all`
- which service namespace owns the new behavior
- whether a capability belongs to the platform core, a KAS process, or another service boundary

Do not blur service ownership just because multiple modules can compile into one binary. Even in `all` mode, ownership boundaries still matter.

## Proto durability guidance

Proto work in this repo should prefer durable, additive evolution.

Default expectations:

- prefer additive fields/RPCs over churn when possible
- avoid shortsighted rename/delete/recreate cycles
- do not leak future-phase aspirations into current-phase contract design
- avoid speculative placeholder fields with no current behavior behind them
- remember that proto changes fan out into generated Go, docs, SDK usage, and possibly operators’ mental models

A proto is tight on purpose. If a detail belongs in rationale or rollout sequencing, keep it in the ADR or spec instead.

## Recommended orchestration flow

1. **Interactive clarification**
   - align on user goal, current behavior, and affected layers
2. **ADR, if direction is still being chosen**
   - capture the durable why and constraints
3. **Spec for the current phase**
   - define the behavioral contract for this repo slice
4. **Proto, only if a seam changes**
   - encode the exact boundary contract
5. **Review and reconciliation**
   - check artifact quality, repo alignment, and readiness for implementation

## Practical checklists

### ADR checklist

- Is the decision directional rather than phase-by-phase implementation detail?
- Does it preserve repo ownership boundaries?
- Are open questions clearly labeled and safely non-blocking for the next phase?

### Spec checklist

- Is the phase boundary explicit?
- Are service, proto, sdk, cli, and docs/ops impacts called out explicitly?
- Could an implementer and reviewer tell what changes and what stays out of scope?

### Proto checklist

- Is this contract needed now?
- Is the seam narrower than the spec and durable beyond this implementation pass?
- Would generated artifacts and downstream consumers still make sense six months from now?
