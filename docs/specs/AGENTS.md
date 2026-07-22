---
title: Spec Writing Guide
kind: guide
status: active
updated: 2026-05-24
scope: docs/specs
---

# Spec Writing Guide

This directory holds lightweight implementation specs for this repo.

Use a spec when a change needs a clear, reviewable description of **what will change**, **which layers move together**, and **how the behavior should look before or alongside implementation**.

Keep specs:

- human-readable first
- parseable second
- grounded in real repo paths and runtime modes
- small enough to help execution, not become process overhead

## What belongs in `docs/specs/`

Good candidates:

- changes that cross layers, such as service + proto + sdk
- behavior changes that need one place to describe producers, consumers, and compatibility
- discovery, well-known configuration, KAS, auth, or policy changes that affect multiple modules
- CLI or ops-facing changes that need explicit rollout or configuration notes

Usually not needed:

- tiny refactors with no behavior change
- code-only fixes that are obvious from the diff
- enduring architectural decisions that should live as ADRs instead

## ADR vs spec vs proto vs implementation

| Artifact | Main question it answers | What it should contain | What it should not try to be |
| --- | --- | --- | --- |
| ADR (`adr/`) | **Why are we choosing this approach?** | decision, tradeoffs, consequences, rejected alternatives | a field-by-field execution plan or the final wire contract |
| Spec (`docs/specs/`) | **What will change, where, and how should it behave?** | scope, goals, affected layers, concrete behavior, compatibility, validation | a long architecture essay or a dump of code details |
| Proto (`service/**/*.proto`, `protocol/**/*.proto`) | **What is the wire/schema contract?** | RPCs, messages, field names, comments, compatibility-safe schema changes | rationale, rollout strategy, or cross-layer implementation detail |
| Implementation (`service/`, `sdk/`, `otdfctl/`, `lib/`, docs) | **How is it realized in code and docs?** | handlers, registration, business logic, tests, generated outputs, user docs | the sole source of intent when the change crosses modules |

Practical rule:

- Put the durable **decision** in an ADR.
- Put the cross-layer **change description** in a spec.
- Put the exact **contract** in proto.
- Put the executable **behavior** in code and tests.

A spec can reference an ADR and planned proto changes. It should not replace either.

## Monorepo layer model

Every spec should name the impacted layer or layers explicitly.

### `service`

Paths: `service/`

This layer owns the server binary and runtime behavior:

- service registration and mode selection, such as `service/pkg/server/services.go` and `service/pkg/server/start.go`
- namespace-scoped services like `kas`, `policy`, `authorization`, `wellknown`, `entityresolution`
- HTTP and ConnectRPC handlers, config loading, well-known registration, caching, tracing, and auth wiring

Because this repo uses a modular-binary architecture, specs should say which runtime modes are affected:

- `core`
- `kas`
- `ers`
- `all` when applicable

Also call out the affected service namespaces when relevant.

### `proto`

Paths: `service/**/*.proto`, `protocol/**/*.proto`, generated outputs under `protocol/go/`, published docs under `docs/openapi/` and `docs/grpc/`

This layer owns external and internal contracts.

Examples in this repo include:

- `service/kas/kas.proto`
- `service/wellknownconfiguration/wellknown_configuration.proto`

If a spec changes a proto contract, say whether the change is additive, deprecated, or breaking, and name the generated artifacts or docs that must move with it.

### `sdk`

Paths: `sdk/`

This layer owns client behavior and platform consumption, including discovery and defaulting behavior.

Examples include:

- reading well-known configuration
- choosing default KAS information
- handling rewrap responses and obligation-related metadata

If the service produces something and the SDK consumes it, the spec should describe both sides.

### `cli`

Paths: `otdfctl/`

This layer owns command UX:

- commands and flags
- output shape
- operator workflows
- local/admin tooling around platform capabilities

If a change is externally visible but only through CLI, say so directly instead of implying a service or proto change.

### `docs/ops`

Paths: `docs/`, `examples/`, config files like `opentdf-*.yaml`, deployment notes, and related operator guidance

This layer owns:

- user and contributor documentation
- example configs and example flows
- rollout notes, enablement steps, and operational caveats

If a change requires config, docs, or operator action, include that here even if code changes are elsewhere.

## Repo-specific writing guidance

### Start from current behavior

Anchor the spec in the code that exists today. Use repo paths, not vague descriptions.

For example, for service-discovery or KAS-related work, useful starting points include:

- `service/pkg/server/services.go`
- `service/pkg/server/start.go`
- `service/wellknownconfiguration/wellknown_configuration.go`
- `service/wellknownconfiguration/wellknown_configuration.proto`
- `service/kas/kas.proto`
- related ADRs in `adr/decisions/`

### Describe producers and consumers

This repo often has one layer producing behavior and another consuming it.

Examples:

- service registers well-known configuration
- proto defines the exposed contract
- SDK discovers and uses the data
- docs/ops explains how operators configure it

Name each side explicitly.

### Be explicit about mode and namespace impact

The service binary is modular. A change may affect only `core`, only `kas`, or a combination.

A good spec says things like:

- affects the `wellknown` namespace in `core`
- adds KAS contract surface in `kas`
- requires SDK changes but no CLI changes

### Prefer concrete behavior over abstract taxonomy

Good:

- “Add `base_key` to well-known configuration and define which service populates it.”
- “SDK uses the configured base key only when no more specific key mapping applies.”

Avoid:

- large status models
- speculative future architecture
- generic process language with no file or behavior references

### Keep frontmatter practical

Use only metadata that helps people and tools route the doc.

Recommended frontmatter fields:

- `title`
- `status`
- `summary`
- `owners`
- `created`
- `updated`
- `layers`
- `service_namespaces` when relevant
- `runtime_modes` when relevant
- `related` links to ADRs, protos, or implementation paths

If a field adds no value for the current spec, omit it.

### Status and execution semantics

Use status values consistently so future agents know whether a document is exploratory, review-ready, or executable.

Recommended meanings for specs in this repo:

- `draft` — working document; safe for exploration and review, not yet an implementation contract
- `proposed` — review-ready candidate awaiting human approval or broader sign-off
- `accepted` — approved source of truth for the current phase; eligible for execution when readiness checks also pass
- `implemented` — the accepted spec has been materially realized in code/docs/tests
- `superseded` — replaced by a newer accepted spec or a different approach

Practical rules:

- A spec executor should not treat `draft` or `proposed` as auto-executable without explicit human approval.
- `accepted` means the current phase behavior is approved strongly enough for implementation planning and execution.
- A proto draft may exist under a real repo path before acceptance, but it should be treated as part of review material until the linked spec is accepted.
- If the status is ambiguous or missing, stop and ask rather than assuming the document is executable.

### Show examples when the shape matters

Include a short example when any of these are true:

- JSON or well-known configuration shape matters
- request or response shape matters
- config or CLI usage matters
- compatibility depends on exact names

### Separate stable decisions from evolving execution detail

If the team has already chosen a direction, the ADR should hold the durable why.
The spec should then focus on what changes in this repo and how to validate it.

## Suggested naming

Put specs directly under `docs/specs/`.

Use a short, readable filename, for example:

- `docs/specs/default-kas-discovery.md`
- `docs/specs/kas-rewrap-obligation-surfacing.md`

Date prefixes are optional. Prefer readability over ceremony.

## Minimum useful spec

A useful spec in this repo usually includes:

1. a short summary
2. goals and non-goals
3. current behavior with file references
4. proposed behavior
5. impacted layers, namespaces, and runtime modes
6. compatibility or migration notes
7. validation plan

Use `SPEC-TEMPLATE.md` as the default starting point.
