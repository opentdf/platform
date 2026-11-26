---
title: Agent Playbooks Guide
kind: guide
status: active
updated: 2026-05-24
scope: docs/agents
---

# Agent Playbooks Guide

This directory holds the **shared, human-readable source of truth** for agent workflows used in this repo.

Keep these docs:

- harness-agnostic first
- aligned to this repo’s monorepo and modular-binary architecture
- specific about artifact hierarchy, readiness gates, and quality bars
- practical enough to guide real work instead of becoming process theater

## What belongs here

Use `docs/agents/` for:

- orchestration playbooks
- artifact hierarchy guidance
- effort-routing and quality guidance
- execution playbooks for accepted ADR/spec/proto sets
- shared agent definitions that should be readable outside any single harness

Examples in this directory:

- `adr-spec-proto-orchestration.md` — how ADR/spec/proto work should be sequenced and reconciled
- `effort-routing-and-agent-quality.md` — how much process and reasoning a task needs
- `spec-executor.md` — shared playbook for executing an accepted spec into implementation

## Relationship to `docs/specs/`

Use `docs/specs/` for **spec content and templates**.

Use `docs/agents/` for **how agents should produce, review, reconcile, and execute those artifacts**.

In shorthand:

- `docs/specs/` = what a spec should look like
- `docs/agents/` = how agents should work with ADRs, specs, protos, and implementation

## Relationship to `.pi/agents/`

`docs/agents/` is the canonical shared location.

Harness-specific wrappers may live under `.pi/agents/` and should:

- reference the shared playbooks here
- adapt them to local tool/runtime semantics
- avoid redefining the repo workflow unless a harness-specific exception is truly needed

Preferred pattern:

- shared playbook or agent definition lives in `docs/agents/`
- thin wrapper lives in `.pi/agents/`

This keeps the workflow portable while still allowing Pi-specific execution details.

## Core repo truths to preserve

Agent playbooks in this directory should preserve the repo’s architectural model:

- `service` owns runtime behavior, namespaces, and modular-binary placement
- `proto` defines durable seam contracts
- `sdk` owns client behavior, discovery, fallback, and compatibility handling
- `cli` owns operator/developer command UX where applicable
- `docs/ops` owns rollout, migration, and deployment guidance

Do not blur those ownership boundaries just because multiple services can run in one binary.

## Artifact hierarchy

Unless a playbook states otherwise, keep this hierarchy:

- **ADR** — broadest, directional, may span multiple phases
- **Spec** — current-phase behavioral contract, usually one phase/slice
- **Proto** — tight seam contract, narrower than the spec and more durable than the current phase
- **Implementation** — code, tests, generated outputs, and docs that realize the accepted contract

A good playbook should reinforce this hierarchy rather than collapse it.

## Readiness and escalation

Good playbooks should help agents answer:

- Is the current artifact ready for the next one?
- Are open questions safely outside the current phase, or do they block progress?
- Is this a local cleanup issue, or does it require a human decision?

Default rule:

- escalate instead of guessing when unresolved questions materially affect service ownership, proto shape, SDK behavior, fallback behavior, rollout, or validation

## Review / cleanup loop

Playbooks may allow bounded review-cleanup loops for concrete, local issues.

Default limits:

- one active writer
- reviewer may trigger cleanup + re-review
- maximum **3** cycles
- escalate earlier for scope, architecture, ownership, or spec ambiguity

## Writing style

When adding new playbooks here:

- start from real repo concerns, not generic framework slogans
- name the affected layers explicitly
- prefer concise rules and checklists over essays
- keep provider/model examples illustrative, not mandatory, unless a harness-specific wrapper needs them
- separate shared guidance from harness-specific instructions

## Related guidance

- `AGENTS.md` at repo root — top-level repo workflow expectations
- `docs/specs/AGENTS.md` — spec-writing guidance
- `docs/agents/adr-spec-proto-orchestration.md`
- `docs/agents/effort-routing-and-agent-quality.md`
- `docs/agents/spec-executor.md`
