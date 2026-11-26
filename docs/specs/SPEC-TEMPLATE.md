---
title: "<short, concrete change title>"
status: draft # draft | proposed | accepted | implemented | superseded
summary: "<2-4 sentence summary of the behavior change and why it matters>"
owners:
  - "@team-or-handle"
created: "YYYY-MM-DD"
updated: "YYYY-MM-DD"
layers:
  - service
service_namespaces:
  - "<namespace-if-applicable>"
runtime_modes:
  - "<core|kas|ers|all>"
related:
  adr:
    - "adr/decisions/<decision>.md"
  proto:
    - "service/<area>/<file>.proto"
  implementation:
    - "service/<area>/"
    - "sdk/"
---

# <short, concrete change title>

> Keep this spec human-readable first. Remove unused sections instead of filling the document with boilerplate.

## Summary

Describe the change in plain language:

- what changes
- who produces it
- who consumes it
- which layer boundaries matter

## Goals

- <goal 1>
- <goal 2>

## Non-goals

- <explicitly out of scope>
- <things intentionally left unchanged>

## Current behavior

Describe how the repo behaves today, with file references.

Examples of the level of detail expected:

- service registration happens in `service/pkg/server/services.go` and `service/pkg/server/start.go`
- well-known configuration is aggregated in `service/wellknownconfiguration/wellknown_configuration.go`
- the current contract is defined in `service/wellknownconfiguration/wellknown_configuration.proto` or `service/kas/kas.proto`
- SDK behavior lives under `sdk/`

If helpful, add a short current-state example.

## Proposed behavior

Describe the desired end state.

Focus on observable behavior and repo boundaries, not line-by-line implementation.

### Service

State the service-layer changes.

Call out:

- affected namespaces
- affected runtime modes (`core`, `kas`, `ers`, `all`)
- config registration or discovery behavior
- handler or server behavior if relevant

If service is not affected, say `Not affected`.

### Proto

State whether any `.proto` contracts change.

Call out:

- messages, fields, or RPCs added/changed/deprecated
- compatibility expectations
- generated artifacts or docs that will need regeneration

If proto is not affected, say `Not affected`.

### SDK

State any client-side or consumer behavior.

Call out:

- discovery behavior
- defaulting/fallback logic
- request/response handling
- compatibility or migration behavior

If SDK is not affected, say `Not affected`.

### CLI

State any `otdfctl/` or other CLI impact.

If CLI is not affected, say `Not affected`.

### Docs/Ops

State any documentation, config, rollout, or operator impact.

Examples:

- new config keys in `opentdf-*.yaml`
- updated examples under `docs/` or `examples/`
- deployment or migration notes

If docs/ops is not affected, say `Not affected`.

## Data shapes and examples

Add only the examples needed to make the change unambiguous.

Possible examples:

- well-known configuration JSON
- request/response payloads
- config snippets
- CLI invocations

```json
{
  "example": true
}
```

## Compatibility and migration

Document anything a reviewer or implementer must preserve.

Consider:

- additive vs breaking proto changes
- old clients vs new clients
- default behavior when new config is absent
- rollout order across service, SDK, and CLI
- whether docs and generated OpenAPI/gRPC output must change

## Validation

List the checks that should prove the work is complete.

Examples:

- unit tests for service or SDK behavior
- `go test ./...` in affected modules
- generated docs or proto regeneration checks
- manual verification of a well-known endpoint or CLI command
- compatibility checks against existing clients

## Risks and open questions

Keep this short and concrete.

Examples:

- unclear ownership of a producer/consumer boundary
- rollout sequencing risk between service and SDK
- unresolved compatibility edge case

## Out-of-scope follow-ups

List any obvious next steps that are intentionally deferred so they do not quietly expand the current change.
