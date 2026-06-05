---
status: 'proposed'
date: '2026-03-30'
tags:
 - policy
 - authorization
 - namespaced-policy
driver: '@elizabethhealy'
---

# Namespaced Subject Mapping Decisioning in PDP

## Context and Problem Statement

Policy objects are moving toward strict namespace ownership, but access decisioning still treats actions as unscoped names in several evaluation paths. Subject mappings are also transitioning from legacy unnamespaced records to namespace-owned records. This creates ambiguity when a request action name exists in multiple namespaces and when a single resource includes attributes from multiple namespaces.

We need a decisioning model that is namespace-correct, fail-closed, and compatible with staged rollout using the `EnforceNamespacedEntitlements` feature flag.

## Decision Drivers

- Preserve existing multi-namespace resource semantics (`AND` behavior) while adding namespace correctness.
- Prevent cross-namespace action matches when namespaced policy mode is enabled.
- Keep rollout safe via feature-flagged behavior split.
- Avoid startup coupling by keeping standard-action checks lazy at evaluation time.

## Decision Outcome

Chosen option: **Resolve request action identity within each evaluation namespace context**.

For `GetDecisionRequest`/`GetDecisionMultiResourceRequest`, request validation still requires `action.name` (current proto contract). During evaluation, matching is always applied per namespace context (derived from the rule/value being evaluated), not globally.

Request-action matching precedence is explicit (given the request action object):

1. `action.id` (exact identity, when present)
2. `action.name + action.namespace` (scoped identity, when namespace is present)
3. `action.name` only (contextual identity)

When identity is explicit (`id` or `name+namespace`), decisioning does not fall back to looser name-only matching. It fails closed only if that explicit identity is unresolved or mismatched for the evaluated namespace context.

Feature-flag mode split:

- `EnforceNamespacedEntitlements=false`: preserve existing legacy behavior (no new namespace filtering semantics introduced by this change).
- `EnforceNamespacedEntitlements=true`: enforce namespaced subject mapping evaluation (unnamespaced SMs are ignored) and require action namespace equality for each evaluated namespace.

Direct entitlements in strict mode:

- Direct entitlements are still modeled as action names per attribute-value FQN.
- During PDP evaluation, each direct-entitlement action is hydrated with the namespace of its attributed value context.
- This makes direct entitlements participate in the same namespace-aware action matching rules as subject-mapping-derived entitlements.
- Direct-entitlement actions are merged with subject-mapping actions per value FQN (not replacing them).

Subject mapping namespace enforcement (strict mode):

- Subject mapping namespace must match the namespace of the referenced attribute value.
- Subject mapping namespace must match the namespace of the referenced subject condition set.
- Name-based action matching is evaluated in the same namespace context as the SM/value under evaluation.

For multi-namespace resources, existing `AND` semantics remain unchanged: all required namespace-scoped checks must pass, and missing action support in any required namespace denies access.

## Consequences

- 🟩 **Good**, because action evaluation becomes deterministic and namespace-safe.
- 🟩 **Good**, because feature-flagged split allows staged migration without mixed-mode ambiguity.
- 🟩 **Good**, because fail-closed behavior prevents accidental entitlement via cross-namespace action reuse.
- 🟥 **Bad**, because policy admins must ensure required actions exist in each relevant namespace.
- 🟥 **Bad**, because debugging becomes harder without explicit namespace-aware logs.

## Validation

Validation is done through PDP and decisioning tests covering:

- mode split (`EnforceNamespacedEntitlements=false` vs `true`) for subject mapping inclusion,
- strict-mode subject mapping namespace scoping (unnamespaced SMs skipped),
- namespace-aware action matching in rule evaluation paths,
- multi-namespace resource behavior where one missing namespace action causes deny,
- regression checks to confirm existing `AND` behavior is preserved.

## Implementation Notes

- Thread `EnforceNamespacedEntitlements` into PDP runtime configuration.
- Filter subject mappings at PDP construction by mode (namespaced vs unnamespaced).
- Enforce subject mapping namespace consistency during create/update operations.
- Centralize action matching in a namespace-aware helper used by all rule/action checks.
- Derive required namespace per evaluated value/rule context.
- Keep standard/custom action existence checks lazy at evaluation time.
- Add debug logs including requested action, required namespace, candidate namespace, and rule/value context.

## Rollout

1. Land logic behind `EnforceNamespacedEntitlements`.
2. Keep default mode as legacy (`false`) until policy data migration is complete.
3. Validate namespaced policy data readiness.
4. Flip `EnforceNamespacedEntitlements=true` and monitor mismatch/deny behavior.
5. Remove legacy branch once namespaced mode is stable.
