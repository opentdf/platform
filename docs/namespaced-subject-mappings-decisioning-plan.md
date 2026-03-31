# Namespaced Subject Mappings: Decisioning Plan

## Agreed Behavior

- `NamespacedPolicy=false` => keep current legacy behavior (no namespace filtering at SM load time; existing name-based matching behavior remains).
- `NamespacedPolicy=true` => enforce namespaced subject mapping/action evaluation.
- For a single resource containing attribute values from multiple namespaces, keep existing `AND` behavior.
- If requested action is missing in any required namespace, fail closed.
- Standard action existence is checked lazily at evaluation time (no startup invariant).

## Current Baseline (Verified)

- Existing PDP decisioning for a single resource with multi-namespace attributes behaves as `AND` at data-rule level.
  - Example coverage: `service/internal/access/v2/pdp_test.go:2344` and follow-up assertions.
- Current action checks are primarily name-based in evaluation paths.
  - RR AAV filtering: `service/internal/access/v2/evaluate.go` (`getResourceDecision`)
  - Rule checks: `allOfRule`, `anyOfRule`, `hierarchyRule` in `service/internal/access/v2/evaluate.go`

## Design Decision

Per-namespace action resolution is done during entitlement/rule evaluation (not request parsing).

- Request action remains unnamespaced (`action.name` from request).
- Resolution context is the namespace of the value/SM/rule currently being evaluated.
- Match requires:
  - name equality, and
  - namespace equality (when `NamespacedPolicy=true`).

This keeps decisioning context-local and avoids leaking cross-namespace action matches.

## Request Action Semantics

`GetDecisionRequest` currently carries `policy.Action`. We will support three request-action shapes with explicit precedence:

1. `action.id` provided (most specific)
   - Resolve exact action by ID.
   - Treat resolved action namespace as authoritative.
   - If ID is missing/invalid for the required evaluation context, fail closed.
2. `action.name` + `action.namespace` provided
   - Resolve by name within provided namespace.
   - If not found in required evaluation context, fail closed.
3. `action.name` only (least specific)
   - Resolve contextually per evaluated namespace (value/rule namespace).
   - In strict mode, this remains namespace-aware at evaluation time.

### Precedence Rule

- If `id` is present, use `id` semantics (ignore name-only fallback behavior).
- Else if `name+namespace` present, use scoped-name semantics.
- Else use name-only contextual semantics.

## Implementation Plan (Detailed)

### 1) Thread feature flag into PDP runtime

Code touchpoints:

- `service/internal/access/v2/pdp.go`

Changes:

- Add `namespacedPolicy bool` field on `PolicyDecisionPoint`.
- Extend `NewPolicyDecisionPoint(...)` to accept/set the flag.
- Thread flag from policy/access service construction into PDP instantiation sites.

### 2) Filter SMs at PDP load time (strict mode only)

Code touchpoint:

- `service/internal/access/v2/pdp.go` inside `NewPolicyDecisionPoint` loop over `allSubjectMappings`.

Changes:

- In namespaced mode, skip SMs without namespace.
- In legacy mode, keep current behavior (no additional filtering introduced by this work).
- Keep validation + warning log on skipped/invalid SMs.

Reason:

- Enforces clean mode split once and prevents mixed-evaluation edge cases downstream.

### 3) Add namespace-aware action match helper

Code touchpoint:

- `service/internal/access/v2/evaluate.go`

Add helper (shape example):

- `isRequestedActionMatch(requestedActionName string, requiredNamespaceID string, entitledAction *policy.Action, namespacedPolicy bool) bool`

Behavior:

- `namespacedPolicy=false`: preserve existing behavior (case-insensitive name match; no new namespace gating in this change).
- `namespacedPolicy=true`: case-insensitive name match and entitled action namespace must equal `requiredNamespaceID`.

Request-shape integration:

- `id` path: require exact ID match, then namespace consistency in strict mode.
- `name+namespace` path: require namespace-aware scoped name match.
- `name` path: namespace-aware contextual matching only when strict mode is enabled.

### 4) Apply helper in all action comparison paths

Code touchpoints:

- `service/internal/access/v2/evaluate.go`
  - RR AAV filtering in `getResourceDecision`
  - `allOfRule`
  - `anyOfRule`
  - `hierarchyRule`

Changes:

- Replace name-only checks with helper-based namespace-aware checks.

### 5) Carry namespace context into rule checks

Problem:

- Current rule functions use value FQNs and entitlements, but action checks don’t receive explicit namespace context per value.

Plan:

- Derive required namespace from `accessibleAttributeValues[valueFQN].Attribute.Namespace` (or value namespace if needed).
- Pass `requiredNamespaceID` into action match checks for each evaluated value FQN.

### 6) Fail-closed semantics for missing action in required namespace

Behavior:

- If any required value/rule cannot find matching action in that namespace, rule fails.
- For multi-namespace resource under `AND`, one failure denies the resource decision.
- For explicit action identity (`id` or `name+namespace`), decisioning does not fall back to looser matching; it denies only when that explicit identity is unresolved or mismatched for the evaluated namespace context.

Notes:

- This naturally aligns with existing `allOfRule`/resource result aggregation model.

### 7) Keep lazy standard-action behavior

Behavior:

- No startup seed validation required.
- If standard/custom action is missing in a required namespace at evaluation time, decision fails closed.

### 8) Logging/audit improvements

Add targeted debug/warn logs where mismatch/failure occurs:

- requested action name
- required namespace
- candidate action namespace (if any)
- rule/value FQN context

This will reduce debugging time when rollouts begin.

## Test Plan (Detailed)

### Unit/logic tests

1. `NamespacedPolicy=false`
   - legacy behavior unchanged (no strict namespace filtering introduced)
   - regression checks for existing name-based matching behavior
2. `NamespacedPolicy=true`
   - unnamespaced SM ignored
   - namespaced SM evaluated
3. Namespace-aware action matching helper
   - match name+namespace succeeds
   - name match with wrong namespace fails
   - legacy mode keeps existing name-based behavior
4. Request action shape precedence
   - `id` beats `name`
   - `name+namespace` is scoped
   - `name` only is contextual

### PDP behavior tests

0. Legacy-mode regression (`NamespacedPolicy=false`)
   - mixed namespaced + unnamespaced policy data continues to evaluate with current behavior (no strict namespace gating introduced)

1. Multi-namespace attrs in one resource, action present in all namespaces => permit
2. Multi-namespace attrs in one resource, action missing in one namespace => deny
3. RR AAV path respects namespace-aware action match (not name-only)
4. Existing `AND` behavior remains unchanged outside namespace-aware action filtering
5. Action request-shape matrix (`id`, `name+namespace`, `name`) across both GetDecision APIs

### Regression safety

- Re-run existing decisioning and obligations PDP suites to ensure no unintended semantic shifts.

## Rollout Plan

1. Land code behind `NamespacedPolicy` flag.
2. Keep default behavior (`false`) in environments until migration complete.
3. Validate policy data readiness (SM/SCS/actions namespaced) before flip.
4. Flip to `true`; monitor deny/mismatch logs.
5. Remove compatibility branch once migration is complete and stable.

## Open Questions

- Exact expected error/log wording when action is missing in required namespace.
- Whether to expose namespace-mismatch reason in decision debug output/API diagnostics.

## Non-Goals

- Changing obligation aggregation semantics.
- Introducing mixed-mode fallback (`evaluate both namespaced + unnamespaced SM`) once flag logic is strict.
