# Add Namespace to Actions

This migration introduces namespace-scoped actions by adding `namespace_id` to `actions` and updating uniqueness semantics.

## Why

Policy objects are namespaced, and action references need to support same-namespace resolution. This migration enables actions to be scoped per namespace while preserving legacy/global actions.

## Up Migration

The Up migration:

- Adds nullable `namespace_id` to `actions` (`REFERENCES attribute_namespaces(id) ON DELETE CASCADE`).
- Replaces global `UNIQUE(name)` with two partial uniqueness constraints:
  - `UNIQUE(namespace_id, name)` when `namespace_id IS NOT NULL` (namespaced actions)
  - `UNIQUE(name)` when `namespace_id IS NULL` (legacy/global actions)
- Adds `idx_actions_namespace_id` for namespaced lookup performance.

## Down Migration

The Down migration is data-aware and performs a deterministic canonicalization before restoring global-only action semantics.

Steps:

1. Build an action-id remap (`old_action_id -> canonical_action_id`) by action name.
2. Canonical action selection order per name is:
   - prefer global (`namespace_id IS NULL`)
   - then earliest `created_at`
   - then smallest `id`
3. Remap and deduplicate references in:
   - `subject_mapping_actions`
   - `registered_resource_action_attribute_values`
   - `obligation_triggers`
4. Delete duplicate (non-canonical) action rows.
5. Drop namespace indexes, restore global `UNIQUE(name)`, and drop `namespace_id`.

## Rollback Semantics

Rollback is intentionally **lossy** with respect to namespace-level action identity.

- Actions sharing the same `name` are collapsed to one canonical global action row.
- Referencing rows are rewritten to canonical action ids.
- Distinct namespace-scoped action ids for the same name are not preserved after rollback.

This behavior is required to safely re-establish global `UNIQUE(name)` without orphaning references.
