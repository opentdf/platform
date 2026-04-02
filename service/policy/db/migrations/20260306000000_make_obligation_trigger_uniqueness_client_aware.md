# Make Obligation Trigger Uniqueness Client-Aware

This migration updates uniqueness semantics for `obligation_triggers` after the
introduction of optional `client_id` scoping.

## Why

The previous unique constraint only considered:

- `obligation_value_id`
- `action_id`
- `attribute_value_id`

That prevented creating multiple triggers for different PEP clients when all
other fields were the same.

## Changes

1. Drop the existing table-level unique constraint on:
   - `(obligation_value_id, action_id, attribute_value_id)`
   - Includes handling historical truncated constraint names in Postgres.
2. Add partial unique index for unscoped triggers:
   - `(obligation_value_id, action_id, attribute_value_id)` where `client_id IS NULL`
3. Add partial unique index for client-scoped triggers:
   - `(obligation_value_id, action_id, attribute_value_id, client_id)` where `client_id IS NOT NULL`

## Resulting Behavior

- Allows one unscoped trigger per obligation/action/attribute tuple.
- Allows one scoped trigger per unique `client_id` for the same tuple.
- Prevents duplicate scoped triggers for the same `client_id`.
