# Seed Standard Actions for Existing Namespaces

This migration retroactively seeds the four standard actions (create, read, update, delete) into all namespaces that already exist.

## Why

When a namespace is created, `CreateNamespace()` automatically calls `seedStandardActionsForNamespace()` to insert the standard CRUD actions scoped to that namespace. However, namespaces created before action namespacing was introduced (`20260312000000_add_namespace_to_actions.sql`) do not have namespace-scoped standard actions — they only have the legacy global standard actions.

The otdfctl policy migration tooling requires that every namespace already has standard actions before migrating existing unnamespaced policy (SMs, SCSs, RRs) into namespaces. Without this seed, migrated policy referencing standard actions would have no same-namespace action to rewrite references to.

## Changes

A single idempotent `INSERT ... ON CONFLICT DO NOTHING` that cross-joins all existing namespaces with the four standard action names and inserts any missing rows into the `actions` table.

## Resulting Behavior

- Every existing namespace will have namespace-scoped standard actions (create, read, update, delete) with `is_standard = TRUE`.
- New namespaces continue to receive standard actions via `CreateNamespace()` as before.
- Running this migration on a system where some or all namespaces already have standard actions is safe — conflicts are silently ignored.

## Rollback

The Down migration is intentionally a no-op. Namespace-scoped standard actions are required for namespace correctness and policy reference rewrites; deleting them on rollback could break existing namespaces.

## Operational Rollback Note

Rolling back past `20260312000000_add_namespace_to_actions.sql` is not a safe automatic path once namespace-scoped standard actions exist. That migration's Down path restores global `UNIQUE(name)` semantics on `actions`, which conflicts with multiple namespace-scoped rows for standard action names (`create`, `read`, `update`, `delete`).

Any rollback beyond action namespacing requires a separate, manual, and potentially destructive data remediation plan.
