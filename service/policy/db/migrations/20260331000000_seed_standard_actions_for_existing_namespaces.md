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

The Down migration removes all namespace-scoped standard actions (`is_standard = TRUE` and `namespace_id IS NOT NULL`). This undoes both this seed migration and any standard actions created by `CreateNamespace()` going forward, effectively reverting to global-only standard actions.
