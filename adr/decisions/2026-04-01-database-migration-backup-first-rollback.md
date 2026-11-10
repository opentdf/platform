---
status: 'proposed'
date: '2026-04-01'
tags:
 - database
 - migrations
 - operations
 - rollback
driver: '@elizabethhealy'
consulted:
  - '@jakedoublev'
  - '@c-r33d'
---
# Database Migration Rollback Posture: Backup-First Recovery

## Context and Problem Statement

OpenTDF ships schema and data migrations that evolve policy and platform behavior over time. Some migrations are structurally reversible; others are intentionally lossy or operationally risky to reverse in-place, especially when data has been rewritten, deduplicated, or normalized.

We need a clear, operator-safe stance: what should customers rely on as the primary rollback mechanism when a migration fails, has unexpected impact, or a change must be reverted.

## Decision Drivers

* Customer safety in production environments
* Predictable rollback outcomes under incident pressure
* Avoidance of data corruption or accidental data loss from complex down-migrations
* Clear contract between product behavior and operator responsibilities
* Alignment with common enterprise database change-management practices

## Considered Options

* Treat migration `Down` scripts as the primary rollback mechanism in all cases
* Define backup/restore as the primary rollback mechanism; keep `Down` as best-effort
* Disallow `Down` scripts entirely and require only forward fixes

## Decision Outcome

Chosen option: "Define backup/restore as the primary rollback mechanism; keep `Down` as best-effort".

### Consequences

* 🟩 **Good**, because operators have a deterministic and well-understood recovery path (restore known-good backup/snapshot).
* 🟩 **Good**, because this reduces dependence on complex, high-risk data-rewrite rollback logic.
* 🟩 **Good**, because this aligns with how most production DB operations are run in practice.
* 🟨 **Neutral**, because migration `Down` scripts remain useful for development/test and selective operational cases.
* 🟥 **Bad**, because backup/restore may increase recovery time vs. a simple schema-only down migration.
* 🟥 **Bad**, because operators must maintain and test backup/restore procedures.

## Policy

Before running OpenTDF migrations in any environment that matters, operators should:

1. Create a verified database backup/snapshot.
2. Ensure restore procedures are tested and available.
3. Prefer restore from backup if migration outcomes are unacceptable.

`Down` migrations are provided as operational aids and may be best-effort. They are not a guarantee of lossless restoration to prior logical state in all scenarios.

## Application to Namespaced Policy Migrations

For namespaced policy/action migrations, OpenTDF may provide downgrade paths, but these can involve data remapping or identity collapse semantics. If an operator wants to revert namespaced policy adoption with high confidence, the recommended path is restoring the pre-migration backup.

## Validation

* Release notes and migration docs must state backup-first guidance.
* Operational runbooks should include pre-migration backup and restore drills.
* PR reviews for migrations should evaluate whether `Down` is safe, lossy, or intentionally no-op.

## Industry Alignment (Examples)

This posture is consistent with common real-world practice:

* **PostgreSQL operations guidance** commonly emphasizes taking backups before major schema/data changes.
* **Managed databases (e.g., AWS RDS/Aurora)** center rollback around snapshots and point-in-time restore.
* **Flyway/Liquibase usage in production** often treats rollback scripts as helpful but not a substitute for tested backup/restore, especially for complex data migrations.
* **Large SaaS/platform upgrade guidance (e.g., GitLab self-managed upgrades)** strongly recommends verified backups before upgrades/migrations.

## More Information

This ADR defines the operational contract:

* We will continue to implement safe `Down` behavior where feasible.
* We will explicitly document lossy/no-op downgrades when needed.
* The primary production safety mechanism remains backup + restore.
