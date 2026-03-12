# Namespaced Actions PR Plan

This document tracks the rollout plan for namespaced actions across platform and `otdfctl`.

## Current Status

- ✅ Proto contract updates are in place in platform (`actions.proto`, `objects.proto`, proto validation tests).
- ⏳ DB + service/query behavior updates are still pending in platform.
- ⏳ `otdfctl` currently has temporary `[namespaced-actions]` skips for impacted e2e tests.

## PR Stack (Recommended)

### PR A (`otdfctl` first): CLI support for namespaced actions

Goal: stop request validation failures now by passing namespace context on action-related commands.

- Add namespace flags (`--namespace-id` / `--namespace-fqn`) where action requests require them.
- Plumb namespace fields into outgoing requests for:
  - actions CRUD/list/get paths
  - other command paths that resolve actions by name/id as needed
- Keep `[namespaced-actions]` skips in place initially; unskip only tests that become stable with CLI changes alone.

Why first: protos already require namespace selectors, so CLI can be made forward-compatible immediately.

### PR B (platform): DB groundwork migration

Goal: prepare schema for namespaced action behavior without forcing all query behavior in same PR.

- Add `actions.namespace_id` (nullable for legacy compatibility).
- Add/adjust constraints and indexes for namespaced uniqueness strategy.
- Backfill/seed approach for standard actions per namespace.
- Update schema ERD + migration notes.

### PR C (platform): Action service + action query namespace semantics

Goal: make actions fully namespace-aware.

- Implement namespace-aware `Create/Get/List/Update/Delete` actions behavior.
- Enforce required namespace semantics in service/DB layer.
- Ensure standard actions are immutable and available per namespace.
- Add/adjust action integration tests.

### PR D (platform): Downstream action consumers

Goal: make all action references namespace-aware.

- Update subject mappings, obligations, and registered resources action resolution/query behavior.
- Update fixtures + integration coverage for namespaced action usage.

### PR E (`otdfctl`): remove temporary `[namespaced-actions]` skips

Goal: restore full e2e coverage once backend behavior is complete.

- Unskip currently skipped tests in `e2e/actions.bats`, `e2e/obligations.bats`, `e2e/registered-resources.bats`, and `e2e/subject-mapping.bats`.
- Keep or update assertions to match final namespace-aware responses/requirements.

### PR F (`otdfctl`): migrate legacy custom actions to namespaces

Goal: provide an operator-safe path to migrate legacy custom actions (`namespace_id IS NULL`) into a namespace.

- Add a new migration command for actions (parallel to registered-resources migration UX):
  - e.g. `otdfctl policy migrate actions` (final command shape can follow existing migration command patterns).
- Support both migration modes:
  - interactive mode (prompt per action)
  - batch mode (single target namespace for all selected legacy actions)
- Include explicit safety/backup confirmation before commit mode, because migration may involve delete/recreate semantics for conflict handling.
- Add `--dry-run` behavior and clear summary output (`--json` friendly) showing:
  - actions to migrate
  - target namespace
  - conflicts/blocked items
  - migrated/skipped counts
- Add collision strategy for duplicate action names in target namespace (fail-fast and report by default; optional rename/override policy can be a follow-up if needed).
- Add unit tests with mocks for migration planning/execution and interactive vs batch flows.

## Merge / Dependency Guidance

- `otdfctl` PR A can be developed and merged early for compatibility.
- Platform PRs B/C/D should merge in order.
- `otdfctl` migration PR F should merge after platform C behavior is available in CI (and before/alongside PR E depending on release preference).
- `otdfctl` unskip PR E should merge after platform C/D behavior is available in CI environment.

## Test Strategy

- For each PR, prefer smallest relevant test scope first, then broader suites.
- Do not remove temporary skips until backing behavior is implemented and stable.
- Tag skip reasons with `[namespaced-actions]` so they are searchable and easy to unwind.
