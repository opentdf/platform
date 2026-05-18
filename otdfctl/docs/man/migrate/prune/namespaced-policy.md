---
title: Prune Namespaced Policy

command:
  name: namespaced-policy
  flags:
    - name: scope
      shorthand: s
      description: "One scope to prune: actions, subject-condition-sets, subject-mappings, registered-resources, obligation-triggers"
      default: ''
---

## General Information

`namespaced-policy` is the cleanup entrypoint for namespaced policy migration.

The command prints a human-readable prune summary to stdout. Dry runs show the planned deletions and blocked items; `--commit` shows the committed summary with the objects that were deleted.

`--scope` is required and must be exactly one of `actions`, `subject-condition-sets`, `subject-mappings`, `registered-resources`, or `obligation-triggers`.

`namespaced-policy` rebuilds the live dependency graph, inspects migration labels, and deletes only legacy objects it can prove are safe to remove for the selected scope.

The parent `migrate` command provides the shared `--commit` and `--interactive` flags. `--interactive` lets you review the prune plan before execution, and when paired with `--commit` it also asks for backup confirmation and per-delete confirmation before any deletion is applied.

## Pre-requisites

1. Run at least `v0.14.0` of the OpenTDF platform before using this prune flow.

2. Run `otdfctl migrate namespaced-policy` successfully before pruning. Prune only deletes legacy objects after it can match them to the expected migrated targets and their `migrated_from` labels.

## Delete safety

An object is safe to delete only when prune can tie the legacy source object to the expected migrated target and prove the source is no longer needed.

- `delete`: the source has the expected migrated target and prune found no remaining legacy dependency that still requires the source object.
- `blocked`: prune will not delete the source. Common reasons are that the source is still referenced by legacy policy or that the source object has not actually been migrated yet.
- `unresolved`: prune found something close to a migrated target, but it cannot prove the source and target match safely. Common reasons are missing or mismatched `migrated_from` labels, no matching labeled target, or a registered resource source that still contains values outside the resolved migration view.

In practice, prune relies on current legacy references plus `migrated_from` metadata on the namespaced targets. If that evidence is incomplete or inconsistent, the object is left in place instead of being deleted.

## Best practices

1. Before running any prune commands you should take a backup of your database to avoid any potential issues.

2. Turn on the `namespaced_policy` feature flag within your deployed service yaml to avoid creating any accidental non-namespaced policy objects.

3. Prune one scope at a time.

4. We recommend pruning in the reverse order of migration so dependents are removed before their dependencies:
   - Registered-Resources
   - Obligation-Triggers
   - Subject-Mappings
   - Subject-Condition-Sets
   - Actions

## Examples

```shell
otdfctl migrate prune namespaced-policy --scope=registered-resources
otdfctl migrate prune namespaced-policy --scope=obligation-triggers --commit
otdfctl migrate prune namespaced-policy --scope=obligation-triggers --interactive --commit
```

## Other Information

1. Actions and subject-condition-sets are pruned a little differently from the other scopes. Instead of reusing the resolved migration view, prune classifies them directly from the current legacy objects, their current legacy references, and the canonical migrated targets it can find. We do that because actions and subject-condition-sets are expected to be pruned last. By the time you reach those scopes, their legacy dependents such as subject mappings, registered resources, and obligation triggers should already be gone, so the safest decision comes from checking the live legacy dependency graph at prune time. That also means some actions or subject-condition-sets that were never used by any other legacy policy object can still end up `blocked`. If prune cannot find a canonical migrated target for the source object, it leaves the source in place as `blocked` instead of assuming it is safe to delete. For example, if a custom action `decrypt` is no longer referenced by any legacy subject mapping, registered resource, or obligation trigger and prune finds a namespaced `decrypt` target with `metadata.labels.migrated_from=<legacy-action-id>`, the source action is safe to delete. If no canonical namespaced `decrypt` target exists, the source action is reported as `blocked` because prune cannot prove that the object was actually migrated.
