---
title: Migrate Namespaced Policy

command:
  name: namespaced-policy
  flags:
    - name: scope
      shorthand: s
      description: "Comma-separated scopes: actions, subject-condition-sets, subject-mappings, registered-resources, obligation-triggers"
      default: ''
---

## General Information

`namespaced-policy` is the migration entrypoint for moving legacy policy objects into namespaced policy.

The command prints a human-readable migration summary to stdout. Dry runs show the plan summary; `--commit` shows the committed summary with created target IDs.

Commit mode can partially apply changes before an error occurs. When that happens, the command prints a committed summary with `Result: failure` and per-scope `Created`, `Will Create`, and `Failed` sections so you can see what was applied and what still remains.

`--scope` is required and selects any subset of `actions`, `subject-condition-sets`, `subject-mappings`, `registered-resources`, and `obligation-triggers`.

The parent `migrate` command provides the shared `--commit` and `--interactive` flags.

`namespaced-policy` is intended to be non-destructive. Commit should create namespaced copies and record migration metadata, but it should not delete legacy objects. Cleanup belongs to `migrate prune`.

All target namespaces must already exist before the command runs. Planning should fail before any writes if a required namespace is missing.

## Pre-requisites

1. Run at least `v0.14.0` of the OpenTDF platform before using this migration.

2. Standard actions are seeded per namespace in that platform version. The migration expects those namespaced standard actions to exist when migrating references to `create`, `read`, `update`, and `delete`.

## Best practices

1. Before running any migration commands you should take a backup of your database to avoid any potential issues.

2. Turn on the `namespaced_policy` feature flag within your deployed service yaml to avoid creating any accidental non-namespaced policy objects.

3. While we allow you to perform a full migration of policy at once with the multiple scopes, we recommend that you migrate one-by-one in the following order:
   - Actions
   - Subject-Condition-Sets
   - Subject-Mappings
   - Obligation-Triggers
   - Registered-Resources

4. Use `--interactive` mode when migrating policy, this will give you the best chance of success for handling any issues that might occur. In addition, we ask for confirmation for each
object before creating it.

## Examples

```shell
otdfctl migrate namespaced-policy --scope=registered-resources
otdfctl migrate namespaced-policy --scope=actions,subject-mappings,registered-resources --commit
otdfctl migrate namespaced-policy --scope=actions,subject-mappings --interactive --commit
```

## Other information

1. For subject-condition-sets and actions, if they are not used by any other policy object they will not be migrated or considered for migration.
2. If you provide a parent scope, the dependent scopes will also be added. For example, given scope `subject-mappings` will also add scope: `actions`, `subject-condition-sets`
since those are required by `subject-mappings` to be migrated to a new namespace.
3. In `--interactive --commit` mode, declining the backup confirmation or aborting review prints an `aborted` summary and exits without applying the remaining changes.
4. In `--interactive` mode only create operations are reviewed. Existing standard objects and already migrated objects are not prompted.
