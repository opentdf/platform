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

`namespaced-policy` is the migration entrypoint for moving legacy policy objects into namespaced policy.

The command prints a human-readable migration summary to stdout. Dry runs show the plan summary; `--commit` shows the committed summary with created target IDs.

`--scope` is required and selects any subset of `actions`, `subject-condition-sets`, `subject-mappings`, `registered-resources`, and `obligation-triggers`.

The parent `migrate` command provides the shared `--commit` and `--interactive` flags.

`namespaced-policy` is intended to be non-destructive. Commit should create namespaced copies and record migration metadata, but it should not delete legacy objects. Cleanup belongs to `migrate prune`.

All target namespaces must already exist before the command runs. Planning should fail before any writes if a required namespace is missing.

## Examples

```shell
otdfctl migrate namespaced-policy --scope=registered-resources
otdfctl migrate namespaced-policy --scope=actions,subject-mappings,registered-resources --commit
```
