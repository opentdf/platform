---
title: Migrate Namespaced Policy

command:
  name: namespaced-policy
  flags:
    - name: scope
      shorthand: s
      description: "Comma-separated scopes: actions, subject-condition-sets, subject-mappings, registered-resources, obligation-triggers"
      default: ''
    - name: output
      shorthand: o
      description: Path to the migration manifest JSON artifact
      default: ''
---

`namespaced-policy` is the migration entrypoint for moving legacy policy objects into namespaced policy.

The command surface is present, but the migration workflow is not implemented yet.

`--scope` is required and selects any subset of `actions`, `subject-condition-sets`, `subject-mappings`, `registered-resources`, and `obligation-triggers`.

`--output` is required and specifies where the migration manifest JSON artifact is written. Dry-run is expected to write the planned artifact, and `--commit` is expected to rewrite the same file with target IDs after successful execution.

The parent `migrate` command provides the shared `--commit` and `--interactive` flags.

`namespaced-policy` is intended to be non-destructive. Commit should create namespaced copies and record migration metadata, but it should not delete legacy objects. Cleanup belongs to `migrate prune`.

All target namespaces must already exist before the command runs. Planning should fail before any writes if a required namespace is missing.

## Examples

```shell
otdfctl migrate namespaced-policy --scope=registered-resources --output=policy-migration.json
otdfctl migrate namespaced-policy --scope=actions,subject-mappings,registered-resources --output=policy-migration.json --commit
```
