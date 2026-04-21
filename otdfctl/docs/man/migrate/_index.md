---
title: Migrate resources

command:
  name: migrate
  aliases:
    - migration
  description: Migrate policy resources
  flags:
    - name: commit
      shorthand: c
      description: Writes changes to policy storage
      default: false
    - name: interactive
      shorthand: i
      description: Interactive walk through of migrations
      default: false
---

`migrate` groups commands used to migrate policy resources and related state.

The end-to-end workflow is not implemented yet, but the command surface is in place.

Available subcommands currently include `namespaced-policy` for migration planning and execution, and `prune` for cleanup flows.

The parent `migrate` command owns the shared `--commit` and `--interactive` flags.

`migrate prune` is separate from the existing destructive `otdfctl policy subject-condition-sets prune` command.

## Planned examples

```shell
otdfctl migrate namespaced-policy --scope=registered-resources --output=policy-migration.json
otdfctl migrate prune namespaced-policy --scope=registered-resources
otdfctl migrate namespaced-policy --scope=actions,subject-mappings,registered-resources --output=policy-migration.json --commit
```
