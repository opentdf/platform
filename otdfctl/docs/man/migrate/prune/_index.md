---
title: Prune Migrated Policy Objects

command:
  name: prune
---

`prune` groups commands used to remove policy resources that are no longer needed after migration or cleanup workflows.

The end-to-end cleanup workflow is not implemented yet, but the command surface is in place.

Available subcommands currently include `namespaced-policy` for policy cleanup workflows.

The parent `migrate` command provides the shared `--commit` flag used to apply deletions.

`migrate prune` is not the same as `otdfctl policy subject-condition-sets prune`. The existing subject-condition-set prune command deletes unmapped subject condition sets. `migrate prune` is only for cleaning up legacy objects after a migration run.

## Planned examples

```shell
otdfctl migrate prune namespaced-policy --scope=registered-resources
otdfctl migrate prune namespaced-policy --scope=actions,subject-mappings,registered-resources --commit
```
