---
title: Prune Migrated Policy Objects

command:
  name: prune
---

`prune` groups commands used to remove policy resources that are no longer needed after migration or cleanup workflows.

Available subcommands currently include `namespaced-policy` for policy cleanup workflows.

The parent `migrate` command provides the shared `--commit` and `--interactive` flags. `--interactive` lets you review prune plans before execution, and when paired with `--commit` it also adds confirmation before deletions are applied.

`migrate prune` is not the same as `otdfctl policy subject-condition-sets prune`. The existing subject-condition-set prune command deletes unmapped subject condition sets. `migrate prune` is only for cleaning up legacy objects after a migration run.
