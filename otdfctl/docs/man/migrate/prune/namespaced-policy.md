---
title: Prune Namespaced Policy

command:
  name: namespaced-policy
  flags:
    - name: scope
      shorthand: s
      description: "Comma-separated scopes: actions, subject-condition-sets, subject-mappings, registered-resources, obligation-triggers"
      default: ''
---

`namespaced-policy` is the cleanup entrypoint for namespaced policy migration.

The command surface is present, but the cleanup workflow is not implemented yet.

`--scope` is required and selects any subset of `actions`, `subject-condition-sets`, `subject-mappings`, `registered-resources`, and `obligation-triggers`.

`namespaced-policy` rebuilds the live dependency graph, inspects migration labels, and deletes only legacy objects it can prove are safe to remove for the selected scopes. It does not require a manifest file.

The parent `migrate` command provides the shared `--commit` flag used to apply deletions.

## Examples

```shell
otdfctl migrate prune namespaced-policy --scope=registered-resources
otdfctl migrate prune namespaced-policy --scope=actions,subject-mappings,registered-resources --commit
```
