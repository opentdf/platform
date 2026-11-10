---
title: Prune (delete all un-mapped Subject Condition Sets)

command:
  name: prune
  flags:
    - name: force
      description: Force prune without interactive confirmation (dangerous)
---

This command will delete all Subject Condition Sets that are not utilized within any Subject Mappings and are therefore 'stranded'.

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Example

```shell
otdfctl policy subject-condition-set prune
```
