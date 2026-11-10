---
title: Delete a resource mapping group
command:
  name: delete
  flags:
    - name: id
      description: The ID of the resource mapping group to delete
      default: ''
    - name: force
      description: Force deletion without interactive confirmation (dangerous)
---

For more information about resource mapping groups, see the `resource-mapping-groups` subcommand.

## Examples

```shell
otdfctl policy resource-mapping-groups delete --id=3ff446fb-8fb1-4c04-8023-47592c90370c
```
