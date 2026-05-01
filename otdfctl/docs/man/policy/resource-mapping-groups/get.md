---
title: Get a resource mapping group
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      description: The ID of the resource mapping group to get.
      default: ''
---

For more information about resource mapping groups, see the `resource-mapping-groups` subcommand.

## Examples

```shell
otdfctl policy resource-mapping-groups get --id=3ff446fb-8fb1-4c04-8023-47592c90370c
```
