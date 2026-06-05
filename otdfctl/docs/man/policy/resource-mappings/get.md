---
title: Get a resource mapping
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      description: The ID of the resource mapping to get.
      default: ''
---

For more information about resource mappings, see the `resource-mappings` subcommand.

## Examples

```shell
otdfctl policy resource-mappings get --id=3ff446fb-8fb1-4c04-8023-47592c90370c
```
