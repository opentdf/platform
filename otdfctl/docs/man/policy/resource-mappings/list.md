---
title: List resource mappings
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: s
      description: Filter the list to resource mappings owned by this namespace (ID or FQN).
      default: ''
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more information about resource mappings, see the `resource-mappings` subcommand.

## Examples

```shell
otdfctl policy resource-mappings get --id=3ff446fb-8fb1-4c04-8023-47592c90370c
```
