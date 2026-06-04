---
title: List resource mapping groups
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace-id
      description: Filter the list to resource mapping groups owned by this namespace ID.
      default: ''
    - name: namespace-fqn
      description: Filter the list to resource mapping groups owned by this namespace FQN.
      default: ''
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more information about resource mapping groups, see the `resource-mapping-groups` subcommand.

## Examples

```shell
otdfctl policy resource-mapping-groups list
```
