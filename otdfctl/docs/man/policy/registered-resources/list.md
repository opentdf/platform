---
title: List Registered Resources
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: s
      description: Namespace ID or FQN to filter results
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more information about Registered Resources, see the `registered-resources` subcommand.

## Example

```shell
otdfctl policy registered-resources list
```
