---
title: List attribute namespaces
command:
  name: list
  aliases:
    - ls
    - l
  flags:
    - name: state
      shorthand: s
      description: Filter by state [active, inactive, any]
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more general information, see the `namespaces` subcommand.

## Example

```shell
otdfctl policy attributes namespaces list
```
