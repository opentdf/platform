---
title: List obligation definitions
command:
  name: list
  aliases:
    - l
  flags:
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: namespace
      shorthand: n
      description: Namespace ID or FQN by which to filter results
---

List obligations definitions (optionally by namespace).

For more information about obligations, see the `obligations` subcommand.

## Example

```shell
otdfctl policy obligations list --limit 10 --offset 0
```
