---
title: List Actions
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: s
      description: Namespace ID or FQN
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more information about Actions, see the manual for the `actions` subcommand.

## Example

```shell
otdfctl policy actions list --namespace https://example.com
```
