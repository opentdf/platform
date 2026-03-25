---
title: List Subject Condition Set

command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: n
      description: Namespace ID or FQN to filter results
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Example

```shell
otdfctl policy subject-condition-set list

otdfctl policy subject-condition-set list --namespace "https://example.com"
```
