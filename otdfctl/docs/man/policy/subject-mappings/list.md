---
title: List subject mappings
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

For more information about subject mappings, see the `subject-mappings` subcommand.

## Example

```shell
otdfctl policy subject-mappings list

otdfctl policy subject-mappings list --namespace "https://example.com"
```
