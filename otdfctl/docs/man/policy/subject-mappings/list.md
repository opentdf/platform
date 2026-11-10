---
title: List subject mappings
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
---

For more information about subject mappings, see the `subject-mappings` subcommand.

## Example

```shell
otdfctl policy subject-mappings list
```
