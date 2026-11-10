---
title: List Registered Resource Values
command:
  name: list
  aliases:
    - l
  flags:
    - name: resource
      shorthand: r
      description: Identifier of the associated registered resource (ID or name)
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

List registered resource values in the platform Policy.

For more information about Registered Resource Values, see the manual for the `values` subcommand.

## Example

```shell
otdfctl policy registered-resources values list
```
