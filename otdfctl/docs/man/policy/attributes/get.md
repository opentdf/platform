---
title: Get an attribute definition
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the attribute
---

Retrieve an attribute along with its metadata, rule, and values.

For more general information about attributes, see the `attributes` subcommand.

## Example

```shell
otdfctl policy attributes get --id=3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```
