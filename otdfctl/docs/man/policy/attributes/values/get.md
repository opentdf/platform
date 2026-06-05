---
title: Get an attribute value
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: The ID of the attribute value to get
---

Retrieve an attribute value along with its metadata.

For more general information about attribute values, see the `values` subcommand.

## Example

```shell
otdfctl policy attributes values get --id 355743c1-c0ef-4e8d-9790-d49d883dbc7d
```
