---
title: Get a Standard or Custom Action
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the action
    - name: name
      shorthand: n
      description: Name of the action
---

If both `id` and `name` flag values are provided, `id` is preferred.

For more information about Actions, see the manual for the `actions` subcommand.

## Example

Get by ID:

```shell
otdfctl policy actions get --id e1402c63-eeaa-45e2-85d2-b939d135941f
```

Get by Name:

```shell
otdfctl policy actions get --name read
```
