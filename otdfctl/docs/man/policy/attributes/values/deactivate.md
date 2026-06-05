---
title: Deactivate an attribute value
command:
  name: deactivate
  flags:
    - name: id
      shorthand: i
      description: The ID of the attribute value to deactivate
    - name: force
      description: Force deactivation without interactive confirmation (dangerous)
---

Deactivation preserves uniqueness of the attribute value within policy and all existing relations, essentially reserving it.

However, a deactivation of an attribute value means it cannot be entitled in an access decision.

For information about reactivation, see the `unsafe reactivate` subcommand.

For more information on attribute values, see the `values` subcommand.

## Example

```shell
otdfctl policy attributes values deactivate --id 355743c1-c0ef-4e8d-9790-d49d883dbc7d
```
