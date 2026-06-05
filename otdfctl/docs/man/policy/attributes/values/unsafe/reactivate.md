---
title: Reactivate an attribute value
command:
  name: reactivate
  flags:
    - name: id
      shorthand: i
      description: ID of the attribute value
      required: true
---

# Unsafe Reactivate Warning

Reactivating an Attribute Value can potentially open up an access path to any existing TDFs referencing values under that definition.

The Active/Inactive state of the Attribute Definition and Namespace above this Value will NOT be changed.

Make sure you know what you are doing.

For more information on attribute values, see the `values` subcommand.

## Example

```shell
otdfctl policy attributes values unsafe reactivate --id 355743c1-c0ef-4e8d-9790-d49d883dbc7d
```
