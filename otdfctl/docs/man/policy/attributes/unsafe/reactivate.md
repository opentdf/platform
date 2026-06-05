---
title: Reactivate an attribute definition
command:
  name: reactivate
  flags:
    - name: id
      shorthand: i
      description: ID of the attribute definition
      required: true
---

# Unsafe Reactivate Warning

Reactivating an Attribute Definition can potentially open up an access path to any existing TDFs referencing values under that definition.

The Active/Inactive state of any Attribute Values under this Definition will NOT be changed.

Make sure you know what you are doing.

For more general information about attributes, see the `attributes` subcommand.

## Example

```shell
otdfctl policy attributes unsafe reactivate --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```
