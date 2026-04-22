---
title: Get an obligation definition
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the obligation
    - name: fqn
      shorthand: f
      description: FQN of the obligation
---

Retrieve an obligation definition along with its metadata and values.

If both `id` and `fqn` flag values are provided, `id` is preferred.

For more information about obligations, see the manual for the `obligations` subcommand.

## Example

Get by ID:

```shell
otdfctl policy obligations get --id=3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```

Get by FQN:

```shell
otdfctl policy obligations get --fqn=https://namespace.com/obl/drm
```
