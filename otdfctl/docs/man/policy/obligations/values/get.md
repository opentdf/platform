---
title: Get an obligation value
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the obligation value
    - name: fqn
      shorthand: f
      description: FQN of the obligation value
---

Retrieve an obligation value along with its metadata.

If both `id` and `fqn` flag values are provided, `id` is preferred.

For more information about obligation values, see the manual for the `values` subcommand.

## Example

Get by ID:

```shell
otdfctl policy obligations values get --id=3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```

Get by FQN:

```shell
otdfctl policy obligations values get --fqn=https://namespace.com/drm/value/watermark
```
