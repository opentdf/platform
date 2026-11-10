---
title: Get a Registered Resource Value
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the registered resource value
    - name: fqn
      shorthand: f
      description: FQN of the registered resource value
---

Retrieve a registered resource value along with its metadata.

If both `id` and `fqn` flag values are provided, `id` is preferred.

For more information about Registered Resource Values, see the manual for the `values` subcommand.

## Example

Get by ID:

```shell
otdfctl policy registered-resources values get --id=3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```

Get by FQN:

```shell
otdfctl policy registered-resources values get --fqn=https://reg_res/my_name/value/my_value
```
