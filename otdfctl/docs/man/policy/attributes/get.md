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
    - name: fqn
      shorthand: f
      description: FQN of the attribute
---

Retrieve an attribute by either its ID or FQN, along with its metadata, rule,
and values. Exactly one of `--id` and `--fqn` is required.

For more general information about attributes, see the `attributes` subcommand.

## Examples

Get by ID:

```shell
otdfctl policy attributes get --id=3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```

Get by FQN:

```shell
otdfctl policy attributes get --fqn=https://example.com/attr/classification
```
