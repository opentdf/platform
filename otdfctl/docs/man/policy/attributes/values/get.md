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
    - name: fqn
      shorthand: f
      description: The FQN of the attribute value to get
---

Retrieve an attribute value by either its ID or FQN, along with its metadata.
Exactly one of `--id` and `--fqn` is required.

For more general information about attribute values, see the `values` subcommand.

## Examples

Get by ID:

```shell
otdfctl policy attributes values get --id 355743c1-c0ef-4e8d-9790-d49d883dbc7d
```

Get by FQN:

```shell
otdfctl policy attributes values get --fqn=https://example.com/attr/classification/value/secret
```
