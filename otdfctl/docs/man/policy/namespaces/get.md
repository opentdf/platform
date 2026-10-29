---
title: Get an attribute namespace
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the attribute namespace
    - name: fqn
      shorthand: f
      description: FQN of the attribute namespace
---

Retrieve an attribute namespace by either its ID or FQN. Exactly one of `--id`
and `--fqn` is required.

For more information, see the `namespaces` subcommand.

## Examples

Get by ID:

```shell
otdfctl policy namespaces get --id=7650f02a-be00-4faa-a1d1-37cded5e23dc
```

Get by FQN:

```shell
otdfctl policy namespaces get --fqn=https://example.com
```
