---
title: Get a dynamic value mapping
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      description: The ID of the dynamic value mapping to get
      shorthand: i
      required: true
      default: ''
---

Retrieve the specifics of a Dynamic Value Mapping by its ID.

For more information about dynamic value mappings, see the `dynamic-value-mappings` subcommand.

## Examples

Get a dynamic value mapping by ID:

```shell
otdfctl policy dynamic-value-mappings get --id 3c51a593-cd4d-4b74-9f97-3b3b6b0a6f21
```

Get a dynamic value mapping as JSON:

```shell
otdfctl policy dynamic-value-mappings get --id 3c51a593-cd4d-4b74-9f97-3b3b6b0a6f21 --json
```
