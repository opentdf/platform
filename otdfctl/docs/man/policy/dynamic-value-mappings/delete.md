---
title: Delete a dynamic value mapping
command:
  name: delete
  aliases:
    - d
  flags:
    - name: id
      description: The ID of the dynamic value mapping to delete
      shorthand: i
      required: true
      default: ''
    - name: force
      description: Force delete without interactive confirmation
---

Delete a Dynamic Value Mapping by its ID.

For more information about dynamic value mappings, see the `dynamic-value-mappings` subcommand.

## Examples

Delete a dynamic value mapping by ID (prompts for confirmation):
```shell
otdfctl policy dynamic-value-mappings delete --id 3c51a593-cd4d-4b74-9f97-3b3b6b0a6f21
```

Delete without the interactive confirmation:
```shell
otdfctl policy dynamic-value-mappings delete --id 3c51a593-cd4d-4b74-9f97-3b3b6b0a6f21 --force
```
