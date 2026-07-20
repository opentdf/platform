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
