---
title: Update Key Access Server Key
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: The internal UUID of the key to be updated.
      required: true
    - name: label
      shorthand: l
      description: Comma-separated key=value pairs for metadata labels (e.g., "owner=team-a,env=production"). Providing new labels will replace any existing labels on the key.
---

This command updates the key for an existing key registered in a Key Access Server (KAS).
You must identify the key using its UUID via the `--id` flag.
Currently, this command primarily supports updating the metadata labels associated with the key.

## Examples

Update key identified by its UUID:
```
otdfctl policy kas-registry key update --id "123e4567-e89b-12d3-a456-426614174000" --label "status=active,project=phoenix"
```
