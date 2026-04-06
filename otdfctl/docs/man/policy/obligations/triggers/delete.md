---
title: Delete an obligation trigger
command:
  name: delete
  flags:
    - name: id
      description: ID of the obligation trigger to delete
      required: true
    - name: force
      description: Force deletion without interactive confirmation
---

Delete an obligation trigger.

## Examples

Delete an obligation trigger by its ID:

```shell
otdfctl policy obligations triggers delete --id "79b798f2-50a4-4a6d-9c5d-0f0e3c8787e8"
```

Force the deletion of an obligation trigger:

```shell
otdfctl policy obligations triggers delete --id "79b798f2-50a4-4a6d-9c5d-0f0e3c8787e8" --force
```
