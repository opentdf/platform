---
title: Delete a Provider Config
command:
  name: delete
  aliases:
    - d
    - remove
  flags:
    - name: force
      shorthand: f
      description: Force the deletion of a provider configuration without confirmation
    - name: id
      shorthand: i
      description: ID of the provider config to delete
      required: true
---

Deletes a provider config by its unique ID.

## Examples

```shell
otdfctl keymanagement provider delete --id <provider-config-id>
```

```shell
otdfctl keymanagement provider delete --id '04ba179c-2f77-4e0d-90c5-fe4d1c9aa3f7'
```

```shell
otdfctl keymanagement provider delete --id '04ba179c-2f77-4e0d-90c5-fe4d1c9aa3f7' --force
```
