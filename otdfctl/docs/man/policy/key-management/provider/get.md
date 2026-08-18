---
title: Get a Provider Config
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the provider config to retrieve
    - name: name
      shorthand: n
      description: Name of the provider config to retrieve
    - name: manager
      shorthand: m
      description: Registered key manager implementation name tied to the provider config
---

Retrieves a provider config by its ID or by name and manager.

The `manager` value comes from the key manager implementation name, such as [`BasicManagerName`](https://github.com/opentdf/platform/blob/54d5c78bdf7a868e00ee83308a4593c86d1d4095/service/internal/security/basic_manager.go#L22). The `name` is the provider config name from `provider create` or `provider list`.

## Examples

```shell
otdfctl keymanagement provider get --id '04ba179c-2f77-4e0d-90c5-fe4d1c9aa3f7'
```

```shell
otdfctl keymanagement provider get --name 'aws-dev' --manager 'opentdf.io/aws'
```
