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
---

Retrieves a provider config by its ID or name.

## Examples

```shell
otdfctl keymanagement provider get --id '04ba179c-2f77-4e0d-90c5-fe4d1c9aa3f7'
```
