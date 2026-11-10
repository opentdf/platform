---
title: Get a registered Key Access Server
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the Key Access Server registration
      required: true
---

For more information about registration of Key Access Servers, see the manual for `kas-registry`.

## Example

```shell
otdfctl policy kas-registry get --id=62857b55-560c-4b67-96e3-33e4670ecb3b
```
