---
title: List Key Access Server registrations
command:
  name: list
  aliases:
    - l
  flags:
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

For more information about registration of Key Access Servers, see the manual for `kas-registry`.

## Example

```shell
otdfctl policy kas-registry list
```
