---
title: List attribute definitions
command:
  name: list
  aliases:
    - l
  flags:
    - name: state
      shorthand: s
      description: Filter by state
      enum:
        - active
        - inactive
        - any
      default: active
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---

By default, the list will only provide `active` attributes if unspecified, but the filter can be controlled with the `--state` flag.

For more general information about attributes, see the `attributes` subcommand.

## Example

```shell
otdfctl policy attributes list
```
