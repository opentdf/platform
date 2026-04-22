---
title: Create an attribute value
command:
  name: create
  aliases:
    - new
    - add
    - c
  flags:
    - name: attribute-id
      shorthand: a
      description: The ID of the attribute to create a value for
    - name: value
      shorthand: v
      description: The value to create
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Add a single new value underneath an existing attribute.

An attribute `value` is normalized to lower case and may contain hyphens and underscores
between other alphanumeric characters.

For a hierarchical attribute, a new value is added in lowest hierarchy (last).

For more information on attribute values, see the `values` subcommand.

## Example

```shell
otdfctl policy attributes values create --attribute-id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value myvalue1
```
