---
title: Get a Registered Resource
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      shorthand: i
      description: ID of the registered resource
    - name: name
      shorthand: n
      description: Name of the registered resource
---

Retrieve a registered resource along with its metadata and values.

If both `id` and `name` flag values are provided, `id` is preferred.

For more information about Registered Resources, see the manual for the `registered-resources` subcommand.

## Example

Get by ID:

```shell
otdfctl policy registered-resources get --id=3c51a593-cbf8-419d-b7dc-b656d0bedfbb
```

Get by Name:

```shell
otdfctl policy registered-resources get --name=my_resource
```
