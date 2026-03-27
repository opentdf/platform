---
title: Create an attribute namespace
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: name
      shorthand: n
      description: Name of the attribute namespace (must be unique within Policy)
      required: true
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Creation of a `namespace` is required to add attributes or any other policy objects beneath.

A namespace `name` is normalized to lower case, may contain hyphens and underscores between other alphanumeric characters, and it
must contain two segments separated by a `.`, such as `example.com`.

For more information, see the `namespaces` subcommand.

## Example

```shell
otdfctl policy attributes namespaces create --name opentdf.io
```
