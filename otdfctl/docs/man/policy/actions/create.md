---
title: Create a Custom Action
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: name
      shorthand: n
      description: Name of the custom action (must be unique within Policy)
      required: true
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Add a custom `action` to the platform Policy.

An Action `name` is normalized to lower case and may contain underscores (`_`) or hyphens (`-`)
between other alphanumeric characters. Each name must be globally unique as actions are not
namespaced.

For more information, see the `actions` subcommand.

## Examples

Create a custom action named 'install_package': 

```shell
otdfctl policy actions create --name install_package
```

