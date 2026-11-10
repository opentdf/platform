---
title: Create a Registered Resource
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: name
      shorthand: n
      description: Name of the registered resource (must be unique within Policy)
      required: true
    - name: value
      shorthand: v
      description: Value of the registered resource (i.e. 'value1', must be unique within the Registered Resource)
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Add a registered resource to the platform Policy.

A registered resource `name` is normalized to lower case and may contain hyphens or dashes between other alphanumeric characters.

For more information, see the `registered-resources` subcommand.

## Examples

Create a registered resource named 'my_resource' with value 'my_value':

```shell
otdfctl policy registered-resources create --name my_resource --value my_value
```
