---
title: Create an obligation definition
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: name
      shorthand: n
      description: Name of the obligation (must be unique within a Namespace)
      required: true
    - name: namespace
      shorthand: s
      description: Namespace ID or FQN
      required: true
    - name: value
      shorthand: v
      description: Value of the obligation (i.e. 'value1', must be unique within the Obligation)
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Add an obligation definition to the platform Policy.

For more information, see the `obligations` subcommand.

## Examples

Create an obligation definition named 'my_obligation' with value 'my_value':

```shell
otdfctl policy obligations create --name my_obligation --value my_value
```
