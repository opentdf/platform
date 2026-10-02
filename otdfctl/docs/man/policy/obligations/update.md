---
title: Update an obligation definition
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: ID of the obligation to update
      required: true
    - name: name
      shorthand: n
      description: Optional updated name of the obligation (must be unique within the Namespace)
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

Update the `name` and/or metadata labels for an obligation definition.

If PEPs rely on this obligation name, a name update could break access.

Make sure you know what you are doing.

For more information about obligations, see the `obligations` subcommand.

## Example

```shell
otdfctl policy obligations update --id 34c62145-5d99-45cb-a732-13cb16270e63 --name new_obligation_name
```
