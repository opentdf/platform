---
title: Update a Registered Resource
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: ID of the registered resource to update
      required: true
    - name: name
      shorthand: n
      description: Optional updated name of the registered resource (must be unique within Policy)
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

Update the `name` and/or metadata labels for a Registered Resource.

If PEPs rely on this registered resource name, a name update could break access.

Make sure you know what you are doing.

For more information about Registered Resources, see the `registered-resources` subcommand.

## Example

```shell
otdfctl policy registered-resources update --id 34c62145-5d99-45cb-a732-13cb16270e63 --name new_resource_name
```
