---
title: Update a Custom Action
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: ID of the action to update
      required: true
    - name: name
      shorthand: n
      description: Optional updated name of the custom action (must be unique within Policy)
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

Update the `name` and/or metadata labels for a Custom Action.

If PEPs rely on this action name, a name update could break access.

Make sure you know what you are doing.

For more information about Actions, see the manual for the `actions` subcommand.

## Example 

```shell
otdfctl policy actions update --id 34c62145-5d99-45cb-a732-13cb16270e63 --name new_action_name
```
