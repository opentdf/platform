---
title: Update a dynamic value mapping
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      description: The ID of the dynamic value mapping to update
      shorthand: i
      required: true
    - name: selector
      description: Replacement selector for a field on the flattened Entity Representation (requires --operator)
      shorthand: s
    - name: operator
      description: Replacement comparison operator (requires --selector)
      shorthand: o
      enum:
        - IN
        - IN_CONTAINS
    - name: action
      description: Each 'id' or 'name' of an Action to be entitled (i.e. 'create', 'read', 'update', 'delete')
    - name: subject-condition-set-id
      description: Replacement static pre-gate Subject Condition Set Id
      required: false
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

Update a Dynamic Value Mapping.

`Actions` are updated in place, destructively replacing the current set. If you want to add or remove
actions, provide the full set of actions on update.

To replace the dynamic value resolver, provide both `--selector` and `--operator` together. Omit both
to leave the resolver unchanged.

For more information about dynamic value mappings, see the `dynamic-value-mappings` subcommand.

## Example

```shell
otdfctl policy dynamic-value-mappings update --id 39866dd2-368b-41f6-b292-b4b68c01888b --action read
```
