---
title: Update a resource mapping group
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      description: The ID of the resource mapping group to update.
      default: ''
    - name: namespace-id
      description: The ID of the namespace of the group
      default: ''
    - name: name
      description: The name of the group
      default: ''
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

Alter the namespace associated with a group, or update the group's name.

For more information about resource mapping groups, see the `resource-mapping-groups` subcommand.

## Examples

```shell
otdfctl policy resource-mapping-groups update --id=3ff446fb-8fb1-4c04-8023-47592c90370c --name new-name
```
