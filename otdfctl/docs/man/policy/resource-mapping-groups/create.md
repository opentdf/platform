---
title: Create a resource mapping group
command:
  name: create
  aliases:
    - add
    - new
    - c
  flags:
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
---

Create a new group to organize resource mappings. Resource mapping groups belong to a namespace and are identified by a name.

For more information about resource mapping groups, see the `resource-mapping-groups` subcommand.

## Examples

```shell
otdfctl policy resource-mapping-groups create --namespace-id 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --name my-group
```
