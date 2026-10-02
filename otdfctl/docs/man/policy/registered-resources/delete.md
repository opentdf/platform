---
title: Delete a Registered Resource
command:
  name: delete
  flags:
    - name: id
      shorthand: i
      description: ID of the registered resource
      required: true
    - name: force
      description: Force deletion without interactive confirmation
---

Removes a Registered Resource from platform Policy.

Registered resource deletion cascades to the associated Registered Resource Values and Action Attribute Values.

For more information about Registered Resources, see the manual for the `registered-resources` subcommand.

## Example 

```shell
otdfctl policy registered-resources delete --id 217b300a-47f9-4bee-be8c-d38c880053f7
```
