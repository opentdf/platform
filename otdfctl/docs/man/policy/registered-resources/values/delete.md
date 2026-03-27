---
title: Delete a Registered Resource Value
command:
  name: delete
  flags:
    - name: id
      shorthand: i
      description: ID of the registered resource value
      required: true
    - name: force
      description: Force deletion without interactive confirmation
---

Removes a Registered Resource Value from platform Policy.

Registered resource value deletion cascades to the associated Action Attribute Values.

For more information about Registered Resource Values, see the manual for the `values` subcommand.

## Example 

```shell
otdfctl policy registered-resources values delete --id 217b300a-47f9-4bee-be8c-d38c880053f7
```
