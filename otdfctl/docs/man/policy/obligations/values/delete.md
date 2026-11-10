---
title: Delete an obligation value
command:
  name: delete
  flags:
    - name: id
      shorthand: i
      description: ID of the obligation value
    - name: fqn
      shorthand: f
      description: FQN of the obligation value
    - name: force
      description: Force deletion without interactive confirmation
---

Removes an obligation value from platform Policy.

For more information about obligation values, see the manual for the `values` subcommand.

## Example 

Delete by ID:

```shell
otdfctl policy obligations values delete --id 217b300a-47f9-4bee-be8c-d38c880053f7
```

Delete by FQN:

```shell
otdfctl policy obligations values delete --fqn "https://namespace.com/obl/name/drm/value/expiration"
```