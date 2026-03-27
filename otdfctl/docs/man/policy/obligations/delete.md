---
title: Delete an obligation definition
command:
  name: delete
  flags:
    - name: id
      shorthand: i
      description: ID of the obligation
    - name: fqn
      shorthand: f
      description: FQN of the obligation
    - name: force
      description: Force deletion without interactive confirmation
---

Removes an obligation definition from platform Policy.

Obligation deletion cascades to the associated obligation values.

For more information about obligations, see the manual for the `obligations` subcommand.

## Example 

Delete by ID:

```shell
otdfctl policy obligations delete --id 217b300a-47f9-4bee-be8c-d38c880053f7
```

Delete by FQN:

```shell
otdfctl policy obligations delete --fqn "https://namespace.com/obl/name/drm"
```