---
title: Delete a Subject Condition Set

command:
  name: delete
  flags:
    - name: id
      description: The ID of the subject condition set to delete
      shorthand: i
      required: true
    - name: force
      description: Force deletion without interactive confirmation (dangerous)
---

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Example

```shell
otdfctl policy subject-condition-sets delete --id=bfade235-509a-4a6f-886a-812005c01db5
```
