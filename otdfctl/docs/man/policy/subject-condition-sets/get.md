---
title: Get a Subject Condition Set

command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      description: The ID of the subject condition set to get
      shorthand: i
      required: true
---

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Example

```shell
otdfctl policy subject-condition-sets get --id=bfade235-509a-4a6f-886a-812005c01db5
```
