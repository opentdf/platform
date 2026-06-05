---
title: Get a subject mapping
command:
  name: get
  aliases:
    - g
  flags:
    - name: id
      description: The ID of the subject mapping to get
      shorthand: i
      required: true
      default: ''
---

Retrieve the specifics of a Subject Mapping.

For more information about subject mappings, see the `subject-mappings` subcommand.

```shell
otdfctl policy subject-mappings get --id 39866dd2-368b-41f6-b292-b4b68c01888b
```
