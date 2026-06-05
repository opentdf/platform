---
title: List Provider Configs
command:
  name: list
  aliases:
    - l
  flags:
    - name: limit
      shorthand: l
      description: Maximum number of results to return
      required: true
    - name: offset
      shorthand: o
      description: Offset for pagination
      required: true
---

Lists all provider configs with pagination support.

## Examples

```shell
otdfctl keymanagement provider list --limit 10 --offset 0
```
