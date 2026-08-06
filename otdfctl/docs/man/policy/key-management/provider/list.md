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
    - name: offset
      shorthand: o
      description: Offset for pagination
---

Lists all provider configs with pagination support.

## Examples

```shell
otdfctl keymanagement provider list --limit 10 --offset 0
```
