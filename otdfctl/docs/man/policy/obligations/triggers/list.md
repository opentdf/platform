---
title: List obligation triggers
command:
  name: list
  aliases:
    - l
  flags:
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: namespace
      shorthand: n
      description: Namespace ID or FQN by which to filter results
---

List obligation triggers (optionally by namespace).

## Example

```shell
otdfctl policy obligations triggers list --limit 10 --offset 0
```

```shell
otdfctl policy obligations triggers list --limit 10 --offset 0 --namespace "https://example.com"
```
