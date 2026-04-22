---
title: (Deprecated) List KAS Grants

command:
  name: list
  aliases:
    - l
  description: List the Grants of KASes to Attribute Namespaces, Definitions, and Values
  flags:
    - name: kas
      shorthand: k
      description: The optional ID or URI of a KAS to filter the list
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
---
# Deprecated\n\nThis command is deprecated and will be removed in a future release.

List the Grants of Registered Key Access Servers (KASes) to attribute namespaces, definitions,
or values.

Omitting `kas` lists all grants known to platform policy, otherwise results are filtered to
the KAS URI or ID specified by the flag value.

For more information, see `kas-registry` and `kas-grants` manuals.

## Example

```shell
otdfctl policy kas-grants list
```
