---
title: (Deprecated) Unassign a grant

command:
  name: unassign
  aliases:
    - delete
    - remove
  description: Remove a grant assignment of a KAS to an Attribute Definition or Value
  flags:
    - name: namespace-id
      shorthand: n
      description: The ID of the Namespace being unassigned a KAS Grant
    - name: attribute-id
      shorthand: a
      description: The ID of the Attribute Definition being unassigned the KAS grant
      required: true
    - name: value-id
      shorthand: v
      description: The ID of the Value being unassigned the KAS Grant
      required: true
    - name: kas-id
      shorthand: k
      description: The Key Access Server (KAS) ID being unassigned a grant
      required: true
    - name: force
      description: Force the unassignment with no confirmation
---

# Deprecated\n\nThis command is deprecated and will be removed in a future release. Use `policy attributes namespace key remove`, `policy attributes key remove`, or `policy attributes value key remove` instead.

Unassign a registered Key Access Server (KAS) to an attribute namespace, definition, or value.

For more information, see `kas-registry` and `kas-grants` manuals.

## Example

Namespace grant:
```shell
otdfctl policy kas-grants unassign --namespace-id 3d25d33e-2469-4990-a9ed-fdd13ce74436 --kas-id 62857b55-560c-4b67-96e3-33e4670ecb3b
```

Attribute grant:
```shell
otdfctl policy kas-grants unassign --attribute-id a21eb299-3a7d-4035-8a39-c8662c03cb15 --kas-id 62857b55-560c-4b67-96e3-33e4670ecb3b
```

Attribute value grant:
```shell
otdfctl policy kas-grants unassign --value-id 0a40b27c-6cc9-49e8-a6ae-663cac2c324b --kas-id 62857b55-560c-4b67-96e3-33e4670ecb3b
```
