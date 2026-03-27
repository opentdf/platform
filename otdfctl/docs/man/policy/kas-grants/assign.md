---
title: (Deprecated) Assign a grant

command:
  name: assign
  aliases:
    - u
    - update
    - create
    - add
    - new
    - upsert
  description: Assign a grant of a KAS to an Attribute Definition or Value
  flags:
    - name: namespace-id
      shorthand: n
      description: The ID of the Namespace being assigned a KAS Grant
    - name: attribute-id
      shorthand: a
      description: The ID of the Attribute Definition being assigned a KAS Grant
      required: true
    - name: value-id
      shorthand: v
      description: The ID of the Value being assigned a KAS Grant
      required: true
    - name: kas-id
      shorthand: k
      description: The ID of the Key Access Server being assigned to the grant
      required: true
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

# Deprecated\n\nThis command is deprecated. Use `policy attributes namespace key assign`, `policy attributes key assign`, or `policy attributes value key assign` instead.

Assign a registered Key Access Server (KAS) to an attribute namespace, definition, or value.

For more information, see `kas-registry` and `kas-grants` manuals.

## Example

Namespace grant:
```shell
otdfctl policy kas-grants assign --namespace-id 3d25d33e-2469-4990-a9ed-fdd13ce74436 --kas-id 62857b55-560c-4b67-96e3-33e4670ecb3b
```

Attribute grant:
```shell
otdfctl policy kas-grants assign --attribute-id a21eb299-3a7d-4035-8a39-c8662c03cb15 --kas-id 62857b55-560c-4b67-96e3-33e4670ecb3b
```

Attribute value grant:
```shell
otdfctl policy kas-grants assign --value-id 0a40b27c-6cc9-49e8-a6ae-663cac2c324b --kas-id 62857b55-560c-4b67-96e3-33e4670ecb3b
```
