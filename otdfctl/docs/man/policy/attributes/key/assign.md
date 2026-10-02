---
title: Assign a KAS key to an attribute definition
command:
  name: assign
  flags:
    - name: attribute
      shorthand: a
      description: URI or ID of the attribute definition
      required: true
    - name: key-id
      shorthand: k
      description: ID of the KAS key to assign
      required: true
---

Assigns a KAS key to a policy attribute. This enables the attribute to be used with the specified KAS key for encryption and decryption operations.

## Example

```shell
otdfctl policy attributes key assign --attribute 3d25d33e-2469-4990-a9ed-fdd13ce74436 --key-id 8f7e6d5c-4b3a-2d1e-9f8d-7c6b5a432f1d
```

```shell
otdfctl policy attributes key assign --attribute "https://example.com/attr/example" --key-id 8f7e6d5c-4b3a-2d1e-9f8d-7c6b5a432f1d
```
