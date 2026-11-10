---
title: Assign a KAS key to an attribute namespace
command:
  name: assign
  flags:
    - name: namespace
      shorthand: n
      description: Can be URI or ID of namespace
      required: true
    - name: key-id
      shorthand: k
      description: ID of the KAS key to assign
      required: true
---

Assigns a KAS key to a policy attribute namespace. This enables the attribute namespace to be used with the specified KAS key for encryption and decryption operations.

## Example

```shell
otdfctl policy attributes namespaces assign --namespace 3d25d33e-2469-4990-a9ed-fdd13ce74436 --key-id 8f7e6d5c-4b3a-2d1e-9f8d-7c6b5a432f1d
```

```shell
otdfctl policy attributes namespaces remove --namespace "https://example.com" --key-id 8f7e6d5c-4b3a-2d1e-9f8d-7c6b5a432f1d
```
