---
title: Remove a KAS key from an attribute value
command:
  name: remove
  flags:
    - name: value
      shorthand: v
      description: URI or ID of attribute value
      required: true
    - name: key-id
      shorthand: k
      description: ID of the KAS key to remove
      required: true
---

Removes a KAS key from a policy attribute value. After removing the key, the attribute value can no longer be used with the specified KAS key for encryption and decryption operations.

## Example

```shell
otdfctl policy attributes values remove --value 3d25d33e-2469-4990-a9ed-fdd13ce74436 --key-id 8f7e6d5c-4b3a-2d1e-9f8d-7c6b5a432f1d
```

```shell
otdfctl policy attributes values remove --value "https://example.com/attr/example/value/1" --key-id 8f7e6d5c-4b3a-2d1e-9f8d-7c6b5a432f1d
```
