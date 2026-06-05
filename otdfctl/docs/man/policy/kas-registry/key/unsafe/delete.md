---
title: Delete a key
command:
  name: delete
  flags:
    - name: id
      shorthand: i
      description: Sytem given ID of the key
      required: true
    - name: kas-uri
      description: The URI of the KAS instance
      required: true
    - name: key-id
      description: The ID of the key assigned by the admin
      required: true
---

# Unsafe Delete Warning

Deleting a key is a destructive operation. Any existing TDFs encrypted with this key will be rendered inaccessible.

Make sure you know what you are doing.

## Example

```shell
otdfctl policy kas-keys unsafe delete --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --kas-uri https://kas.example.com --key-id "key-1"
```
