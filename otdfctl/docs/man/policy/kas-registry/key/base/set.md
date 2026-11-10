---
title: Set Base Key
command:
  name: set
  aliases:
    - s
  flags:
    - name: key
      shorthand: k
      description: The KeyID (human-readable identifier) or the internal UUID of an existing key within the specified KAS. This key will be designated as the platform base key. The system will attempt to resolve the provided value as either a UUID or a KeyID.
      required: true
    - name: kas
      description: Specify the Key Access Server (KAS) where the key (identified by `--key`) is registered. The KAS can be identified by its ID, URI, or Name.    
---

Command for setting a base key to be used for encryption operations on data where no attributes are present or where no keys are present on found attributes. The key to be set as the base key must be identified using its KeyID or UUID via the `--key` flag, and the KAS it belongs to must be specified with the `--kas` flag.

## Examples

Set the platform base key using the internal UUID of a key from a KAS specified by its URI:
```
otdfctl policy kas-registry key base set --key 8af2059f-5d0b-46c2-84f0-bed8a6101d90 --kas https://kas.example.com/kas

otdfctl policy kas-registry key base set --key my-platform-base-key-v1 --kas primary-key-access-server
```
