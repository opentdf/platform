---
title: Get Key
command:
  name: get
  aliases:
    - g
  flags:
    - name: key
      shorthand: k
      description: The KeyID (human-readable identifier) or the internal UUID of the key to retrieve from the specified KAS. The system will attempt to resolve the provided value as either a UUID or a KeyID.
      required: true
    - name: kas
      description: Specify the Key Access Server (KAS) where the key (identified by `--key`) is registered. The KAS can be identified by its ID, URI, or Name.
      required: true
    
---

This command retrieves detailed information about a specific key registered within a Key Access Server (KAS). You must specify the key using its KeyID or UUID and the KAS it belongs to.

## Examples

Retrieve details for a key identified by its UUID from a KAS specified by its URI:
```
otdfctl policy kas-registry key get --key "123e4567-e89b-12d3-a456-426614174000" --kas "https://kas.example.com/kas"
```

Retrieve details for a key identified by its human-readable KeyID from a KAS specified by its name, and output in JSON format:
```
otdfctl policy kas-registry key get --key "my-specific-key-v2" --kas "Secondary KAS" --json
```
