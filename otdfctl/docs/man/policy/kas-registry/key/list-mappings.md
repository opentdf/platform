---
title: List Key Mappings
command:
  name: list-mappings
  aliases:
    - m
  flags:
    - name: limit
      shorthand: l
      description: Maximum number of key mappings to return
      required: true
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
      required: true
    - name: id
      shorthand: i
      description: The system ID of the key for which to list mappings.
    - name: key-id
      description: The user-defined ID of the key for which to list mappings. Must be used with --kas.
    - name: kas
      description: Specify the Key Access Server (KAS) where the key (identified by `--key-id`) is registered. The KAS can be identified by its ID, URI, or Name.
---

This command lists key mappings. You can list all key mappings, or filter by a specific key.

To filter by a key, you can either provide the system ID of the key, or the user-defined key ID along with the KAS identifier.

The list is paginated, so you must provide `limit` and `offset` flags.

## Examples

List the first 10 key mappings:

```bash
otdfctl policy kas-registry key list-mappings --limit 10 --offset 0
```

List key mappings for a key with a specific system ID:

```bash
otdfctl policy kas-registry key list-mappings --id "cc8bf36a-8c76-4c8c-9723-3c0d1ce897b8" --limit 10 --offset 0
```

List key mappings for a key with a user-defined ID within a KAS specified by its URI:

```bash
otdfctl policy kas-registry key list-mappings --key-id "my-key" --kas "https://kas.example.com/kas" --limit 10 --offset 0
```
