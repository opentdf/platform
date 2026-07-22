---
title: Unsafely update a key
command:
  name: update
  flags:
    - name: id
      shorthand: i
      description: System-given ID of the key to update.
      required: true
    - name: mode
      shorthand: m
      description: Target key mode. Only "remote" and "public_key" are supported.
    - name: provider-config-id
      shorthand: p
      description: Configuration ID for the key provider. Required when changing to "remote" mode, or when updating only the provider configuration for an existing remote key.
---

# Unsafe Update Warning

Updating a key in place is a dangerous support operation. It can retroactively change decryptability for existing TDFs.

This command is limited to switching a key between `remote` and `public_key` modes, or updating the provider configuration
for an existing `remote` key. The key ID, KAS URI, and public key are preserved.

Make sure you know what you are doing.

## Examples

Change a key of mode `public_key` key to one of mode `remote`:

```shell
otdfctl policy kas-registry key unsafe update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --mode remote --provider-config-id 298c9446-ef71-49eb-a6ef-960149095a76
```

Change a `remote` key to `public_key` mode:

```shell
otdfctl policy kas-registry key unsafe update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --mode public_key
```

Update only the provider configuration for an existing remote key:

```shell
otdfctl policy kas-registry key unsafe update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --provider-config-id 298c9446-ef71-49eb-a6ef-960149095a76
```
