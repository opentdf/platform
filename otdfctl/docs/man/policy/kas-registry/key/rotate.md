---
title: Rotate Key
command:
  name: rotate
  aliases:
    - r
  flags:
    # Flags for identifying the old key (from get.md)
    - name: key
      shorthand: k
      description: The KeyID (human-readable identifier) or the internal UUID of the existing key to rotate from the specified KAS. The system will attempt to resolve the provided value as either a UUID or a KeyID.
      required: true
    - name: kas
      description: Specify the Key Access Server (KAS) where the key is registered. The KAS can be identified by its ID, URI, or Name.
      required: true
    
    # Flags for the new key creation (from create.md)
    - name: key-id
      description: A unique, often human-readable, identifier for the new key to be created.
      required: true
    - name: algorithm
      shorthand: a
      description: Algorithm for the new key (see table below for options).
      required: true
    - name: mode
      shorthand: m
      description: Describes how the private key is managed (see table below for options).
      required: true
    - name: wrapping-key-id
      description: Identifier related to the wrapping key. Its meaning depends on the `mode`. For `local` mode, it's a descriptive ID for the `wrappingKey` you provide. For `provider` or `remote` mode, it's the ID of the key within the external provider/system used for wrapping.
    - name: wrapping-key
      shorthand: w
      description: The symmetric key material (AES cipher, base64 encoded) used to wrap the generated private key. Primarily used when `mode` is `local`.
    - name: private-key-pem
      description: The private key PEM (encrypted by an AES 32-byte key, then base64 encoded). Used when importing an existing key pair, typically with `provider` mode.
    - name: provider-config-id
      shorthand: p
      description: Configuration ID for the key provider. Often required when `mode` is `provider` or `remote` and an external key provider is used.
    - name: public-key-pem
      shorthand: e
      description: The base64 encoded public key PEM. Required for `remote` and `public_key` modes, and can be used with `provider` mode if importing an existing key pair.
    - name: label
      shorthand: l
      description: Comma-separated key=value pairs for metadata labels to associate with the new key (e.g., "owner=team-a,env=production").
---

Rotates a cryptographic key within a specified Key Access Server (KAS).
This command replaces an existing key with a new one while maintaining references to the old key to ensure data encrypted with the old key can still be decrypted.

## Examples

### Rotate a key in `local` mode

Rotate an existing key to a new key in local mode, where the KAS generates the key pair and the private key is wrapped by the provided `wrappingKey`:

```shell
otdfctl policy kas-registry key rotate --key "old-key-id" --kas "https://kas.example.com/kas" --key-id "new-key-v2" --algorithm "rsa:2048" --mode "local" --wrapping-key-id "virtru-stored-key" --wrapping-key "YWVzIGtleQ=="
```

### Rotate a key in `provider` mode

```shell
otdfctl policy kas-registry key rotate --key "123e4567-e89b-12d3-a456-426614174000" --kas "https://kas.example.com/kas" --key-id "provider-key-v2" --algorithm "rsa:2048" --mode "provider" --public-key-pem "LS0tLS1CRUdJTi..." --private-key-pem "LS0tLS1CRUdJTi..." --wrapping-key-id "openbao-key" --provider-config-id "f86b166a-98a5-407a-939f-ef84916ce1e5"
```

### Rotate a key in `remote` mode

```shell
otdfctl policy kas-registry key rotate --key "my-remote-key" --kas "Secondary KAS" --key-id "remote-key-v2" --algorithm "rsa:2048" --mode "remote" --wrapping-key-id "openbao-key" --provider-config-id "f86b166a-98a5-407a-939f-ef84916ce1e5" --public-key-pem "LS0tLS1CRUdJTi..."
```

### Rotate a key in `public_key` mode

```shell
otdfctl policy kas-registry key rotate --key "public-key-old" --kas "Secondary KAS" --key-id "public-key-v2" --algorithm "rsa:2048" --mode "public_key" --public-key-pem "LS0tLS1CRUdJTi..."
```

## Key Algorithms and Modes

1. The `"algorithm"` specifies the key algorithm:

    | Key Algorithm  |
    | -------------- |
    | `rsa:2048`     |
    | `rsa:4096`     |
    | `ec:secp256r1` |
    | `ec:secp384r1` |
    | `ec:secp521r1` |

2. The `"mode"` specifies where the key that is encrypting TDFs is stored. All keys will be encrypted when stored in Virtru's DB, for modes `"local"` and `"provider"`

    | Mode         | Description                                                                                             |
    | ------------ | ------------------------------------------------------------------------------------------------------- |
    | `local`      | Root Key is stored within Virtru's database and the symmetric wrapping key is stored in KAS             |
    | `provider`   | Root Key is stored within Virtru's database and the symmetric wrapping key is stored externally         |
    | `remote`     | Root Key and wrapping key are stored remotely                                                           |
    | `public_key` | Root Key and wrapping key are stored remotely. Use this when importing another org's policy information |
