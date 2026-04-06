---
title: Import Key
command:
  name: import
  aliases:
    - i
  flags:
    - name: key-id
      description: A unique, often human-readable, identifier for the key being imported.
      required: true
    - name: algorithm
      shorthand: a
      description: Algorithm for the key being imported (see table below for options).
      required: true
    - name: kas
      description: Specify the Key Access Server (KAS) where the key will be imported. The KAS can be identified by its ID, URI, or Name.
      required: true
    - name: wrapping-key-id
      description: Identifier related to the wrapping key.
      required: true
    - name: wrapping-key
      shorthand: w
      description: The symmetric key material (AES cipher, hex encoded) used to wrap the imported private key.
      required: true
    - name: private-key-pem
      description: The base64 encoded private key PEM to import
      required: true
    - name: public-key-pem
      shorthand: e
      description: The base64 encoded public key PEM to import
      required: true
    - name: legacy
      description: Mark the imported key as a legacy key.
      default: false
    - name: label
      shorthand: l
      description: Comma-separated key=value pairs for metadata labels to associate with the imported key (e.g., "owner=team-a,env=production").
---

Imports an existing cryptographic key into a specified Key Access Server (KAS).

>[!IMPORTANT]
>Use this command when migrating keys from KAS over to the platform.
>All keys created with import will be of key_mode=**KEY_MODE_CONFIG_ROOT_KEY**

## Examples

### Import a key

```shell
otdfctl policy kas-registry key import --key-id "imported-key" --algorithm "rsa:2048" \
  --kas 891cfe85-b381-4f85-9699-5f7dbfe2a9ab \
  --wrapping-key-id "my-wrapping-key" \
  --wrapping-key "a8c4824daafcfa38ed0d13002e92b08720e6c4fcee67d52e954c1a6e045907d1" \
  --public-key-pem <base64 encoded public key pem> \
  --private-key-pem <base64 encoded private key pem> \
```

### Import a legacy key

```shell
otdfctl policy kas-registry key import --key-id "imported-key" --algorithm "rsa:2048" \
  --kas 891cfe85-b381-4f85-9699-5f7dbfe2a9ab \
  --wrapping-key-id "my-wrapping-key" \
  --wrapping-key "a8c4824daafcfa38ed0d13002e92b08720e6c4fcee67d52e954c1a6e045907d1" \
  --public-key-pem <base64 encoded public key pem> \
  --private-key-pem <base64 encoded private key pem> \
  --legacy true
```

1. The `algorithm` specifies the key algorithm:

    | Key Algorithm  |
    | -------------- |
    | `rsa:2048`     |
    | `rsa:4096`     |
    | `ec:secp256r1` |
    | `ec:secp384r1` |
    | `ec:secp521r1` |
