# BinaryTDF-MIG: Go Prototype Migration

| | |
|---|---|
| Document | BinaryTDF-MIG |
| Guide version | 0.1 |
| Source draft | 0.2 |
| Target frame version | 2 |
| Status | Non-normative |
| Depends on | BinaryTDF-CORE |

This guide applies to the original Go SDK frame version 1 prototype. It does not define
interoperability or change normative requirements.

## 1. Migration boundary

Frame versions 1 and 2 are intentionally incompatible. The Go SDK was the only known
frame version 1 implementation and prototype use was internal. Frame version 2 therefore
establishes a long-term model rather than preserving prototype wire compatibility.

A version 1 object cannot be converted in place. Decrypt and write a new version 2
object, or retain a separate read-only version 1 decoder.

## 2. Changes

| Prototype version 1 | Frame version 2 | Reason |
|---|---|---|
| loose AEAD and KDF `crypto_suite` | complete `content_encryption_suite` | prevents invalid combinations |
| `wrap_algorithm` | `wrap_suite` | suites fix KEM/ECDH, KDF, AEAD, sizes, encodings |
| `ephemeral_public_key` | `encapsulation` | supports ECDH keys and ML-KEM ciphertexts |
| opaque `wrap_params` | removed | parameters belong to registered suites |
| `split_id` and reserved SPLIT | XOR_ALL with explicit groups | defines AND/OR reconstruction structurally |
| unknown metadata core keys accepted | closed core and tagged extensions | separates compatibility from ambiguous semantics |
| empty and absent public policies | absent policy only | one deterministic encoding |
| KAS URL as locator | stable `authority_id` resolved by configuration | separates identity from routing |
| empty AAD for key and session wrap | context CBOR as AAD | binds object, path, and session |
| ECDH-specific rewrap | suite-neutral recipient and encapsulation | supports ML-KEM and future suites |
| core private assertion identifiers | claims use metadata extensions | claim formats own validation |

## 3. Options

1. Re-encrypt: open with the prototype decoder and create a new frame version 2 object
   from plaintext and current policy.
2. Retain a read-only version 1 decoder with explicit isolated dispatch until objects
   migrate or expire.

Do not interpret version 1 bytes with version 2 schemas, silently upgrade during parse,
or emit new version 1 objects.
