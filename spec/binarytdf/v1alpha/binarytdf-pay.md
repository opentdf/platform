# BinaryTDF-PAY: Payload Protection

| | |
|---|---|
| Document | BinaryTDF-PAY |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-CORE, BinaryTDF-MTD, BinaryTDF-REC, BinaryTDF-ALG |
| Referenced by | BinaryTDF-CDDL, BinaryTDF-EX, BinaryTDF-STREAM, BinaryTDF-KEY-EPOCH |

## 1. Suites

| Symbol | Integer | Definition |
|---|---:|---|
| `AES_256_GCM_HKDF_SHA256` | 1 | 32-byte object key, HKDF-SHA256, AES-256-GCM, 12-byte nonce, 16-byte tag |
| `AES_256_GCM_HKDF_SHA256_STREAM` | 2 | Optional segmented construction defined by BinaryTDF-STREAM |

Every frame version 2 implementation MUST support suite 1. Unsupported suites are
rejected as `UNSUPPORTED_CAPABILITY`; there is no fallback.

Each object has a unique 32-byte object key. DIRECT and XOR_ALL generate it uniformly
at random. A derivation scheme defines byte-exact inputs producing a distinct key for
each object. Object keys MUST NOT be reused or serialized directly.

## 2. Baseline key derivation

For suite 1:

```text
payload_key = HKDF-SHA256(
  ikm  = object_key,
  salt = UTF8("binary-tdf:v2:hkdf-salt"),
  info = UTF8("binary-tdf:v2:payload-key"),
  len  = 32
)
```

## 3. Associated data

```text
payload_aad =
  version_byte ||
  uint32_be(len(metadata_bytes)) || metadata_bytes ||
  uint32_be(len(object_key_recovery_bytes)) || object_key_recovery_bytes
```

Implementations MUST use original section bytes. Parsed structures MUST NOT be
re-encoded to create AAD.

## 4. Baseline encryption

Suite 1 encrypts the payload with AES-256-GCM and a fresh random 12-byte nonce:

```text
payload_nonce || encrypted_payload || authentication_tag
```

No plaintext may be released until authentication succeeds. The streaming suite may
refine this rule only as defined by its registered specification.

## 5. Security requirements

AES-GCM nonce reuse under one key is catastrophic. Producers MUST use a cryptographically
secure random source for object keys, shares, identifiers, and random nonces. Derived
schemes MUST guarantee distinct object-key inputs.
