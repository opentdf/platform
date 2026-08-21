# BinaryTDF-ALG: Algorithm and Extension Registries

| | |
|---|---|
| Document | BinaryTDF-ALG |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-SEC |
| Referenced by | BinaryTDF-MTD, BinaryTDF-REC, BinaryTDF-KAO, BinaryTDF-PAY, BinaryTDF-KAS, BinaryTDF-SCH, BinaryTDF-CORE, BinaryTDF extensions |

## 1. Content-encryption suites

| Symbol | Integer | Encoded bytes | Definition |
|---|---:|---|---|
| `UNSPECIFIED` | 0 | `00` | invalid |
| `AES_256_GCM_HKDF_SHA256` | 1 | `01` | baseline single-message suite |
| `AES_256_GCM_HKDF_SHA256_STREAM` | 2 | `02` | streaming suite defined by BinaryTDF-STREAM |
| `AES_256_GCM_HKDF_SHA256_STREAM_PART` | 3 | `03` | partitioned streaming suite defined by BinaryTDF-STREAM |

Suite 1 is mandatory. Suites 2 and 3 are optional and independent of each other. A
suite defines the complete payload construction inside the opaque Ciphertext section.
Registering a suite does not change the frame or object-key recovery.

## 2. Recovery schemes

| Symbol | Integer | Encoded bytes | Definition |
|---|---:|---|---|
| `UNSPECIFIED` | 0 | `00` | invalid |
| `DIRECT` | 1 | `01` | direct object-key release |
| `XOR_ALL` | 2 | `02` | all required shares XOR to the object key |
| `KEY_EPOCH` | 3 | `03` | separately defined epoch derivation |
| `PRIVATE_USE` | 24–255 | `18 18`–`18 ff` | explicit profile |

BinaryTDF-REC defines registry semantics and the recovery-scheme contract.

## 3. KAO wrap suites

| Symbol | Integer | Recipient key | Encapsulation |
|---|---:|---|---|
| `UNSPECIFIED` | 0 | — | invalid |
| `ECDH_P256_HKDF_SHA256_AES_256_GCM` | 1 | NIST P-256 | 33-byte compressed SEC 1 point |
| `ECDH_P384_HKDF_SHA256_AES_256_GCM` | 2 | NIST P-384 | 49-byte compressed SEC 1 point |
| `ECDH_P521_HKDF_SHA256_AES_256_GCM` | 3 | NIST P-521 | 67-byte compressed SEC 1 point |
| `ML_KEM_768_HKDF_SHA256_AES_256_GCM` | 4 | 1184-byte ML-KEM-768 key | 1088-byte ML-KEM ciphertext |
| `ML_KEM_1024_HKDF_SHA256_AES_256_GCM` | 5 | 1568-byte ML-KEM-1024 key | 1568-byte ML-KEM ciphertext |

Every frame version 2 implementation MUST support suite 1. An implementation claiming
post-quantum KAO wrapping MUST support suite 4; suite 5 is optional.

Hybrid suites may be registered without a frame change, but each assignment MUST fully
define component order, encodings, combiner, domain separation, and failure behavior.

## 4. Policy binding

| Symbol | Integer | Encoded bytes |
|---|---:|---|
| `UNSPECIFIED` | 0 | `00` |
| `HMAC_SHA256` | 1 | `01` |

HMAC-SHA256 is the only registered policy-binding algorithm.

## 5. Registry requirements

A suite, scheme, or extension specification MUST define, as applicable:

- its identifier and encoded bytes or registered CBOR tag;
- algorithms, parameter sets, key sizes, output sizes, and encodings;
- KDF inputs, domain-separation strings, and associated data;
- for a content-encryption suite, the maximum plaintext one key protects and the
  maximum plaintext one AEAD invocation protects, within the bounds of BinaryTDF-SEC
  Section 3;
- producer, opener, and authority validation;
- malformed-input and cryptographic-failure behavior;
- whether the capability is normally critical; and
- security and downgrade considerations with cross-language vectors.

Recovery schemes additionally MUST define their recovery-data CDDL plug, KAO path
shape, key-material generation and size, object-key production, group satisfaction,
reconstruction, policy binding, partial success, and malicious contribution handling.
Stateful schemes also MUST define identity, lifetime, replay, cache, and resolution
rules.

Metadata extensions additionally MUST define their CDDL plug and any explicit mapping
to Canonical Policy. Metadata never becomes authorization policy merely by being
present. A mapping MUST be deterministic and published as its own specification or
profile.

For BinaryTDF-owned unsigned-integer registries, identifiers 1 through 23 are reserved
for compact, broadly deployed assignments. Identifier 0 is permanently invalid. Each
registry defines its remaining policy and Private Use range. Unassigned identifiers and
unconfigured Private Use values MUST be rejected.

An identifier or registered tag denotes one stable wire contract. Compatible revisions
retain it. Incompatible changes to schema, cryptographic behavior, validation, or
interpretation MUST use a new identifier or tag.

## 6. Capability handling

An object declares capabilities; it does not negotiate them. A receiver MUST reject an
unsupported suite, scheme, or critical extension as `UNSUPPORTED_CAPABILITY` and MUST
NOT fall back to another capability.
