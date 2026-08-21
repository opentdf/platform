# BinaryTDF-PAY: Payload Protection

| | |
|---|---|
| Document | BinaryTDF-PAY |
| Version | 1 Alpha |
| Source draft | 0.3 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-SEC, BinaryTDF-ALG, BinaryTDF-MTD, BinaryTDF-REC |
| Referenced by | BinaryTDF-CORE, BinaryTDF-EX, BinaryTDF-STREAM, BinaryTDF-KEY-EPOCH |

## 1. Suites

| Symbol | Integer | Definition |
|---|---:|---|
| `AES_256_GCM_HKDF_SHA256` | 1 | 32-byte object key, HKDF-SHA256, AES-256-GCM, 12-byte nonce, 16-byte tag |
| `AES_256_GCM_HKDF_SHA256_STREAM` | 2 | Optional segmented construction defined by BinaryTDF-STREAM |
| `AES_256_GCM_HKDF_SHA256_STREAM_PART` | 3 | Optional partitioned segmented construction defined by BinaryTDF-STREAM |

Every frame version 2 implementation MUST support suite 1. Unsupported suites are
rejected as `UNSUPPORTED_CAPABILITY`; there is no fallback.

Each object has a unique 32-byte object key. DIRECT and XOR_ALL generate it uniformly
at random. A derivation scheme defines byte-exact inputs producing a distinct key for
each object. Object keys MUST NOT be reused or serialized directly. The suite 1 payload
key is a deterministic function of the object key, so reuse places two objects under
one content-encryption key: protected volume accumulates against the Section 5 limit
and a 12-byte nonce may repeat under one key. Suites 2 and 3 mix in a fresh stream
salt, which separates their payload keys but does not relax this requirement.
BinaryTDF-SEC Section 3.5 quantifies both cases.

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

No plaintext may be released until authentication succeeds. The streaming suites may
refine this rule only as defined by their registered specification.

The complete payload is one AES-GCM invocation, so it is bounded by the NIST SP
800-38D Section 5.2.1.1 per-invocation limit. A suite 1 payload MUST NOT exceed
68719476704 plaintext bytes, that is 2^36 - 32 bytes, or 64 GiB - 32 bytes. With the
12-byte nonce and 16-byte tag, the corresponding Ciphertext Length is at most
68719476732 bytes. A producer MUST NOT emit a larger suite 1 object, and an opener
MUST reject one on the declared Ciphertext Length before decryption. The 8-byte
Ciphertext Length field of BinaryTDF-PKG frames far more than AES-GCM can protect in
one invocation; this requirement, not the frame, is the binding limit.

A payload larger than that limit MUST use a segmented suite or several objects with
independent object keys.

## 5. Confidentiality budget

BinaryTDF-SEC Section 3 limits one object's GCM confidentiality advantage by requiring
`sum(sigma_p^2) <= 2^70`, where `sigma_p` is the number of 16-byte plaintext blocks
encrypted under content-encryption key `K_p`. Each AES-GCM invocation contributes
`ceil(plaintext_length / 16)` blocks. The per-suite consequences are:

| Suite | Content-encryption key | Bound on one object |
|---:|---|---|
| 1 | payload key | 68719476704 bytes, from the stricter Section 4 invocation limit |
| 2 | payload key | at most 2^35 plaintext blocks, from BinaryTDF-STREAM Section 8.1 |
| 3 | partition key `K_p` | sum of squared partition block counts at most 2^70 |

Suite 1 cannot spend the complete confidentiality budget because its single-invocation
limit binds first. Suite 2 protects the complete object under one payload key, so the
block budget is its object ceiling. Suite 3 derives one key per partition and applies
the budget across all partitions, allowing 50 TiB plaintexts with approximately
1 GiB partitions while retaining the object-wide target.

## 6. Security requirements

AES-GCM nonce reuse under one key is catastrophic. Producers MUST use a cryptographically
secure random source for object keys, shares, identifiers, and random nonces. Derived
schemes MUST guarantee distinct object-key inputs.
