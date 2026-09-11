# BaseTDF-ALG: Algorithm Registry

| Field | Value |
|-------|-------|
| **Title** | Algorithm Registry |
| **Document** | BaseTDF-ALG |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Depends on** | BaseTDF-SEC |
| **Referenced by** | BaseTDF-KAO, BaseTDF-INT, BaseTDF-ASN, BaseTDF-CORE |

---

## 1. Introduction

### 1.1 Purpose

This document is the central registry of cryptographic algorithm identifiers for
the BaseTDF specification suite. Every cryptographic operation referenced by other
BaseTDF documents -- content encryption, key protection, integrity verification,
and assertion signing -- is defined here by a unique string identifier, its
parameters, and its implementation requirements.

By factoring algorithm definitions into a single registry, the suite achieves a
clean extensibility point: new algorithms (including post-quantum constructions)
can be introduced by adding entries to this document without modifying the
structural specifications (BaseTDF-KAO, BaseTDF-INT, BaseTDF-ASN, BaseTDF-CORE).

### 1.2 Scope

This document defines:

- The format and semantics of algorithm identifiers
- Registry tables for all algorithm categories
- Detailed parameters, key sizes, and encoding requirements for each algorithm
- Key protection categories and their operational procedures
- Security strength classifications
- Backward compatibility mappings from earlier TDF versions

This document does **not** define how algorithms are selected, negotiated, or
composed into a TDF manifest. Those concerns belong to the documents that
reference this registry (see BaseTDF-KAO for key access objects, BaseTDF-INT for
integrity, BaseTDF-ASN for assertions).

### 1.3 Adding New Algorithms

To add a new algorithm to the BaseTDF suite:

1. Add an entry to the appropriate registry table in [Section 3](#3-algorithm-registry-tables).
2. Add a detailed parameter section in [Section 5](#5-key-protection-algorithm-details) or [Section 6](#6-assertion-signing-algorithm-details).
3. Add a row to the security strength table in [Section 7](#7-security-strength-classification).
4. If the algorithm introduces a new key protection category, add it to [Section 4](#4-key-protection-categories).
5. Update referencing documents (BaseTDF-KAO, BaseTDF-INT, BaseTDF-ASN) to
   describe how the new algorithm is used in their respective contexts.

No changes to BaseTDF-CORE or the manifest schema are required unless the new
algorithm introduces a structural change to the manifest.

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][rfc2119] [RFC 8174][rfc8174]
when, and only when, they appear in ALL CAPITALS, as shown here.

---

## 2. Algorithm Identifier Format

Algorithm identifiers are **case-sensitive strings**. They appear in `alg` fields
throughout the BaseTDF suite, including:

- The `alg` field of Key Access Objects (BaseTDF-KAO)
- The `algorithm` field of integrity configuration (BaseTDF-INT)
- The `alg` field of assertion signatures (BaseTDF-ASN)

Each identifier maps to **exactly one** cryptographic operation with a fixed set
of parameters. Implementations MUST NOT interpret an identifier as referring to a
different operation or parameter set than what is defined in this registry.

Identifiers follow these conventions:

- Classical symmetric algorithms use JWA-style short names (e.g., `A256GCM`, `HS256`).
- Classical asymmetric algorithms use descriptive names (e.g., `RSA-OAEP-256`, `ECDH-HKDF`).
- Post-quantum algorithms use their NIST standardized names with security level (e.g., `ML-KEM-768`).
- Hybrid algorithms use the prefix `X-` followed by the component names (e.g., `X-ECDH-ML-KEM-768`).

Implementations MUST reject any `alg` value that is not recognized. Unknown
algorithm identifiers MUST NOT be silently ignored.

---

## 3. Algorithm Registry Tables

### 3.1 Content Encryption Algorithms

These algorithms protect TDF payload data. They are symmetric authenticated
encryption algorithms that provide both confidentiality and integrity of the
plaintext.

| Identifier | Description | Key Size | IV Size | Tag Size | Status |
|:-----------|:------------|:---------|:--------|:---------|:-------|
| `A256GCM` | AES-256-GCM | 256 bits | 96 bits | 128 bits | REQUIRED |

**A256GCM**: AES-256 in Galois/Counter Mode as specified in [NIST SP 800-38D][sp800-38d].
The 96-bit initialization vector (IV, also called nonce) MUST be unique for every
encryption operation performed under the same key. Reuse of an IV under the same
key catastrophically compromises both confidentiality and authenticity. The 128-bit
authentication tag MUST be appended to each ciphertext segment and verified before
any plaintext is released.

### 3.2 Key Protection Algorithms

These algorithms protect DEK shares within Key Access Objects (see BaseTDF-KAO).
Each algorithm belongs to one of the key protection categories defined in
[Section 4](#4-key-protection-categories).

| Identifier | Description | Category | Status |
|:-----------|:------------|:---------|:-------|
| `RSA-OAEP` | RSA-OAEP with SHA-1 | Key Wrapping | LEGACY |
| `RSA-OAEP-256` | RSA-OAEP with SHA-256 | Key Wrapping | RECOMMENDED |
| `ECDH-HKDF` | ECDH + HKDF-SHA256 | Key Agreement | RECOMMENDED |
| `ML-KEM-768` | ML-KEM-768 encapsulation | Key Encapsulation | RECOMMENDED |
| `ML-KEM-1024` | ML-KEM-1024 encapsulation | Key Encapsulation | OPTIONAL |
| `X-ECDH-ML-KEM-768` | Hybrid: ECDH-P256 + ML-KEM-768 | Hybrid | RECOMMENDED |

### 3.3 Integrity MAC Algorithms

These algorithms produce message authentication codes for payload integrity
verification (see BaseTDF-INT).

| Identifier | Description | Output Size | Status |
|:-----------|:------------|:------------|:-------|
| `HS256` | HMAC-SHA256 | 256 bits | REQUIRED |
| `GMAC` | AES-256-GMAC | 128 bits | OPTIONAL |

**HS256**: HMAC with SHA-256 as specified in [RFC 2104][rfc2104]. Used both for
per-segment integrity tags and for the root integrity signature over the segment
hash table.

**GMAC**: The GMAC mode of AES-256-GCM (i.e., GCM applied to an empty plaintext),
producing a 128-bit authentication tag. When used, the IV requirements of AES-GCM
apply (see Section 3.1).

### 3.4 Assertion Signing Algorithms

These algorithms sign or MAC assertion payloads (see BaseTDF-ASN). They establish
the authenticity of verifiable statements bound to a TDF.

| Identifier | Description | Status |
|:-----------|:------------|:-------|
| `HS256` | HMAC-SHA256 | REQUIRED |
| `RS256` | RSASSA-PKCS1-v1_5 with SHA-256 | OPTIONAL |
| `ES256` | ECDSA P-256 with SHA-256 | OPTIONAL |
| `ES384` | ECDSA P-384 with SHA-384 | OPTIONAL |
| `ML-DSA-44` | ML-DSA-44 (FIPS 204) | RECOMMENDED |
| `ML-DSA-65` | ML-DSA-65 (FIPS 204) | OPTIONAL |

---

## 4. Key Protection Categories

Key protection algorithms in Section 3.2 fall into four categories. Each category
defines a distinct operational pattern for how a DEK share is protected and
recovered. These categories replace the legacy `type` field values (`"wrapped"`,
`"ec-wrapped"`) from BaseTDF v4.3.0 (see [Section 9](#9-backward-compatibility)).

### 4.1 Key Wrapping (Direct Encryption)

**Used by**: `RSA-OAEP`, `RSA-OAEP-256`

In key wrapping, the DEK share is directly encrypted under the KAS public key.
No ephemeral key generation or key agreement is involved.

**Encryption operation**:

```
protectedKey = RSA-OAEP(kas_public_key, DEK_share)
```

**Decryption operation**:

```
DEK_share = RSA-OAEP-Decrypt(kas_private_key, protectedKey)
```

**Requirements**:

- Minimum RSA key size: 2048 bits (LEGACY deployments).
- RECOMMENDED RSA key size: 4096 bits for new deployments.
- The `ephemeralKey` field in the KAO is not used and SHOULD be omitted.

### 4.2 Key Agreement

**Used by**: `ECDH-HKDF`

In key agreement, an ephemeral key pair is generated by the encrypting party. The
ephemeral private key and the KAS public key are used to derive a shared secret
via Elliptic Curve Diffie-Hellman. A key derivation function produces a symmetric
key that protects the DEK share.

**Encryption operation**:

```
1. ephemeral_ec = generate_ec_keypair(curve)
2. shared_secret = ECDH(ephemeral_ec.sk, kas_ec_pk)
3. derived_key = HKDF-SHA256(
     salt = "",          // empty by default
     ikm  = shared_secret,
     info = "",          // empty by default
     len  = 32
   )
4. protectedKey = AES-256-GCM(derived_key, DEK_share)
5. ephemeralKey = ephemeral_ec.pk   // sent in KAO
```

**Decryption operation**:

```
1. shared_secret = ECDH(kas_ec_sk, ephemeralKey)
2. derived_key = HKDF-SHA256(salt="", shared_secret, info="", 32)
3. DEK_share = AES-256-GCM-Decrypt(derived_key, protectedKey)
```

**Requirements**:

- Supported curves: P-256 (secp256r1) is REQUIRED; P-384 (secp384r1) and
  P-521 (secp521r1) are OPTIONAL.
- Salt: empty by default. Implementations MAY provide a custom salt value.
- Info: empty by default. Implementations MAY provide a custom info value.
- **Backward compatibility**: The OpenTDF v4.3.0 implementation uses XOR wrapping
  (`derived_key XOR DEK_share`) instead of AES-256-GCM wrapping in step 4.
  Implementations MUST support XOR wrapping when reading existing TDFs for
  backward compatibility. New TDFs SHOULD use AES-256-GCM wrapping.

### 4.3 Key Encapsulation

**Used by**: `ML-KEM-768`, `ML-KEM-1024`

In key encapsulation, the encrypting party uses the KAS public encapsulation key
to produce a ciphertext and a shared secret in a single operation (KEM). The
shared secret is then used to derive a symmetric key that protects the DEK share.

**Encryption operation**:

```
1. (ct, ss) = ML-KEM.Encapsulate(kas_mlkem_pk)
2. derived_key = HKDF-SHA256(
     salt = "",
     ikm  = ss,
     info = "BaseTDF-KEM",
     len  = 32
   )
3. protectedKey = AES-256-GCM(derived_key, DEK_share)
4. ephemeralKey = ct   // KEM ciphertext, sent in KAO
```

**Decryption operation**:

```
1. ss = ML-KEM.Decapsulate(kas_mlkem_sk, ephemeralKey)
2. derived_key = HKDF-SHA256(salt="", ss, info="BaseTDF-KEM", 32)
3. DEK_share = AES-256-GCM-Decrypt(derived_key, protectedKey)
```

**Parameters by algorithm**:

| Algorithm | Ciphertext Size | Shared Secret Size | NIST Security Level |
|:----------|:----------------|:-------------------|:--------------------|
| `ML-KEM-768` | 1088 bytes | 32 bytes | Level 3 |
| `ML-KEM-1024` | 1568 bytes | 32 bytes | Level 5 |

**Requirements**:

- Implementations MUST use `"BaseTDF-KEM"` as the HKDF info string for domain
  separation.
- The `ephemeralKey` field in the KAO carries the KEM ciphertext, base64-encoded.
- ML-KEM operations MUST conform to [NIST FIPS 203][fips203].

### 4.4 Hybrid Key Protection

**Used by**: `X-ECDH-ML-KEM-768`

Hybrid key protection combines a classical key agreement mechanism with a
post-quantum key encapsulation mechanism. The construction is designed so that the
overall protection is secure as long as **either** the classical or the
post-quantum component remains unbroken. This provides defense-in-depth during the
transition to post-quantum cryptography.

**Encryption operation**:

```
// ---- Classical component ----
ephemeral_ec = generate_ec_keypair(P-256)
ss_classical = ECDH(ephemeral_ec.sk, kas_ec_pk)

// ---- Post-quantum component ----
(ct_pqc, ss_pqc) = ML-KEM-768.Encapsulate(kas_mlkem_pk)

// ---- Combine shared secrets ----
combined_ss = HKDF-SHA256(
  salt = SHA256("BaseTDF-Hybrid"),
  ikm  = ss_classical || ss_pqc,
  info = "BaseTDF-Hybrid-Key",
  len  = 32
)

// ---- Protect the DEK share ----
protectedKey = AES-256-GCM(combined_ss, DEK_share)

// ---- Encode ephemeral material ----
ephemeralKey = ephemeral_ec.pk || ct_pqc
```

**Decryption operation**:

```
// ---- Parse ephemeralKey ----
ephemeral_ec_pk = ephemeralKey[0..65]      // 65 bytes: uncompressed P-256 point
ct_pqc          = ephemeralKey[65..1153]   // 1088 bytes: ML-KEM-768 ciphertext

// ---- Classical component ----
ss_classical = ECDH(kas_ec_sk, ephemeral_ec_pk)

// ---- Post-quantum component ----
ss_pqc = ML-KEM-768.Decapsulate(kas_mlkem_sk, ct_pqc)

// ---- Combine shared secrets ----
combined_ss = HKDF-SHA256(
  salt = SHA256("BaseTDF-Hybrid"),
  ikm  = ss_classical || ss_pqc,
  info = "BaseTDF-Hybrid-Key",
  len  = 32
)

// ---- Recover the DEK share ----
DEK_share = AES-256-GCM-Decrypt(combined_ss, protectedKey)
```

**ephemeralKey encoding**:

The `ephemeralKey` field contains the concatenation of two components, in order:

| Component | Format | Size |
|:----------|:-------|:-----|
| EC ephemeral public key | Uncompressed point (`0x04 \|\| x \|\| y`) | 65 bytes |
| ML-KEM-768 ciphertext | Raw bytes | 1088 bytes |
| **Total** | | **1153 bytes** |

The concatenated value is base64-encoded when stored in the KAO `ephemeralKey`
field.

**Requirements**:

- The classical component MUST use the P-256 curve.
- The post-quantum component MUST use ML-KEM-768 per [FIPS 203][fips203].
- The HKDF salt MUST be `SHA256("BaseTDF-Hybrid")` -- a fixed 32-byte value
  derived by hashing the ASCII string `BaseTDF-Hybrid` (without null terminator)
  using SHA-256.
- The HKDF info string MUST be `"BaseTDF-Hybrid-Key"` (ASCII, without null
  terminator).
- The concatenation order of shared secrets MUST be `ss_classical || ss_pqc`
  (classical first, post-quantum second).
- The KAS MUST hold both an EC P-256 key pair and an ML-KEM-768 key pair. How
  these keys are provisioned, stored, and advertised is defined in BaseTDF-KAS.

**Security property**: The hybrid construction achieves IND-CCA2 security as long
as **either** the ECDH or ML-KEM component remains secure. A break of one
component alone does not compromise the combined shared secret because the
HKDF combiner mixes both shared secrets with domain-separated parameters.

---

## 5. Key Protection Algorithm Details

### 5.1 RSA-OAEP

| Parameter | Value |
|:----------|:------|
| Identifier | `RSA-OAEP` |
| Standard | [PKCS#1 v2.1][rfc8017], Section 7.1 |
| Hash function | SHA-1 |
| Mask generation function | MGF1 with SHA-1 |
| Key format | PKCS#8 or PKCS#1 PEM |
| Minimum key size | 2048 bits |
| Status | LEGACY |

**Status rationale**: SHA-1 is used within OAEP as a random oracle in the
encryption padding scheme, not for collision resistance. The known collision
weaknesses in SHA-1 do not translate to a practical attack on RSA-OAEP.
Nevertheless, new deployments SHOULD use `RSA-OAEP-256` to align with current
best practice. Implementations MUST support `RSA-OAEP` for decrypting existing
TDFs but MUST NOT use it when creating new TDFs in security-sensitive contexts.

### 5.2 RSA-OAEP-256

| Parameter | Value |
|:----------|:------|
| Identifier | `RSA-OAEP-256` |
| Standard | [PKCS#1 v2.1][rfc8017], Section 7.1 |
| Hash function | SHA-256 |
| Mask generation function | MGF1 with SHA-256 |
| Key format | PKCS#8 or PKCS#1 PEM |
| Minimum key size | 2048 bits |
| RECOMMENDED key size | 4096 bits |
| Status | RECOMMENDED |

### 5.3 ECDH-HKDF

| Parameter | Value |
|:----------|:------|
| Identifier | `ECDH-HKDF` |
| Key agreement | ECDH per [RFC 6090][rfc6090] |
| KDF | HKDF-SHA256 per [RFC 5869][rfc5869] |
| Wrapping algorithm | AES-256-GCM (new TDFs); XOR (legacy, read-only) |
| REQUIRED curve | P-256 (secp256r1) |
| OPTIONAL curves | P-384 (secp384r1), P-521 (secp521r1) |
| Ephemeral key format | Uncompressed EC point (`0x04 \|\| x \|\| y`) or PEM |
| Status | RECOMMENDED |

**Implementation note**: The current OpenTDF implementation (v4.3.0 and earlier)
uses XOR wrapping, where `protectedKey = derived_key XOR DEK_share`. This
approach is acceptable only when the derived key is indistinguishable from random
and is at least as long as the DEK share. For improved robustness, v4.4.0
specifies AES-256-GCM wrapping as the default for new TDFs. Implementations:

- MUST support XOR-based unwrapping when reading existing TDFs.
- SHOULD use AES-256-GCM wrapping when creating new TDFs.
- MAY indicate the wrapping mode via metadata if disambiguation is needed.

### 5.4 ML-KEM-768

| Parameter | Value |
|:----------|:------|
| Identifier | `ML-KEM-768` |
| Standard | [NIST FIPS 203][fips203] |
| Public key size | 1184 bytes |
| Ciphertext size | 1088 bytes |
| Shared secret size | 32 bytes |
| NIST security level | Level 3 (equivalent to AES-192 security) |
| Key format | Raw bytes, base64-encoded in KAO fields |
| Status | RECOMMENDED |

**Key encoding**: ML-KEM public keys and ciphertexts are encoded as raw byte
arrays and base64-encoded when stored in JSON fields. There is no PEM wrapper for
ML-KEM keys in KAO fields; the raw FIPS 203 byte encoding is used directly.

### 5.5 ML-KEM-1024

| Parameter | Value |
|:----------|:------|
| Identifier | `ML-KEM-1024` |
| Standard | [NIST FIPS 203][fips203] |
| Public key size | 1568 bytes |
| Ciphertext size | 1568 bytes |
| Shared secret size | 32 bytes |
| NIST security level | Level 5 (equivalent to AES-256 security) |
| Key format | Raw bytes, base64-encoded in KAO fields |
| Status | OPTIONAL |

### 5.6 X-ECDH-ML-KEM-768

| Parameter | Value |
|:----------|:------|
| Identifier | `X-ECDH-ML-KEM-768` |
| Classical component | ECDH with P-256 |
| Post-quantum component | ML-KEM-768 per [FIPS 203][fips203] |
| Combiner | HKDF-SHA256 with domain separation |
| HKDF salt | `SHA256("BaseTDF-Hybrid")` (fixed 32 bytes) |
| HKDF info | `"BaseTDF-Hybrid-Key"` (ASCII) |
| Wrapping algorithm | AES-256-GCM |
| Status | RECOMMENDED |

**ephemeralKey field encoding**:

| Offset | Length | Content |
|:-------|:-------|:--------|
| 0 | 65 bytes | EC ephemeral public key (uncompressed P-256 point: `0x04 \|\| x \|\| y`) |
| 65 | 1088 bytes | ML-KEM-768 ciphertext |
| **Total** | **1153 bytes** | Base64-encoded in the KAO `ephemeralKey` field |

The operational procedure is fully specified in [Section 4.4](#44-hybrid-key-protection).

---

## 6. Assertion Signing Algorithm Details

### 6.1 HS256

| Parameter | Value |
|:----------|:------|
| Identifier | `HS256` |
| Standard | HMAC with SHA-256 per [RFC 2104][rfc2104] |
| Key size | Minimum 256 bits |
| Output size | 256 bits (32 bytes) |
| Status | REQUIRED |

**Dual role**: `HS256` serves two purposes in the BaseTDF suite:

1. **Policy binding MAC** (BaseTDF-KAO): the HMAC over the policy object that
   binds the policy to the encrypted key material.
2. **Assertion signing** (BaseTDF-ASN): HMAC-based authentication of assertion
   payloads.

In both roles, the key MUST be at least 256 bits and MUST be generated using a
cryptographically secure random number generator.

### 6.2 RS256

| Parameter | Value |
|:----------|:------|
| Identifier | `RS256` |
| Standard | RSASSA-PKCS1-v1_5 with SHA-256 per [RFC 8017][rfc8017] |
| Minimum key size | 2048 bits |
| Status | OPTIONAL |

### 6.3 ES256

| Parameter | Value |
|:----------|:------|
| Identifier | `ES256` |
| Standard | ECDSA with P-256 and SHA-256 per [FIPS 186-4][fips186-4] |
| Curve | P-256 (secp256r1) |
| Hash | SHA-256 |
| Status | OPTIONAL |

### 6.4 ES384

| Parameter | Value |
|:----------|:------|
| Identifier | `ES384` |
| Standard | ECDSA with P-384 and SHA-384 per [FIPS 186-4][fips186-4] |
| Curve | P-384 (secp384r1) |
| Hash | SHA-384 |
| Status | OPTIONAL |

### 6.5 ML-DSA-44

| Parameter | Value |
|:----------|:------|
| Identifier | `ML-DSA-44` |
| Standard | [NIST FIPS 204][fips204] |
| Public key size | 1312 bytes |
| Signature size | 2420 bytes |
| NIST security level | Level 2 (approximately equivalent to AES-128 / SHA-256 collision resistance) |
| Key format | Raw bytes, base64-encoded in assertion fields |
| Status | RECOMMENDED |

**Recommended use**: `ML-DSA-44` is the RECOMMENDED post-quantum signing algorithm
for assertion signing. Its Level 2 security is appropriate for assertions where
the primary threat is signature forgery, and its relatively compact signatures
(compared to higher ML-DSA parameter sets) make it suitable for inclusion in TDF
manifests.

### 6.6 ML-DSA-65

| Parameter | Value |
|:----------|:------|
| Identifier | `ML-DSA-65` |
| Standard | [NIST FIPS 204][fips204] |
| Public key size | 1952 bytes |
| Signature size | 3309 bytes |
| NIST security level | Level 3 (approximately equivalent to AES-192 security) |
| Key format | Raw bytes, base64-encoded in assertion fields |
| Status | OPTIONAL |

---

## 7. Security Strength Classification

The following table summarizes the security strength of each algorithm against
classical and quantum adversaries. For the security model and minimum strength
requirements, see BaseTDF-SEC.

| Algorithm | Classical Security | Post-Quantum Security | Notes |
|:----------|:-------------------|:----------------------|:------|
| `A256GCM` | 256 bits | 128 bits (Grover's bound) | Content encryption |
| `RSA-OAEP` (2048-bit) | ~112 bits | 0 (Shor's algorithm) | LEGACY only |
| `RSA-OAEP-256` (4096-bit) | ~150 bits | 0 (Shor's algorithm) | Transition period |
| `ECDH-HKDF` (P-256) | 128 bits | 0 (Shor's algorithm) | Transition period |
| `ML-KEM-768` | N/A | 192 bits (NIST Level 3) | Post-quantum |
| `ML-KEM-1024` | N/A | 256 bits (NIST Level 5) | Post-quantum |
| `X-ECDH-ML-KEM-768` | 128 bits | 192 bits (NIST Level 3) | Hybrid: secure if either component holds |
| `HS256` | 256 bits | 128 bits (Grover's bound) | MAC / policy binding |
| `GMAC` | 128 bits | 64 bits (Grover's bound) | Integrity MAC |
| `RS256` (2048-bit) | ~112 bits | 0 (Shor's algorithm) | Assertion signing |
| `ES256` | 128 bits | 0 (Shor's algorithm) | Assertion signing |
| `ES384` | 192 bits | 0 (Shor's algorithm) | Assertion signing |
| `ML-DSA-44` | N/A | ~128 bits (NIST Level 2) | Assertion signing |
| `ML-DSA-65` | N/A | ~192 bits (NIST Level 3) | Assertion signing |

**Post-quantum security = 0** means the algorithm is completely broken by a
cryptographically relevant quantum computer (CRQC) running Shor's algorithm.
**Grover's bound** means the symmetric key space is effectively halved by
Grover's algorithm (e.g., 256-bit key provides 128-bit post-quantum security).

For hybrid algorithms, the combined security level is the **maximum** of the two
component security levels in each category (classical and post-quantum),
reflecting the design property that the hybrid is secure as long as either
component remains unbroken.

---

## 8. Status Definitions

| Status | RFC 2119 Keyword | Meaning |
|:-------|:-----------------|:--------|
| REQUIRED | MUST | All conformant implementations MUST support this algorithm. Interoperability depends on it. |
| RECOMMENDED | SHOULD | Implementations SHOULD support this algorithm. It is the preferred choice for new deployments unless specific constraints dictate otherwise. |
| OPTIONAL | MAY | Implementations MAY support this algorithm. It is defined for use cases with specific requirements (e.g., higher security levels). |
| LEGACY | MUST (read) / MUST NOT (write) | Implementations MUST support this algorithm when reading existing TDFs for backward compatibility. Implementations MUST NOT use this algorithm when creating new TDFs in security-sensitive contexts. |

---

## 9. Backward Compatibility

### 9.1 Mapping from v4.3.0 Type Strings

BaseTDF v4.3.0 used a `type` field in Key Access Objects to indicate the key
protection mechanism. Version 4.4.0 replaces this with the explicit `alg` field.
The following mapping defines the equivalence:

| v4.3.0 `type` Value | v4.4.0 `alg` Value | Notes |
|:---------------------|:---------------------|:------|
| `"wrapped"` | `"RSA-OAEP"` | SHA-1 variant, for historical compatibility |
| `"ec-wrapped"` | `"ECDH-HKDF"` | With XOR wrapping (legacy mode) |

### 9.2 Reading Legacy KAOs

When reading a Key Access Object that contains a `type` field but no `alg` field,
implementations MUST apply the mapping in Section 9.1 to determine the algorithm.
The `type` field alone is sufficient to unambiguously identify the algorithm for
all v4.3.0 TDFs.

### 9.3 Writing New KAOs

When creating new Key Access Objects, implementations MUST include the `alg`
field. The `type` field MAY be included for backward compatibility with older
readers, but the `alg` field is the authoritative identifier.

If both `type` and `alg` are present and they conflict (e.g., `type: "wrapped"`
with `alg: "ECDH-HKDF"`), the `alg` field takes precedence. Implementations
SHOULD NOT produce conflicting values.

---

## 10. Normative References

- <a id="sp800-38d"></a>**[NIST SP 800-38D]** — Dworkin, M., "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", NIST Special Publication 800-38D, November 2007.
  https://csrc.nist.gov/publications/detail/sp/800-38d/final

- <a id="fips203"></a>**[NIST FIPS 203]** — "Module-Lattice-Based Key-Encapsulation Mechanism Standard", Federal Information Processing Standards Publication 203, August 2024.
  https://csrc.nist.gov/publications/detail/fips/203/final

- <a id="fips204"></a>**[NIST FIPS 204]** — "Module-Lattice-Based Digital Signature Standard", Federal Information Processing Standards Publication 204, August 2024.
  https://csrc.nist.gov/publications/detail/fips/204/final

- <a id="fips186-4"></a>**[NIST FIPS 186-4]** — "Digital Signature Standard (DSS)", Federal Information Processing Standards Publication 186-4, July 2013.
  https://csrc.nist.gov/publications/detail/fips/186-4/final

- <a id="rfc5869"></a>**[RFC 5869]** — Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.
  https://www.rfc-editor.org/rfc/rfc5869

- <a id="rfc8017"></a>**[RFC 8017]** — Moriarty, K., Ed., Kaliski, B., Jonsson, J., and A. Rusch, "PKCS #1: RSA Cryptography Specifications Version 2.2", RFC 8017, November 2016.
  https://www.rfc-editor.org/rfc/rfc8017

- <a id="rfc6090"></a>**[RFC 6090]** — McGrew, D., Igoe, K., and M. Salter, "Fundamental Elliptic Curve Cryptography Algorithms", RFC 6090, February 2011.
  https://www.rfc-editor.org/rfc/rfc6090

- <a id="rfc2104"></a>**[RFC 2104]** — Krawczyk, H., Bellare, M., and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, February 1997.
  https://www.rfc-editor.org/rfc/rfc2104

- <a id="rfc2119"></a>**[BCP 14 / RFC 2119]** — Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
  https://www.rfc-editor.org/rfc/rfc2119

- <a id="rfc8174"></a>**[RFC 8174]** — Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
  https://www.rfc-editor.org/rfc/rfc8174

---

[sp800-38d]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
[fips203]: https://csrc.nist.gov/publications/detail/fips/203/final
[fips204]: https://csrc.nist.gov/publications/detail/fips/204/final
[fips186-4]: https://csrc.nist.gov/publications/detail/fips/186-4/final
[rfc5869]: https://www.rfc-editor.org/rfc/rfc5869
[rfc8017]: https://www.rfc-editor.org/rfc/rfc8017
[rfc6090]: https://www.rfc-editor.org/rfc/rfc6090
[rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174
