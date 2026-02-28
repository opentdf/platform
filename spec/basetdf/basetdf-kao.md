# BaseTDF-KAO: Key Access Object

| | |
|---|---|
| **Document** | BaseTDF-KAO |
| **Title** | Key Access Object |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG |
| **Referenced by** | BaseTDF-CORE, BaseTDF-KAS |

## Table of Contents

1. [Introduction](#1-introduction)
2. [KAO Schema](#2-kao-schema)
3. [Key Splitting](#3-key-splitting)
4. [Algorithm-Specific Operations](#4-algorithm-specific-operations)
5. [Policy Binding](#5-policy-binding)
6. [Encrypted Metadata](#6-encrypted-metadata)
7. [Backward Compatibility](#7-backward-compatibility)
8. [Security Considerations](#8-security-considerations)
9. [Normative References](#9-normative-references)

---

## 1. Introduction

### 1.1 Purpose

The Key Access Object (KAO) is the core cryptographic structure within a TDF
manifest that binds a protected Data Encryption Key (DEK) share to a policy and
a specific Key Access Service (KAS) instance. Each KAO carries sufficient
information for its designated KAS to:

1. Identify the KAS key pair needed for decapsulation or unwrapping.
2. Recover the plaintext DEK share.
3. Verify the integrity of the policy binding before any key release.

A TDF manifest contains one or more KAOs in its `encryptionInformation.keyAccess`
array. When key splitting is used (Section 3), multiple KAOs protect independent
shares of the DEK, each addressed to a potentially different KAS. The full DEK
can only be reconstructed when all shares are recovered.

### 1.2 Scope

This document defines:

- The JSON schema and field semantics for the Key Access Object.
- The XOR-based key splitting mechanism and its relationship to policy
  attribute rules.
- Algorithm-specific procedures for protecting DEK shares, referencing the
  algorithm registry in BaseTDF-ALG.
- The policy binding computation and verification procedure.
- The encrypted metadata sub-structure.
- Backward compatibility rules for reading and writing KAOs across TDF versions.

This document does NOT define:

- The wire protocol for communicating KAOs to the KAS (see BaseTDF-KAS).
- The policy structure or ABAC evaluation rules (see BaseTDF-POL).
- The container format in which KAOs are embedded (see BaseTDF-CORE).
- The algorithm parameters themselves (see BaseTDF-ALG).

### 1.3 Relationship to Other BaseTDF Documents

- **BaseTDF-SEC** defines the security invariants that the KAO mechanism
  implements, including policy binding integrity (SI-1), algorithm validation
  (SI-6), and key material hygiene (SI-7).
- **BaseTDF-ALG** defines the algorithm identifiers, parameters, and key
  protection categories referenced by the KAO `alg` field.
- **BaseTDF-POL** defines the policy object whose integrity is protected by the
  KAO policy binding.
- **BaseTDF-KAS** defines the rewrap protocol through which a KAS processes KAOs
  and returns re-encrypted DEK shares to authorized clients.
- **BaseTDF-CORE** defines the manifest structure in which KAOs are embedded.

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][RFC2119] [RFC
8174][RFC8174] when, and only when, they appear in ALL CAPITALS, as shown here.

---

## 2. KAO Schema

### 2.1 v4.4.0 Schema

The following JSON illustrates a complete v4.4.0 Key Access Object using the
ML-KEM-768 key encapsulation mechanism:

```json
{
  "alg": "ML-KEM-768",
  "kas": "https://kas.example.com",
  "kid": "kas-mlkem-key-2025",
  "sid": "split-0",
  "protectedKey": "<base64-encoded protected DEK share>",
  "ephemeralKey": "<base64-encoded KEM ciphertext>",
  "policyBinding": {
    "alg": "HS256",
    "hash": "<base64-encoded HMAC-SHA256 digest>"
  },
  "encryptedMetadata": "<base64-encoded AES-256-GCM ciphertext>"
}
```

### 2.2 Field Definitions

#### `alg` (string, REQUIRED)

Algorithm identifier from the BaseTDF-ALG key protection registry (BaseTDF-ALG
Section 3.2). This field unambiguously identifies the cryptographic mechanism
used to protect the DEK share.

Valid values include: `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-HKDF`, `ML-KEM-768`,
`ML-KEM-1024`, `X-ECDH-ML-KEM-768`.

Implementations MUST include this field when creating new KAOs. Implementations
MUST reject KAOs whose `alg` value is not recognized (see SI-6 in BaseTDF-SEC).

#### `type` (string, DEPRECATED)

Legacy key type field from BaseTDF v4.3.0. Accepted values: `"wrapped"`,
`"ec-wrapped"`, `"remote"`.

When both `alg` and `type` are present, `alg` takes precedence. When only `type`
is present (legacy KAOs), the algorithm is inferred per the backward
compatibility mapping in Section 7. Implementations SHOULD NOT produce
conflicting `type` and `alg` values.

#### `kas` (string, REQUIRED)

Fully qualified URL of the Key Access Service that holds the private key
corresponding to the public key used to protect the DEK share. This URL
identifies the KAS endpoint to which rewrap requests for this KAO MUST be
directed.

Example: `"https://kas.example.com"`

This field is the v4.4.0 canonical name for the KAS URL. See `url` below for
the deprecated alias.

#### `url` (string, DEPRECATED)

Legacy name for the `kas` field. When reading a KAO, implementations MUST treat
`url` as equivalent to `kas`. When both are present, `kas` takes precedence.
When writing new KAOs, implementations SHOULD use `kas` and MAY additionally
include `url` for backward compatibility with older readers.

#### `kid` (string, REQUIRED)

Key identifier for the KAS key pair used to protect the DEK share. The KAS uses
this value to select the correct private key for decapsulation or unwrapping.

Implementations MUST include `kid` when creating new KAOs. KAS implementations
MUST support KAOs that omit `kid` for backward compatibility with legacy TDFs,
but SHOULD log a warning when processing such KAOs (see BaseTDF-SEC
Section 4.4).

#### `sid` (string, REQUIRED)

Split identifier. Groups KAOs that protect the same DEK share within a key
splitting configuration. All KAOs with the same `sid` value protect the same
DEK share and represent alternative paths to recover that share (i.e., any one
of them is sufficient).

When key splitting is not used (single KAS), the `sid` field MAY be empty or
omitted. When key splitting is used, each distinct split MUST have a unique
`sid` value. See Section 3 for the key splitting mechanism.

#### `protectedKey` (string, REQUIRED)

Base64-encoded algorithm-specific protected DEK share. The contents and
structure of this field depend on the algorithm identified by `alg`:

- For key wrapping algorithms (`RSA-OAEP`, `RSA-OAEP-256`): the RSA-OAEP
  ciphertext.
- For key agreement algorithms (`ECDH-HKDF`): the AES-256-GCM ciphertext of
  the DEK share encrypted under the derived key (or XOR of DEK share and
  derived key for legacy TDFs).
- For key encapsulation algorithms (`ML-KEM-768`, `ML-KEM-1024`): the
  AES-256-GCM ciphertext of the DEK share encrypted under the HKDF-derived
  key.
- For hybrid algorithms (`X-ECDH-ML-KEM-768`): the AES-256-GCM ciphertext of
  the DEK share encrypted under the combined derived key.

#### `wrappedKey` (string, DEPRECATED)

Legacy name for the `protectedKey` field. When reading a KAO, implementations
MUST treat `wrappedKey` as equivalent to `protectedKey`. When both are present,
`protectedKey` takes precedence. When writing new KAOs, implementations MUST use
`protectedKey` and MAY additionally include `wrappedKey` for backward
compatibility.

#### `ephemeralKey` (string, CONDITIONAL)

Base64-encoded ephemeral public key or KEM ciphertext. This field is REQUIRED
for key agreement and key encapsulation algorithms; it is not used for key
wrapping algorithms.

The contents depend on the algorithm:

| Algorithm | `ephemeralKey` Contents |
|:----------|:-----------------------|
| `RSA-OAEP`, `RSA-OAEP-256` | Not used; SHOULD be omitted |
| `ECDH-HKDF` | Ephemeral EC public key in PEM format |
| `ML-KEM-768`, `ML-KEM-1024` | KEM ciphertext (raw bytes, base64-encoded) |
| `X-ECDH-ML-KEM-768` | Concatenation: EC point (65 bytes) &#124;&#124; ML-KEM-768 ciphertext (1088 bytes), base64-encoded. See BaseTDF-ALG Section 4.4. |

Legacy KAOs use the JSON field name `ephemeralPublicKey` instead of
`ephemeralKey`. Implementations MUST accept both field names when reading.

#### `policyBinding` (object, REQUIRED)

Policy binding verification data. This object cryptographically binds the KAO to
the policy embedded in the TDF manifest. See Section 5 for the computation and
verification procedure.

```json
{
  "alg": "HS256",
  "hash": "<base64-encoded HMAC-SHA256 digest>"
}
```

- `policyBinding.alg` (string, REQUIRED): The MAC algorithm used for the
  binding. MUST be `"HS256"` (HMAC-SHA256). Implementations MUST reject unknown
  values (SI-6).
- `policyBinding.hash` (string, REQUIRED): Base64-encoded MAC digest.

Legacy KAOs MAY represent the policy binding as a bare string (the hash value
alone) instead of an object. See Section 7 for handling legacy formats.

#### `encryptedMetadata` (string, OPTIONAL)

Base64-encoded encrypted metadata. When present, this field contains metadata
encrypted with the DEK share using AES-256-GCM. See Section 6 for the structure
and security requirements.

### 2.3 Additional Fields

The following fields are recognized for compatibility but are not part of the
core v4.4.0 schema:

- `protocol` (string): Legacy field, value `"kas"`. Informational only.
- `schemaVersion` (string): Legacy field indicating the KAO schema version
  (e.g., `"1.0"`). The TDF manifest-level `schemaVersion` field is the
  authoritative version indicator in v4.4.0.

---

## 3. Key Splitting

### 3.1 Overview

Key splitting divides the DEK into multiple independent shares using XOR-based
n-of-n secret sharing. Each share is protected in its own KAO, potentially
addressed to a different KAS. All shares are required to reconstruct the DEK;
compromise of fewer than all shares reveals no information about the DEK.

### 3.2 Formal Definition

Given a DEK of length L bytes (32 bytes for AES-256), key splitting produces
n shares such that:

```
DEK = share_0 XOR share_1 XOR ... XOR share_(n-1)
```

**Share generation procedure**:

1. For i = 0 to n-2:
   - Generate `share_i` as L bytes from a CSPRNG (see BaseTDF-SEC Section 6.5).
2. Compute the final share:
   - `share_(n-1) = DEK XOR share_0 XOR share_1 XOR ... XOR share_(n-2)`

**DEK reconstruction procedure**:

1. Obtain all n shares from their respective KAOs via the rewrap protocol.
2. Compute: `DEK = share_0 XOR share_1 XOR ... XOR share_(n-1)`

**Security property**: Each individual share is uniformly random and
statistically independent of the DEK. An adversary who obtains any strict subset
of shares gains zero information about the DEK. This is information-theoretic
security, not computational security -- it holds regardless of the adversary's
computational power.

### 3.3 Split Assignment from Policy Attribute Rules

The mapping from policy attribute rules to key splits determines which KAS
instances must authorize access. The following rules govern split assignment:

| Attribute Rule | Split Assignment | Semantic |
|:---------------|:-----------------|:---------|
| `allOf` | Each attribute value gets a SEPARATE split (`sid`) | ALL KASes associated with the attribute values must independently authorize access |
| `anyOf` | All attribute values share ONE split (`sid`) | ANY one KAS associated with the attribute values can authorize access |
| `hierarchy` | Treated as `anyOf` (single split) | Same as `anyOf`; hierarchical ordering is enforced by the KAS authorization logic, not by the split structure |

**Example**: A policy with two `allOf` attributes and one `anyOf` attribute
(with three values) produces two splits:

```
Split 0 (sid: "s-0"): allOf attribute #1 → KAS A
Split 1 (sid: "s-1"): allOf attribute #2 → KAS B
                       anyOf values 1,2,3 → KAS C, KAS D, KAS E (same split)
```

In this example, Split 0 has one KAO (to KAS A), and Split 1 has four KAOs (one
to KAS B for the allOf attribute, and one each to KAS C, KAS D, KAS E for the
anyOf attribute values). Reconstruction requires one KAO from Split 0 AND one
KAO from Split 1.

### 3.4 Split Identifier Generation

Split identifiers (`sid`) MUST be unique within a single TDF manifest.
Implementations MAY use any scheme that guarantees uniqueness, including:

- Sequential identifiers: `"s-0"`, `"s-1"`, `"s-2"`, ...
- UUID-based identifiers.

When a TDF has only a single KAO (no splitting), the `sid` field MAY be empty
or omitted.

### 3.5 Same-KAS Split Warning

Implementations SHOULD warn when all splits in a key splitting configuration
resolve to the same KAS URL. While this configuration is functionally correct,
it reduces the defense-in-depth benefit of key splitting to a single point of
compromise (see BaseTDF-SEC Section 4.4).

---

## 4. Algorithm-Specific Operations

This section describes how each key protection category (defined in BaseTDF-ALG
Section 4) is applied to produce the `protectedKey` and `ephemeralKey` fields in
a KAO. For full algorithm parameters and implementation requirements, see
BaseTDF-ALG Section 5.

### 4.1 Key Wrapping (RSA-OAEP, RSA-OAEP-256)

Key wrapping directly encrypts the DEK share under the KAS RSA public key.

**Encryption** (TDF creation):

```
protectedKey = Base64(RSA-OAEP(kas_rsa_pk, DEK_share))
```

**Decryption** (KAS rewrap):

```
DEK_share = RSA-OAEP-Decrypt(kas_rsa_sk, Base64Decode(protectedKey))
```

**KAO fields**:

| Field | Value |
|:------|:------|
| `alg` | `"RSA-OAEP"` or `"RSA-OAEP-256"` |
| `protectedKey` | Base64-encoded RSA-OAEP ciphertext |
| `ephemeralKey` | Not used; SHOULD be omitted |

**Example** (RSA-OAEP-256):

```json
{
  "alg": "RSA-OAEP-256",
  "kas": "https://kas.example.com",
  "kid": "rsa-4096-2025",
  "sid": "s-0",
  "protectedKey": "TUlJQ...base64-encoded RSA-OAEP ciphertext...",
  "policyBinding": {
    "alg": "HS256",
    "hash": "YTgz...base64-encoded HMAC..."
  }
}
```

### 4.2 Key Agreement (ECDH-HKDF)

Key agreement uses an ephemeral ECDH exchange to derive a symmetric key, which
then protects the DEK share.

**Encryption** (TDF creation):

```
1. ephemeral_ec = generate_ec_keypair(curve)
2. shared_secret = ECDH(ephemeral_ec.sk, kas_ec_pk)
3. derived_key = HKDF-SHA256(
     salt = SHA256("TDF"),
     ikm  = shared_secret,
     info = "",
     len  = 32
   )
4. protectedKey = Base64(AES-256-GCM(derived_key, DEK_share))
5. ephemeralKey = PEM(ephemeral_ec.pk)
```

**Decryption** (KAS rewrap):

```
1. shared_secret = ECDH(kas_ec_sk, PEM_parse(ephemeralKey))
2. derived_key = HKDF-SHA256(
     salt = SHA256("TDF"),
     ikm  = shared_secret,
     info = "",
     len  = 32
   )
3. DEK_share = AES-256-GCM-Decrypt(derived_key, Base64Decode(protectedKey))
```

**KAO fields**:

| Field | Value |
|:------|:------|
| `alg` | `"ECDH-HKDF"` |
| `protectedKey` | Base64-encoded AES-256-GCM ciphertext (or XOR result for legacy) |
| `ephemeralKey` | Ephemeral EC public key in PEM format |

**Implementation note**: The HKDF salt is `SHA256("TDF")` -- the SHA-256 hash
of the three ASCII bytes `0x54 0x44 0x46`. This is a fixed 32-byte value.

**Legacy compatibility**: The v4.3.0 implementation uses XOR wrapping
(`derived_key XOR DEK_share`) in step 4 instead of AES-256-GCM. Implementations
MUST support XOR-based unwrapping when reading existing TDFs. New TDFs SHOULD
use AES-256-GCM wrapping. See BaseTDF-ALG Section 4.2 for details.

**Example** (ECDH-HKDF):

```json
{
  "alg": "ECDH-HKDF",
  "kas": "https://kas.example.com",
  "kid": "ec-p256-2025",
  "sid": "",
  "protectedKey": "dGhl...base64-encoded AES-GCM ciphertext...",
  "ephemeralKey": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
  "policyBinding": {
    "alg": "HS256",
    "hash": "YTgz...base64-encoded HMAC..."
  }
}
```

### 4.3 Key Encapsulation (ML-KEM-768, ML-KEM-1024)

Key encapsulation uses a lattice-based KEM to establish a shared secret, which
is then used to derive a symmetric key protecting the DEK share.

**Encryption** (TDF creation):

```
1. (ct, ss) = ML-KEM.Encapsulate(kas_mlkem_pk)
2. derived_key = HKDF-SHA256(
     salt = "",
     ikm  = ss,
     info = "BaseTDF-KEM",
     len  = 32
   )
3. protectedKey = Base64(AES-256-GCM(derived_key, DEK_share))
4. ephemeralKey = Base64(ct)
```

**Decryption** (KAS rewrap):

```
1. ss = ML-KEM.Decapsulate(kas_mlkem_sk, Base64Decode(ephemeralKey))
2. derived_key = HKDF-SHA256(
     salt = "",
     ikm  = ss,
     info = "BaseTDF-KEM",
     len  = 32
   )
3. DEK_share = AES-256-GCM-Decrypt(derived_key, Base64Decode(protectedKey))
```

**KAO fields**:

| Field | Value |
|:------|:------|
| `alg` | `"ML-KEM-768"` or `"ML-KEM-1024"` |
| `protectedKey` | Base64-encoded AES-256-GCM ciphertext |
| `ephemeralKey` | Base64-encoded KEM ciphertext (1088 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024) |

**Requirements**:

- Implementations MUST use `"BaseTDF-KEM"` as the HKDF info string for domain
  separation.
- ML-KEM operations MUST conform to [NIST FIPS 203][FIPS203].

**Example** (ML-KEM-768):

```json
{
  "alg": "ML-KEM-768",
  "kas": "https://kas.example.com",
  "kid": "kas-mlkem-key-2025",
  "sid": "split-0",
  "protectedKey": "base64...AES-GCM ciphertext of DEK share...",
  "ephemeralKey": "base64...1088 bytes of ML-KEM-768 ciphertext...",
  "policyBinding": {
    "alg": "HS256",
    "hash": "base64...HMAC-SHA256 digest..."
  }
}
```

### 4.4 Hybrid (X-ECDH-ML-KEM-768)

Hybrid key protection combines ECDH key agreement with ML-KEM key encapsulation.
The combined construction is secure as long as either the classical or the
post-quantum component remains unbroken.

**Encryption** (TDF creation):

```
// Classical component
1. ephemeral_ec = generate_ec_keypair(P-256)
2. ss_classical = ECDH(ephemeral_ec.sk, kas_ec_pk)

// Post-quantum component
3. (ct_pqc, ss_pqc) = ML-KEM-768.Encapsulate(kas_mlkem_pk)

// Combine shared secrets
4. combined_ss = HKDF-SHA256(
     salt = SHA256("BaseTDF-Hybrid"),
     ikm  = ss_classical || ss_pqc,
     info = "BaseTDF-Hybrid-Key",
     len  = 32
   )

// Protect the DEK share
5. protectedKey = Base64(AES-256-GCM(combined_ss, DEK_share))

// Encode ephemeral material
6. ephemeralKey = Base64(ephemeral_ec.pk_uncompressed || ct_pqc)
```

**Decryption** (KAS rewrap):

```
// Parse ephemeralKey
1. raw = Base64Decode(ephemeralKey)
2. ephemeral_ec_pk = raw[0..65]      // 65 bytes: uncompressed P-256 point
3. ct_pqc          = raw[65..1153]   // 1088 bytes: ML-KEM-768 ciphertext

// Classical component
4. ss_classical = ECDH(kas_ec_sk, ephemeral_ec_pk)

// Post-quantum component
5. ss_pqc = ML-KEM-768.Decapsulate(kas_mlkem_sk, ct_pqc)

// Combine shared secrets
6. combined_ss = HKDF-SHA256(
     salt = SHA256("BaseTDF-Hybrid"),
     ikm  = ss_classical || ss_pqc,
     info = "BaseTDF-Hybrid-Key",
     len  = 32
   )

// Recover the DEK share
7. DEK_share = AES-256-GCM-Decrypt(combined_ss, Base64Decode(protectedKey))
```

**KAO fields**:

| Field | Value |
|:------|:------|
| `alg` | `"X-ECDH-ML-KEM-768"` |
| `protectedKey` | Base64-encoded AES-256-GCM ciphertext |
| `ephemeralKey` | Base64-encoded concatenation: EC point (65 bytes) &#124;&#124; ML-KEM-768 ciphertext (1088 bytes) = 1153 bytes total |

**Requirements**:

- The HKDF salt MUST be `SHA256("BaseTDF-Hybrid")` -- a fixed 32-byte value.
- The HKDF info string MUST be `"BaseTDF-Hybrid-Key"`.
- The concatenation order of shared secrets MUST be `ss_classical || ss_pqc`.
- The classical component MUST use the P-256 curve.
- The post-quantum component MUST use ML-KEM-768 per [FIPS 203][FIPS203].
- The KAS MUST hold both an EC P-256 key pair and an ML-KEM-768 key pair.

See BaseTDF-ALG Section 4.4 for the full parameter specification.

**Example** (X-ECDH-ML-KEM-768):

```json
{
  "alg": "X-ECDH-ML-KEM-768",
  "kas": "https://kas.example.com",
  "kid": "kas-hybrid-2025",
  "sid": "s-0",
  "protectedKey": "base64...AES-GCM ciphertext of DEK share...",
  "ephemeralKey": "base64...1153 bytes: EC point || ML-KEM ciphertext...",
  "policyBinding": {
    "alg": "HS256",
    "hash": "base64...HMAC-SHA256 digest..."
  }
}
```

---

## 5. Policy Binding

### 5.1 Purpose

The policy binding cryptographically ties a KAO to the specific policy embedded
in the TDF manifest. It prevents an adversary from substituting, modifying, or
transplanting a policy without detection. The KAS MUST verify the policy binding
before releasing any key material (SI-1 in BaseTDF-SEC).

### 5.2 Computation

The policy binding is computed as follows:

```
canonical_policy = encryptionInformation.policy
    (the base64-encoded policy string exactly as it appears in the manifest)

hmac_digest = HMAC-SHA256(key = DEK_share, message = canonical_policy)

policyBinding = {
  "alg": "HS256",
  "hash": Base64(hmac_digest)
}
```

**Detailed procedure**:

1. Obtain the base64-encoded policy string from
   `encryptionInformation.policy`. This is the canonical form of the policy.
   Implementations MUST NOT decode, re-encode, re-serialize, or otherwise
   transform the policy string before computing the HMAC. The exact byte
   sequence of the base64-encoded string is the HMAC message.
2. Compute the HMAC-SHA256 digest using the DEK share as the HMAC key and the
   canonical policy string (as raw bytes of the base64-encoded string) as the
   message.
3. Encode the resulting 32-byte digest as standard Base64 (RFC 4648 Section 4).
4. Store the result in `policyBinding.hash`.
5. Set `policyBinding.alg` to `"HS256"`.

### 5.3 Verification

The KAS MUST verify the policy binding as part of the rewrap operation. The
verification procedure is:

1. After unwrapping the DEK share from the KAO, compute the expected HMAC:
   `expected = HMAC-SHA256(key = DEK_share, message = canonical_policy)`
   where `canonical_policy` is the base64-encoded policy string from the
   rewrap request.
2. Decode the `policyBinding.hash` value from the KAO using Base64.
3. Compare the computed digest with the decoded hash using constant-time
   comparison (e.g., `hmac.Equal` in Go, `crypto.timingSafeEqual` in Node.js).
4. If the comparison fails, the KAS MUST reject the KAO and MUST NOT return
   any key material derived from the corresponding DEK share.

### 5.4 Algorithm Requirements

- `policyBinding.alg` MUST be `"HS256"` (HMAC-SHA256).
- The KAS MUST validate the `policyBinding.alg` field against the set of
  supported binding algorithms before performing verification.
- The KAS MUST reject KAOs whose `policyBinding.alg` specifies an unrecognized
  or unsupported algorithm (SI-6 in BaseTDF-SEC).
- When the policy binding is a bare string (legacy format without an `alg`
  field), the binding algorithm MUST default to HMAC-SHA256.

### 5.5 Legacy Policy Binding Formats

In v4.3.0 and earlier, the policy binding hash was computed using a
hex-then-base64 encoding:

```
hmac_digest = HMAC-SHA256(DEK_share, canonical_policy)
hex_string  = hex.Encode(hmac_digest)        // 64 ASCII hex characters
legacy_hash = Base64(hex_string)             // Base64 of the hex string
```

Additionally, the policy binding could be expressed as either:

- An object: `{ "alg": "HS256", "hash": "<value>" }`
- A bare string: `"<value>"` (the hash value directly)

KAS implementations MUST support both formats when reading KAOs:

1. Decode the `policyBinding.hash` (or bare string) from Base64.
2. If the decoded result is 64 bytes and consists entirely of valid hexadecimal
   ASCII characters (`0-9`, `a-f`, `A-F`), treat it as hex-encoded and decode
   again to obtain the 32-byte HMAC digest.
3. If the decoded result is 32 bytes, treat it as the raw HMAC digest directly.
4. Compare using constant-time comparison.

When writing new v4.4.0 KAOs, implementations MUST use direct Base64 encoding
(not hex-then-base64) and MUST use the object form with an explicit `alg` field.

---

## 6. Encrypted Metadata

### 6.1 Purpose

The `encryptedMetadata` field provides an OPTIONAL mechanism for the TDF creator
to attach freeform metadata to a KAO that is only readable by the KAS. This
metadata is encrypted with the DEK share, ensuring it is only accessible after
the KAS has unwrapped the key.

### 6.2 Structure

The encrypted metadata is a Base64-encoded JSON structure:

```json
{
  "ciphertext": "<base64-encoded AES-256-GCM ciphertext>",
  "iv": "<base64-encoded initialization vector>"
}
```

This JSON structure is itself Base64-encoded to produce the value stored in the
`encryptedMetadata` field of the KAO.

### 6.3 Encryption Procedure

1. Serialize the metadata as a JSON string: `plaintext = JSON.stringify(metadata)`.
2. Generate a 12-byte random IV using a CSPRNG.
3. Encrypt: `ciphertext = AES-256-GCM(key = DEK_share, iv = IV, plaintext)`.
   The ciphertext includes the GCM authentication tag.
4. Construct the encrypted metadata JSON object with the Base64-encoded
   ciphertext and IV.
5. Base64-encode the entire JSON object.
6. Store the result in the KAO `encryptedMetadata` field.

### 6.4 Security Requirements

- The KAS MUST NOT decrypt or process `encryptedMetadata` before successful
  policy binding verification (SI-1 in BaseTDF-SEC) and authorization
  (SI-2 in BaseTDF-SEC).
- The contents of `encryptedMetadata` are freeform JSON. Implementations MUST
  treat decrypted metadata as untrusted input subject to validation.
- The contents of `encryptedMetadata` MUST NOT be used for access control
  decisions. Access control is determined solely by the policy object and
  the authorization service.

---

## 7. Backward Compatibility

### 7.1 Reading v4.3.0 KAOs

When reading a KAO that was created under v4.3.0 or earlier, implementations
MUST apply the following transformations:

| v4.3.0 Field / Value | v4.4.0 Interpretation |
|:----------------------|:----------------------|
| `type: "wrapped"` | Infer `alg: "RSA-OAEP"` |
| `type: "ec-wrapped"` | Infer `alg: "ECDH-HKDF"` |
| `wrappedKey` | Treat as `protectedKey` |
| `url` | Treat as `kas` |
| `ephemeralPublicKey` | Treat as `ephemeralKey` |
| `policyBinding` as bare string | Treat as `{ "alg": "HS256", "hash": "<value>" }` |
| Policy binding in hex-then-base64 | Decode hex after base64 to recover raw HMAC (see Section 5.5) |

When a KAO contains a `type` field but no `alg` field, the type-to-algorithm
mapping in the table above is the sole mechanism for determining the algorithm.
These mappings are exhaustive for all v4.3.0 KAOs.

When reading v4.3.0 TDFs, the `ECDH-HKDF` algorithm uses XOR-based wrapping
(not AES-256-GCM). Implementations MUST support XOR-based unwrapping for
backward compatibility.

### 7.2 Writing v4.4.0 KAOs

When creating new KAOs, implementations MUST observe the following:

1. MUST include the `alg` field with a valid algorithm identifier from
   BaseTDF-ALG.
2. SHOULD include the `type` field for backward compatibility with older readers
   that do not recognize `alg`. If included, the `type` value MUST be consistent
   with the `alg` value:
   - `alg: "RSA-OAEP"` or `alg: "RSA-OAEP-256"` -> `type: "wrapped"`
   - `alg: "ECDH-HKDF"` -> `type: "ec-wrapped"`
   - All other `alg` values have no `type` equivalent; `type` SHOULD be omitted.
3. MUST use `protectedKey` as the field name. MAY additionally include
   `wrappedKey` as an alias with the same value for backward compatibility.
4. MUST use `kas` as the KAS URL field name. MAY additionally include `url`
   with the same value for backward compatibility.
5. MUST use the object form for `policyBinding` with explicit `alg` and `hash`
   fields.
6. MUST use direct Base64 encoding for the policy binding hash (not
   hex-then-base64).
7. MUST include the `kid` field.
8. MUST include the `sid` field when key splitting is used.

### 7.3 Version Detection

Implementations MAY use the following heuristics to determine the KAO version:

- Presence of `alg` field: v4.4.0 or later.
- Presence of `type` field without `alg`: v4.3.0 or earlier.
- Manifest-level `schemaVersion` field: versions below `"4.3.0"` use
  hex-then-base64 encoding for integrity hashes and policy bindings.

---

## 8. Security Considerations

### 8.1 Policy Binding Integrity (SI-1)

The policy binding is the primary mechanism preventing policy tampering. An
adversary who modifies the base64-encoded policy in the manifest cannot
recompute a valid HMAC without knowledge of the DEK share, which is protected by
the KAS public key. The KAS MUST verify the binding before any key release.
Failure to verify the policy binding allows an adversary to substitute arbitrary
policies on existing TDFs. See BaseTDF-SEC Section 5, SI-1.

### 8.2 Algorithm Validation (SI-6)

The KAS MUST reject KAOs with unrecognized `alg` or `policyBinding.alg` values.
Accepting unknown algorithms could lead to downgrade attacks, where an adversary
substitutes a weak or broken algorithm. The algorithm registry in BaseTDF-ALG is
the authoritative source for valid identifiers. See BaseTDF-SEC Section 5, SI-6.

### 8.3 Key Material Hygiene (SI-7)

DEK shares MUST be securely erased from memory after use, on both the client and
KAS side. Specifically:

- After the KAS verifies the policy binding and re-encrypts the DEK share to
  the client's ephemeral public key, the plaintext DEK share MUST be erased
  from KAS memory.
- After the client reconstructs the DEK from its shares, all individual shares
  MUST be erased from client memory.
- After decryption is complete, the reconstructed DEK MUST be erased from
  client memory.

See BaseTDF-SEC Section 5, SI-7.

### 8.4 Key Splitting Security

XOR-based n-of-n secret sharing provides information-theoretic security:
knowledge of any proper subset of shares reveals no information about the DEK.
However, this guarantee depends on each share being generated from a CSPRNG
with full entropy. Implementations MUST NOT use deterministic or low-entropy
sources for share generation.

### 8.5 KAO Substitution

An adversary who replaces a KAO in the manifest with one they created faces
the following constraints:

- If the adversary wraps to their own KAS, the legitimate KAS will not have the
  corresponding private key and cannot unwrap.
- If the adversary wraps a different key to the legitimate KAS, the policy
  binding will fail verification because the HMAC was computed with a different
  DEK share.
- If the adversary wraps a different key and recomputes the policy binding, the
  DEK reconstructed from the modified share will not match the DEK used to
  encrypt the payload, and decryption will fail or produce garbage.

### 8.6 Cross-TDF Replay

Each KAO's policy binding is computed using the specific DEK share and the
specific policy of the TDF it belongs to. Transplanting a KAO from one TDF to
another will fail policy binding verification because the target TDF has a
different policy and potentially different DEK shares.

---

## 9. Normative References

| Reference | Title |
|---|---|
| [BaseTDF-SEC][BaseTDF-SEC] | Security Model and Zero Trust Architecture, v4.4.0 |
| [BaseTDF-ALG][BaseTDF-ALG] | Algorithm Registry, v4.4.0 |
| [NIST FIPS 203][FIPS203] | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) |
| [NIST SP 800-38D][SP800-38D] | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC |
| [NIST SP 800-56A][SP800-56A] | Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography |
| [RFC 2104][RFC2104] | HMAC: Keyed-Hashing for Message Authentication |
| [RFC 2119][RFC2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 4648][RFC4648] | The Base16, Base32, and Base64 Data Encodings |
| [RFC 5869][RFC5869] | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| [RFC 8017][RFC8017] | PKCS #1: RSA Cryptography Specifications Version 2.2 |
| [RFC 8174][RFC8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |

[BaseTDF-SEC]: basetdf-sec.md
[BaseTDF-ALG]: basetdf-alg.md
[FIPS203]: https://doi.org/10.6028/NIST.FIPS.203
[SP800-38D]: https://doi.org/10.6028/NIST.SP.800-38D
[SP800-56A]: https://doi.org/10.6028/NIST.SP.800-56Ar3
[RFC2104]: https://www.rfc-editor.org/rfc/rfc2104
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC5869]: https://www.rfc-editor.org/rfc/rfc5869
[RFC8017]: https://www.rfc-editor.org/rfc/rfc8017
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
