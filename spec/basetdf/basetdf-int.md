# BaseTDF-INT: Integrity Verification

| | |
|---|---|
| **Document** | BaseTDF-INT |
| **Title** | Integrity Verification |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG |
| **Referenced by** | BaseTDF-CORE, BaseTDF-ASN |

## Table of Contents

1. [Introduction](#1-introduction)
2. [Segment Model](#2-segment-model)
3. [Integrity Information Schema](#3-integrity-information-schema)
4. [Segment Hash Computation](#4-segment-hash-computation)
5. [Root Signature Computation](#5-root-signature-computation)
6. [Segment Size Accounting](#6-segment-size-accounting)
7. [Verification Procedure](#7-verification-procedure)
8. [Legacy TDF Handling](#8-legacy-tdf-handling)
9. [Security Considerations](#9-security-considerations)
10. [Normative References](#10-normative-references)

---

## 1. Introduction

### 1.1 Purpose

This document defines the integrity verification model for the Trusted Data
Format (TDF) payload. It specifies how per-segment hashes and a whole-payload
root signature are computed, stored, and verified, ensuring that any
modification to the encrypted payload is detected before plaintext is released
to the application.

### 1.2 Design Rationale

The integrity model provides two complementary layers of verification:

- **Per-segment hashes** enable streaming verification: each segment's
  integrity can be checked immediately after decryption, without waiting for
  the entire payload to be processed.
- **A root signature** binds the entire sequence of segment hashes into a
  single authenticator, providing whole-payload integrity and ensuring that
  segments cannot be reordered, omitted, or duplicated without detection.

Together, these layers allow implementations to support both streaming and
non-streaming consumption patterns while satisfying the security invariant
SI-5 (Payload Integrity Verification) from [BaseTDF-SEC][basetdf-sec].

### 1.3 Stability Note

The integrity model is largely unchanged from TDF v4.3.0. The segment hash and
root signature constructions, algorithm choices, and verification procedure
described in this document are fully backward-compatible with TDFs produced by
v4.3.0 implementations. The only change is the encoding of hash values (see
[Section 8](#8-legacy-tdf-handling)).

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][rfc2119]
[RFC 8174][rfc8174] when, and only when, they appear in ALL CAPITALS, as shown
here.

---

## 2. Segment Model

### 2.1 Segmentation

Before encryption, the plaintext payload is divided into a sequence of
fixed-size **segments**. Each segment is independently encrypted using
AES-256-GCM (see [BaseTDF-ALG][basetdf-alg] Section 3.1) with the Data
Encryption Key (DEK) as the symmetric key.

The segmentation procedure is as follows:

1. Let `P` be the plaintext payload of length `L` bytes.
2. Let `S` be the configured segment size in bytes (the `segmentSizeDefault`
   value).
3. The payload is divided into `ceil(L / S)` segments, where segments
   `0` through `N-2` are exactly `S` bytes, and the final segment `N-1`
   contains the remaining `L mod S` bytes (which MAY be less than `S`).
4. If `L` is zero, a single empty segment MUST still be produced.

### 2.2 Segment Encryption

Each plaintext segment is encrypted independently:

```
encrypted_segment_i = AES-256-GCM-Encrypt(DEK, IV_i, plaintext_segment_i)
```

The encrypted segment output consists of the concatenation:

```
IV (12 bytes) || ciphertext || authentication tag (16 bytes)
```

Each segment MUST use a unique initialization vector (IV). See
[BaseTDF-ALG][basetdf-alg] Section 3.1 and [BaseTDF-SEC][basetdf-sec]
Section 6.6 for IV uniqueness requirements.

### 2.3 Segment Ordering

Segments MUST be stored in the payload in the same order as the plaintext
from which they were produced. The `segments` array in the integrity
information MUST list segment metadata in the same order. Implementations
MUST NOT reorder segments during creation or verification.

---

## 3. Integrity Information Schema

The `integrityInformation` object is carried within the
`encryptionInformation` section of the TDF manifest (see BaseTDF-CORE). It
contains the root signature, the segment hash algorithm, default segment
sizes, and the per-segment metadata array.

### 3.1 Schema Definition

```json
{
  "rootSignature": {
    "alg": "<string: algorithm identifier>",
    "sig": "<string: base64-encoded root signature>"
  },
  "segmentHashAlg": "<string: algorithm identifier>",
  "segmentSizeDefault": "<integer: default plaintext segment size in bytes>",
  "encryptedSegmentSizeDefault": "<integer: default encrypted segment size in bytes>",
  "segments": [
    {
      "hash": "<string: base64-encoded segment hash>",
      "segmentSize": "<integer: plaintext size of this segment in bytes>",
      "encryptedSegmentSize": "<integer: encrypted size of this segment in bytes>"
    }
  ]
}
```

### 3.2 Field Definitions

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `rootSignature` | object | REQUIRED | The whole-payload root signature (see [Section 5](#5-root-signature-computation)). |
| `rootSignature.alg` | string | REQUIRED | Algorithm identifier for the root signature. MUST be a value from the Integrity MAC Algorithms table in [BaseTDF-ALG][basetdf-alg] Section 3.3. |
| `rootSignature.sig` | string | REQUIRED | The base64-encoded root signature value. |
| `segmentHashAlg` | string | REQUIRED | Algorithm identifier for per-segment hashing. MUST be a value from the Integrity MAC Algorithms table in [BaseTDF-ALG][basetdf-alg] Section 3.3. |
| `segmentSizeDefault` | integer | REQUIRED | Default plaintext segment size in bytes. |
| `encryptedSegmentSizeDefault` | integer | REQUIRED | Default encrypted segment size in bytes (see [Section 6](#6-segment-size-accounting)). |
| `segments` | array | REQUIRED | Ordered array of per-segment metadata. MUST contain one entry for each segment in the payload. |
| `segments[i].hash` | string | REQUIRED | Base64-encoded hash of the encrypted segment (see [Section 4](#4-segment-hash-computation)). |
| `segments[i].segmentSize` | integer | REQUIRED | Plaintext size of this segment in bytes. |
| `segments[i].encryptedSegmentSize` | integer | REQUIRED | Encrypted size of this segment in bytes. |

### 3.3 Algorithm Identifier Values

The `rootSignature.alg` and `segmentHashAlg` fields MUST contain one of the
following values, as defined in [BaseTDF-ALG][basetdf-alg] Section 3.3:

| Identifier | Algorithm | Output Size | Status |
|:-----------|:----------|:------------|:-------|
| `HS256` | HMAC-SHA256 | 256 bits (32 bytes) | REQUIRED |
| `GMAC` | AES-256-GMAC | 128 bits (16 bytes) | OPTIONAL |

Implementations MUST support `HS256`. Implementations MAY support `GMAC`.

---

## 4. Segment Hash Computation

For each encrypted segment, a hash value is computed and stored in the
corresponding `segments[i].hash` field. The computation depends on the
algorithm specified in `segmentHashAlg`.

### 4.1 HS256 (HMAC-SHA256)

When `segmentHashAlg` is `"HS256"`:

```
hash_i = HMAC-SHA256(key = DEK, message = encrypted_segment_i)
```

Where:

- `DEK` is the reconstructed Data Encryption Key (256 bits).
- `encrypted_segment_i` is the complete encrypted segment bytes, including
  the IV prefix and the GCM authentication tag suffix.
- The output is 256 bits (32 bytes).

The hash is base64-encoded and stored in `segments[i].hash`.

### 4.2 GMAC

When `segmentHashAlg` is `"GMAC"`:

```
hash_i = encrypted_segment_i[len - 16 : len]
```

Where:

- `encrypted_segment_i` is the complete encrypted segment bytes.
- The hash is the final 16 bytes of the encrypted segment, which is the
  AES-GCM authentication tag produced during encryption.
- The output is 128 bits (16 bytes).

The hash is base64-encoded and stored in `segments[i].hash`.

**Implementation note**: When GMAC is selected as the segment hash algorithm,
no additional computation is needed beyond what AES-256-GCM encryption already
produces. The GCM authentication tag, which is appended to each encrypted
segment, serves directly as the segment hash. This makes GMAC segment hashing
computationally free at encryption time.

### 4.3 Minimum Data Length for GMAC

When `segmentHashAlg` is `"GMAC"`, the encrypted segment MUST be at least 16
bytes long (the size of a GCM authentication tag). If the encrypted segment is
shorter than 16 bytes, the implementation MUST treat this as an error and abort
processing. In practice, this condition cannot arise for valid TDF segments
because even an empty plaintext segment produces an encrypted segment of at
least 28 bytes (12-byte IV + 16-byte tag).

---

## 5. Root Signature Computation

The root signature provides whole-payload integrity by binding all segment
hashes into a single authenticator. It is stored in the `rootSignature` object.

### 5.1 Aggregate Hash Construction

The aggregate hash is constructed by concatenating the **raw** (decoded) segment
hashes in order:

```
aggregate_hash = hash_0 || hash_1 || ... || hash_{N-1}
```

Where each `hash_i` is the raw byte value of the segment hash (as computed in
[Section 4](#4-segment-hash-computation)), NOT the base64-encoded string stored
in the manifest.

Specifically, to construct the aggregate hash during verification:

1. For each segment `i`, base64-decode the `segments[i].hash` field to obtain
   the raw hash bytes.
2. Concatenate all decoded hash byte sequences in segment order.

### 5.2 Signature Computation

The root signature is computed over the aggregate hash using the algorithm
specified in `rootSignature.alg`.

#### 5.2.1 HS256 (HMAC-SHA256)

When `rootSignature.alg` is `"HS256"`:

```
root_sig = HMAC-SHA256(key = DEK, message = aggregate_hash)
```

The result is 256 bits (32 bytes). It is base64-encoded and stored in
`rootSignature.sig`.

#### 5.2.2 GMAC

When `rootSignature.alg` is `"GMAC"`:

```
root_sig = aggregate_hash[len - 16 : len]
```

The root signature is the final 16 bytes of the aggregate hash. The result is
128 bits (16 bytes). It is base64-encoded and stored in `rootSignature.sig`.

**Note**: GMAC for the root signature is computed over the aggregate hash
(a concatenation of segment hashes), not over a GCM-encrypted ciphertext. The
implementation extracts the final 16 bytes of the aggregate hash as the
signature value, consistent with the GMAC extraction pattern used for segment
hashes.

### 5.3 Default Configuration

The reference implementation uses the following defaults:

| Setting | Default Value |
|:--------|:--------------|
| Root signature algorithm (`rootSignature.alg`) | `HS256` |
| Segment hash algorithm (`segmentHashAlg`) | `GMAC` |

Implementations MAY use different defaults. The algorithms used for any
particular TDF are always recorded explicitly in the manifest and MUST be
honored during verification regardless of the implementation's defaults.

---

## 6. Segment Size Accounting

### 6.1 Default Sizes

The `segmentSizeDefault` and `encryptedSegmentSizeDefault` fields record the
default plaintext and encrypted segment sizes, respectively.

The relationship between these two values is:

```
encryptedSegmentSizeDefault = segmentSizeDefault + GCM_OVERHEAD
```

Where `GCM_OVERHEAD` is the sum of the AES-GCM IV size and the authentication
tag size:

```
GCM_OVERHEAD = IV_SIZE + TAG_SIZE = 12 + 16 = 28 bytes
```

| Component | Size | Description |
|:----------|:-----|:------------|
| IV (nonce) | 12 bytes (96 bits) | AES-GCM initialization vector |
| Authentication tag | 16 bytes (128 bits) | AES-GCM authentication tag |
| **GCM overhead** | **28 bytes** | **Total overhead per segment** |

Implementations MUST verify during decryption that the relationship
`segmentSizeDefault + 28 == encryptedSegmentSizeDefault` holds. If this
invariant is violated, the implementation MUST reject the TDF.

### 6.2 Per-Segment Size Overrides

Each entry in the `segments` array contains `segmentSize` and
`encryptedSegmentSize` fields. These fields specify the actual sizes for that
particular segment.

- For all segments except the last, `segmentSize` SHOULD equal
  `segmentSizeDefault` and `encryptedSegmentSize` SHOULD equal
  `encryptedSegmentSizeDefault`.
- The last segment MAY have a smaller `segmentSize` if the plaintext payload
  length is not evenly divisible by the default segment size.
- For any segment, the relationship
  `encryptedSegmentSize = segmentSize + 28` MUST hold.

### 6.3 Configurable Segment Sizes

The default segment size is configurable at TDF creation time. The reference
implementation uses a default of 2,097,152 bytes (2 MiB). Implementations
SHOULD support segment sizes in the following range:

| Parameter | Value |
|:----------|:------|
| Minimum segment size | 16,384 bytes (16 KiB) |
| Default segment size | 2,097,152 bytes (2 MiB) |
| Maximum segment size | 4,194,304 bytes (4 MiB) |

Implementations MAY support segment sizes outside this range. The chosen
segment size is recorded in the manifest and MUST be honored during
verification.

---

## 7. Verification Procedure

This section defines the normative verification procedure that implementations
MUST follow when decrypting a TDF payload.

### 7.1 Full Verification (Non-Streaming)

For non-streaming decryption, the implementation MUST perform the following
steps in order:

1. **Reconstruct the DEK** from the rewrapped key shares (see BaseTDF-KAO).

2. **Verify the root signature**:
   a. For each segment `i` in order, base64-decode `segments[i].hash` to
      obtain the raw hash bytes.
   b. Concatenate all decoded segment hashes to form the `aggregate_hash`.
   c. Compute the expected root signature over `aggregate_hash` using the
      algorithm specified in `rootSignature.alg` and the DEK as the key
      (see [Section 5](#5-root-signature-computation)).
   d. Compare the computed root signature with the base64-decoded value
      of `rootSignature.sig`.
   e. If the comparison fails, the implementation MUST abort and MUST NOT
      decrypt any segment data.

3. **Verify and decrypt each segment**:
   For each segment `i` in order:
   a. Read `segments[i].encryptedSegmentSize` bytes of encrypted data from
      the payload at the appropriate offset.
   b. Compute the segment hash per [Section 4](#4-segment-hash-computation)
      using the algorithm specified in `segmentHashAlg`.
   c. Compare the computed hash with the base64-decoded value of
      `segments[i].hash`.
   d. If the comparison fails, the implementation MUST abort and MUST
      discard ALL previously decrypted data.
   e. Decrypt the segment using AES-256-GCM with the DEK.
   f. If GCM decryption fails (authentication tag mismatch), the
      implementation MUST abort and MUST discard ALL previously decrypted
      data.

4. **Return the plaintext** only after all segments have been verified and
   decrypted successfully.

### 7.2 Streaming Verification

For streaming decryption, where decrypted data is released to the application
incrementally as segments are processed, the implementation MUST perform the
following steps:

1. **Reconstruct the DEK** from the rewrapped key shares.

2. **Verify the root signature before decryption**:
   a. Construct the `aggregate_hash` from the segment hashes recorded in
      the manifest (base64-decode and concatenate).
   b. Compute and verify the root signature as described in
      [Section 7.1](#71-full-verification-non-streaming), step 2.
   c. If the root signature fails, the implementation MUST abort and MUST
      NOT decrypt any segment data.

3. **Verify and decrypt each segment incrementally**:
   For each segment `i` in order:
   a. Read the encrypted segment data from the payload.
   b. Compute the segment hash per [Section 4](#4-segment-hash-computation).
   c. Compare the computed hash with the expected value from the manifest.
   d. If the comparison fails, the implementation MUST abort immediately
      and MUST signal an integrity failure to the application. Any
      previously released plaintext from earlier segments cannot be
      recalled, but no further plaintext MUST be released.
   e. Decrypt the segment using AES-256-GCM with the DEK.
   f. If GCM decryption fails, the implementation MUST abort immediately.
   g. Release the decrypted plaintext for this segment to the application.

### 7.3 Integrity Failure Handling

When an integrity failure is detected at any point during verification:

1. The implementation MUST immediately stop processing.
2. The implementation MUST NOT return any further plaintext to the application.
3. For non-streaming verification, the implementation MUST securely discard
   ALL decrypted data, as no plaintext has yet been released.
4. For streaming verification, plaintext from previously verified segments
   may have already been released to the application. The implementation MUST
   signal the integrity failure to the application so that it can take
   appropriate action (e.g., discard buffered data, alert the user).
5. The implementation MUST return an error to the caller indicating the nature
   of the failure (segment hash mismatch or root signature mismatch).

These requirements implement [SI-5 (Payload Integrity Verification)][basetdf-sec]
from BaseTDF-SEC.

---

## 8. Legacy TDF Handling

### 8.1 Hash Encoding Change

TDF versions prior to 4.3.0 (identified by the absence of a `schemaVersion`
field in the manifest, or a `schemaVersion` value less than `"4.3.0"`) encode
segment hashes and the root signature differently from v4.3.0 and later.

| TDF Version | Hash Encoding |
|:------------|:--------------|
| Pre-4.3.0 (legacy) | Hex-encoded string, then base64-encoded |
| 4.3.0 and later | Raw bytes, base64-encoded |

### 8.2 Legacy Detection

A TDF is considered "legacy" when the manifest's top-level `schemaVersion`
field is either:

- Absent (empty string or missing), OR
- Present with a semantic version value less than `"4.3.0"`.

### 8.3 Legacy Hash Computation

When computing hashes for a legacy TDF, the `calculateSignature` function
MUST produce a hex-encoded string instead of raw bytes:

**HS256 (legacy)**:

```
hash_i = hexEncode(HMAC-SHA256(key = DEK, message = encrypted_segment_i))
```

The hex-encoded string is then base64-encoded for storage in the manifest.

**GMAC (legacy)**:

```
hash_i = hexEncode(encrypted_segment_i[len - 16 : len])
```

The hex-encoded string is then base64-encoded for storage in the manifest.

### 8.4 Compatibility Requirements

Implementations MUST support both encoding formats:

1. When **reading** a TDF, implementations MUST detect whether the TDF is
   legacy (per Section 8.2) and use the appropriate hash encoding for
   verification.
2. When **creating** a new TDF, implementations MUST include the
   `schemaVersion` field and MUST use the current encoding (raw bytes,
   base64-encoded). Implementations MUST NOT produce legacy-encoded hashes
   in new TDFs.

---

## 9. Security Considerations

### 9.1 Relationship to SI-5

This document provides the detailed procedures that satisfy
[SI-5 (Payload Integrity Verification)][basetdf-sec] from BaseTDF-SEC:

> Clients MUST verify segment hashes and the root signature after decryption.
> Integrity failure MUST abort processing and discard all decrypted data.

All verification requirements in [Section 7](#7-verification-procedure) are
normative and trace directly to SI-5.

### 9.2 Defense Against Payload Tampering

The integrity model defends against payload tampering by an adversary who has
access to the encrypted TDF but does not possess the DEK:

- **Ciphertext modification**: Any modification to an encrypted segment will
  be detected by AES-GCM authentication tag verification during decryption
  AND by the segment hash comparison. These are independent checks: the GCM
  tag is verified by the decryption primitive, while the segment hash is
  verified by the integrity layer.

- **Segment reordering**: Reordering segments in the payload will cause
  segment hash mismatches (each hash is bound to a specific segment's
  ciphertext). Even if an adversary also reorders the `segments` array in
  the manifest, the root signature will detect the change because it is
  computed over the concatenation of segment hashes in their original order.

- **Segment omission or duplication**: Adding or removing segments changes
  the set of segment hashes that contribute to the root signature, causing
  root signature verification to fail.

- **Segment truncation**: Modifying the size fields in the `segments` array
  to truncate a segment will cause either a read error (insufficient data)
  or a hash mismatch (the hash was computed over the full segment).

### 9.3 Limitations

- **GMAC collision resistance**: GMAC produces a 128-bit tag. For applications
  requiring stronger collision resistance, `HS256` (256-bit output) SHOULD be
  used for both segment hashing and the root signature.

- **Root signature timing for streaming**: In streaming mode, the root
  signature is verified before decryption begins (using the hashes stored in
  the manifest), but segment hash verification still occurs incrementally.
  If an adversary modifies both the payload and the corresponding hash in the
  manifest, the root signature check will catch this. However, if an adversary
  can modify the root signature as well (which requires knowledge of the DEK),
  the integrity model is defeated. This is by design: the DEK is the root of
  trust for payload integrity.

- **No constant-time comparison requirement for hashes**: Unlike policy binding
  verification (SI-1), segment hash comparison does not require constant-time
  comparison. The segment hashes are not secret values; they are stored in the
  cleartext manifest. Timing side channels on hash comparison do not leak
  information about the DEK.

### 9.4 Quantum Resistance

The integrity algorithms used by BaseTDF are resistant to quantum attacks at
their specified security levels (see [BaseTDF-ALG][basetdf-alg] Section 7):

| Algorithm | Post-Quantum Security |
|:----------|:----------------------|
| `HS256` (HMAC-SHA256) | 128 bits (Grover's bound) |
| `GMAC` (AES-256-GMAC) | 64 bits (Grover's bound) |

Both algorithms remain secure against quantum adversaries. No migration is
required for the integrity layer.

---

## 10. Normative References

| Reference | Title |
|:----------|:------|
| [BaseTDF-SEC][basetdf-sec] | Security Model and Zero Trust Architecture, v4.4.0 |
| [BaseTDF-ALG][basetdf-alg] | Algorithm Registry, v4.4.0 |
| [NIST SP 800-38D][sp800-38d] | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC |
| [RFC 2104][rfc2104] | HMAC: Keyed-Hashing for Message Authentication |
| [RFC 2119][rfc2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 8174][rfc8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |

---

[basetdf-sec]: basetdf-sec.md
[basetdf-alg]: basetdf-alg.md
[sp800-38d]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
[rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174
