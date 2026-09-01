# BaseTDF-CORE: Container Format and Manifest

| | |
|---|---|
| **Document** | BaseTDF-CORE |
| **Title** | Container Format and Manifest |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG, BaseTDF-KAO, BaseTDF-INT, BaseTDF-POL, BaseTDF-ASN |
| **Referenced by** | BaseTDF-EX |

## Table of Contents

1. [Introduction](#1-introduction)
2. [Container Structure](#2-container-structure)
3. [Manifest Schema](#3-manifest-schema)
4. [Payload Object](#4-payload-object)
5. [Encryption Information Object](#5-encryption-information-object)
6. [Version Field](#6-version-field)
7. [End-to-End TDF Creation Flow](#7-end-to-end-tdf-creation-flow)
8. [End-to-End TDF Reading Flow](#8-end-to-end-tdf-reading-flow)
9. [Backward Compatibility](#9-backward-compatibility)
10. [Security Considerations](#10-security-considerations)
11. [Normative References](#11-normative-references)

---

## 1. Introduction

### 1.1 Purpose

This document is the top-level specification of the BaseTDF suite. It defines the
physical container format, the JSON manifest schema, and the end-to-end flows for
creating and reading Trusted Data Format (TDF) objects. Every other document in the
suite defines a component that this document assembles into a complete, interoperable
data protection format.

### 1.2 Scope

BaseTDF-CORE covers:

- The ZIP-based container that packages encrypted payload and metadata together.
- The `0.manifest.json` schema at version 4.4.0, including all top-level and nested
  fields.
- The precise relationship between the manifest and its constituent sub-objects
  defined in companion specifications.
- The normative creation and reading procedures that implementers MUST follow.

BaseTDF-CORE does not define:

- Cryptographic algorithm parameters (see [BaseTDF-ALG](basetdf-alg.md)).
- Key Access Object internals (see [BaseTDF-KAO](basetdf-kao.md)).
- Integrity hash and signature computation (see [BaseTDF-INT](basetdf-int.md)).
- Policy structure and ABAC evaluation (see [BaseTDF-POL](basetdf-pol.md)).
- Assertion binding and signing (see [BaseTDF-ASN](basetdf-asn.md)).
- The Key Access Service wire protocol (see BaseTDF-KAS).
- The security model and threat analysis (see [BaseTDF-SEC](basetdf-sec.md)).

### 1.3 Design Principles

BaseTDF is a **data-centric** protection format: encryption, policy, integrity
proofs, and assertions travel **with** the data. This design ensures that protected
content remains self-describing regardless of the storage or transport system.

The format is built on three principles:

1. **Self-containment** -- A TDF carries everything needed to identify the Key
   Access Services that can authorize decryption, the policy that governs access,
   and the integrity information that proves the payload has not been tampered with.
2. **Separation of concerns** -- The manifest is cleartext JSON, allowing inspection
   of metadata without decryption. The payload is opaque ciphertext.
3. **Streaming support** -- The segmented payload model allows consumers to begin
   processing data before the entire file has been received.

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][rfc2119] [RFC 8174][rfc8174]
when, and only when, they appear in ALL CAPITALS, as shown here.

---

## 2. Container Structure

### 2.1 ZIP Archive

A TDF is a ZIP archive ([APPNOTE 6.3.10][appnote]) containing exactly two entries:

| Entry name | Content | Format |
|---|---|---|
| `0.payload` | Encrypted payload segments | Binary (ciphertext) |
| `0.manifest.json` | Manifest | UTF-8 JSON |

The payload entry MUST appear before the manifest entry in the ZIP central
directory. Writers MUST use this ordering so that streaming readers can process
payload segments before the manifest finalizes the archive.

> **Note:** The `0.` prefix is a legacy convention that ensures deterministic
> ordering. Implementations MUST NOT change these entry names.

### 2.2 Rationale for ZIP

The ZIP format was chosen for the following reasons:

- **Broad tooling compatibility** -- ZIP archives can be inspected with standard
  utilities on every major operating system.
- **Manifest inspection without custom tooling** -- The cleartext JSON manifest
  can be extracted and examined with any ZIP tool.
- **Streaming support** -- ZIP local file headers precede file data, enabling
  progressive reading without seeking to the central directory first.
- **Random access** -- ZIP supports per-entry access, allowing a reader to extract
  the manifest without reading the entire payload.

### 2.3 ZIP Constraints

Implementations MUST observe the following constraints:

- Entries MUST NOT use ZIP encryption (the TDF payload provides its own encryption).
- Compression MUST be set to `STORE` (no compression). The payload is encrypted and
  therefore incompressible; applying compression wastes CPU and may leak information
  about plaintext structure.
- The archive MUST contain exactly the two entries listed above. Implementations
  MUST ignore unknown entries when reading, but MUST NOT add extra entries when
  writing.
- For payloads exceeding 4 GiB (the 32-bit ZIP limit), writers MUST use the
  ZIP64 extended information extra field as defined in [APPNOTE 6.3.10][appnote]
  Section 4.5.3.

---

## 3. Manifest Schema

### 3.1 Complete Manifest Structure (v4.4.0)

The manifest (`0.manifest.json`) is a single JSON object with the following
structure. Detailed field definitions follow in subsequent sections.

```json
{
  "schemaVersion": "4.4.0",
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "mimeType": "application/octet-stream",
    "isEncrypted": true
  },
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "https://kas.example.com",
        "protocol": "kas",
        "wrappedKey": "<base64>",
        "policyBinding": {
          "alg": "HS256",
          "hash": "<base64>"
        },
        "encryptedMetadata": "<base64>",
        "kid": "<uuid>",
        "sid": "<uuid>",
        "schemaVersion": "1.0"
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM",
      "iv": "",
      "isStreamable": true
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "<base64>"
      },
      "segmentHashAlg": "HS256",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "<base64>",
          "segmentSize": 1048576,
          "encryptedSegmentSize": 1048604
        }
      ]
    },
    "policy": "<base64-encoded-policy-JSON>"
  },
  "assertions": [
    {
      "id": "assertion-id",
      "type": "handling",
      "scope": "tdo",
      "appliesToState": "encrypted",
      "statement": {
        "format": "string",
        "value": "<statement content>"
      },
      "binding": {
        "method": "jws",
        "signature": "<signed-token>"
      }
    }
  ]
}
```

### 3.2 Top-Level Field Summary

| Field | Type | Required | Description |
|---|---|---|---|
| `schemaVersion` | string | RECOMMENDED | Semantic version of the TDF specification (Section 6). |
| `payload` | object | REQUIRED | Describes the encrypted payload (Section 4). |
| `encryptionInformation` | object | REQUIRED | Key access, encryption method, integrity, and policy (Section 5). |
| `assertions` | array | OPTIONAL | Verifiable assertions bound to the TDF (see [BaseTDF-ASN](basetdf-asn.md)). |

---

## 4. Payload Object

The `payload` object describes the encrypted content stored in the ZIP archive.

### 4.1 Field Definitions

| Field | Type | Required | Value / Description |
|---|---|---|---|
| `type` | string | REQUIRED | MUST be `"reference"`. Indicates the payload is stored as a reference within the container. |
| `url` | string | REQUIRED | MUST be `"0.payload"`. The entry name within the ZIP archive that holds the encrypted content. |
| `protocol` | string | REQUIRED | MUST be `"zip"`. Identifies the container protocol used for payload storage. |
| `mimeType` | string | OPTIONAL | MIME type of the **original plaintext** before encryption. Default: `"application/octet-stream"`. Writers SHOULD set this to the actual content type when known. |
| `isEncrypted` | boolean | REQUIRED | MUST be `true` for TDF payloads. Indicates the payload content is encrypted. |

### 4.2 Example

```json
{
  "type": "reference",
  "url": "0.payload",
  "protocol": "zip",
  "mimeType": "text/plain",
  "isEncrypted": true
}
```

---

## 5. Encryption Information Object

The `encryptionInformation` object is the central structure of the manifest. It
binds together key access, content encryption method, integrity verification, and
policy.

### 5.1 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | MUST be `"split"`. Identifies the key access protocol type. In split mode, the Data Encryption Key (DEK) is XOR-split across one or more Key Access Objects. |
| `keyAccess` | array of objects | REQUIRED | One or more Key Access Objects (KAOs) used to retrieve key shares from Key Access Services. See [BaseTDF-KAO](basetdf-kao.md) for the full KAO schema. |
| `method` | object | REQUIRED | Content encryption method (Section 5.2). |
| `integrityInformation` | object | REQUIRED | Payload integrity hashes and root signature. See [BaseTDF-INT](basetdf-int.md) for computation details. Summarized in Section 5.3. |
| `policy` | string | REQUIRED | Base64-encoded JSON policy object. See [BaseTDF-POL](basetdf-pol.md) for the policy schema and ABAC evaluation semantics. |

### 5.2 Method Object

The `method` object specifies the symmetric algorithm and mode used to encrypt the
payload.

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | REQUIRED | Algorithm identifier for content encryption. MUST be a registered content encryption algorithm from [BaseTDF-ALG](basetdf-alg.md). Current value: `"AES-256-GCM"`. |
| `iv` | string | REQUIRED | Base64-encoded initialization vector. For AES-256-GCM with segmented payloads, this field is present but MAY be empty (`""`), since each segment carries its own IV prepended to the ciphertext. |
| `isStreamable` | boolean | REQUIRED | MUST be `true`. Indicates that the payload is encrypted in segments supporting streaming decryption. |

### 5.3 Integrity Information Object

The `integrityInformation` object provides the data needed to verify that the
payload has not been modified. The normative computation procedures are defined
in [BaseTDF-INT](basetdf-int.md); this section defines the schema.

| Field | Type | Required | Description |
|---|---|---|---|
| `rootSignature` | object | REQUIRED | The aggregate signature over all segment hashes. |
| `rootSignature.alg` | string | REQUIRED | Algorithm used for the root signature. MUST be a registered integrity algorithm from [BaseTDF-ALG](basetdf-alg.md). Values: `"HS256"` (HMAC-SHA-256) or `"GMAC"`. See [BaseTDF-INT Section 5](basetdf-int.md#5-root-signature-computation). |
| `rootSignature.sig` | string | REQUIRED | Base64-encoded root signature value. |
| `segmentHashAlg` | string | REQUIRED | Algorithm used to hash individual segments. Values: `"HS256"` or `"GMAC"`. See [BaseTDF-INT Section 4](basetdf-int.md#4-segment-hash-computation). |
| `segmentSizeDefault` | integer | REQUIRED | Default plaintext segment size in bytes (before encryption). |
| `encryptedSegmentSizeDefault` | integer | REQUIRED | Default encrypted segment size in bytes (after encryption). For AES-256-GCM this equals `segmentSizeDefault + 12 (IV) + 16 (authentication tag)`. |
| `segments` | array of objects | REQUIRED | Ordered array of per-segment integrity records. |

Each element of the `segments` array:

| Field | Type | Required | Description |
|---|---|---|---|
| `hash` | string | REQUIRED | Base64-encoded hash of the encrypted segment, computed with the algorithm specified by `segmentHashAlg`. |
| `segmentSize` | integer | OPTIONAL | Plaintext size of this segment. REQUIRED only when it differs from `segmentSizeDefault` (typically the last segment). |
| `encryptedSegmentSize` | integer | REQUIRED | Encrypted size of this segment in bytes. |

### 5.4 Key Access Objects (Summary)

Each entry in the `keyAccess` array is a Key Access Object as defined in
[BaseTDF-KAO](basetdf-kao.md). The following fields are used at the manifest level:

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | KAO type: `"wrapped"` (RSA key wrapping) or `"ec-wrapped"` (ECDH + AES key wrapping). |
| `url` | string | REQUIRED | Fully qualified URL of the Key Access Service (KAS) responsible for this key share. |
| `protocol` | string | REQUIRED | MUST be `"kas"`. |
| `wrappedKey` | string | REQUIRED | Base64-encoded symmetric key share, encrypted with the KAS public key. |
| `policyBinding` | string or object | REQUIRED | Binds this key share to the policy. See [BaseTDF-KAO Section 5](basetdf-kao.md#5-policy-binding). When an object, contains `alg` and `hash` fields. When a string, represents a legacy hash using HS256. |
| `kid` | string | RECOMMENDED | UUID identifying the specific KAS key pair used for wrapping. |
| `sid` | string | REQUIRED | Split identifier. Groups KAOs that share the same key split. Multiple KAOs with the same `sid` represent alternative paths to the same key share (key redundancy). |
| `schemaVersion` | string | OPTIONAL | Version of the KAO schema. Current value: `"1.0"`. |
| `encryptedMetadata` | string | OPTIONAL | Base64-encoded encrypted metadata associated with the TDF. See [BaseTDF-KAO Section 6](basetdf-kao.md#6-encrypted-metadata). |
| `ephemeralPublicKey` | string | CONDITIONAL | REQUIRED when `type` is `"ec-wrapped"`. The client ephemeral public key in PEM format used for ECDH key derivation. |

### 5.5 Assertions (Summary)

Each entry in the `assertions` array is an Assertion object as defined in
[BaseTDF-ASN](basetdf-asn.md). Assertions provide verifiable metadata about the
TDF or its payload. The following fields appear in the manifest:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | REQUIRED | Unique identifier for the assertion within this TDF. |
| `type` | string | REQUIRED | Assertion type: `"handling"` or `"other"`. |
| `scope` | string | REQUIRED | Scope of the assertion: `"tdo"` (the entire TDF object) or `"payload"`. |
| `appliesToState` | string | REQUIRED | Whether the statement applies to `"encrypted"` or `"unencrypted"` data. |
| `statement` | object | REQUIRED | The assertion statement content. Contains `format` (string) and `value` (string or object). See [BaseTDF-ASN Section 3](basetdf-asn.md#3-statement-object). |
| `binding` | object | OPTIONAL | Cryptographic binding of the assertion to the TDF. Contains `method` (default `"jws"`) and `signature`. See [BaseTDF-ASN Section 5](basetdf-asn.md#5-binding-mechanism). |

---

## 6. Version Field

### 6.1 Schema Version

The `schemaVersion` field at the top level of the manifest records the version of
the TDF specification that the writer conformed to when creating the TDF.

- **JSON field name**: `schemaVersion`
- **Type**: string (semantic version, e.g., `"4.4.0"`)
- **Location**: Top-level property of the manifest object.

> **Implementation note:** In the reference Go SDK, the `Manifest` struct maps this
> field with the JSON tag `"schemaVersion"` (see the `TDFVersion` field in
> `manifest.go`). The current SDK writes `"4.3.0"` as the `TDFSpecVersion` constant;
> implementations conforming to this specification MUST write `"4.4.0"` for new TDFs.

### 6.2 Version Rules

Writers:

- Writers conforming to this specification MUST set `schemaVersion` to `"4.4.0"`.
- Writers SHOULD NOT omit the `schemaVersion` field. Omission is permitted only for
  backward compatibility with pre-4.3.0 consumers that cannot tolerate the field.

Readers:

- Readers MUST accept manifests with `schemaVersion` values of `"4.3.x"` and
  `"4.4.x"` (where `x` is any patch version).
- Readers SHOULD accept manifests where `schemaVersion` is absent and treat them
  as pre-4.3.0 TDFs (see Section 9).
- Readers MUST reject manifests with a `schemaVersion` major version other than `4`,
  as this indicates a breaking change in the format.

### 6.3 Version 4.4.0 Changes from 4.3.0

Version 4.4.0 is a **backward-compatible** minor version bump. Changes include:

- Introduction of the `alg` field in `policyBinding` objects within KAOs (structured
  policy binding). The presence of a structured `policyBinding` object (with `alg`
  and `hash` fields) indicates a v4.4.0+ TDF.
- Addition of the `kid` field in KAOs for explicit key identification.
- Support for EC-wrapped key types alongside RSA-wrapped keys.
- Formal specification of the assertions mechanism.
- Registration of post-quantum cryptographic algorithms in [BaseTDF-ALG](basetdf-alg.md).

---

## 7. End-to-End TDF Creation Flow

This section describes the normative procedure for creating a TDF. Each step
references the relevant specification for detailed requirements.

### 7.1 Preparation

1. **Obtain plaintext** -- Read the input data and determine its MIME type.
2. **Determine segment size** -- Select a default segment size (implementation-
   defined; the reference SDK uses 1 MiB = 1,048,576 bytes). The segment size
   MUST NOT exceed implementation-defined limits.

### 7.2 Key Generation and Policy

3. **Generate the Data Encryption Key (DEK)** -- Generate a 256-bit (32-byte)
   cryptographically random key. This is the payload encryption key. See
   [BaseTDF-SEC Section 7.1](basetdf-sec.md#7-key-lifecycle) for key generation
   requirements.

4. **Create the policy object** -- Construct the policy JSON object containing
   a UUID, data attributes, and dissemination list. See
   [BaseTDF-POL Section 2](basetdf-pol.md#2-policy-object-schema).

5. **Determine key splits** -- Based on the policy and KAS configuration, determine
   how to split the DEK. For each split, generate a random 256-bit symmetric key
   share. The DEK is reconstructed by XOR-combining all shares. See
   [BaseTDF-KAO Section 3](basetdf-kao.md#3-key-splitting).

### 7.3 Key Access Object Construction

6. **For each key share, create a KAO** -- For each KAS that will hold a share:
   a. Obtain the KAS public key (RSA or EC, identified by `kid`).
   b. Encrypt the symmetric key share with the KAS public key using the appropriate
      algorithm (`"wrapped"` for RSA, `"ec-wrapped"` for EC). See
      [BaseTDF-KAO Section 4](basetdf-kao.md#4-algorithm-specific-operations) and
      [BaseTDF-ALG](basetdf-alg.md).
   c. Compute the policy binding for the share. See
      [BaseTDF-KAO Section 5](basetdf-kao.md#5-policy-binding).
   d. Optionally encrypt metadata with the share key.
   e. Assemble the KAO with `type`, `url`, `protocol`, `wrappedKey`,
      `policyBinding`, `kid`, `sid`, and optional fields.

### 7.4 Payload Encryption and Integrity

7. **Segment and encrypt the payload** -- Divide the plaintext into segments of
   the configured size. Encrypt each segment independently using AES-256-GCM with
   a unique IV (prepended to the ciphertext). See
   [BaseTDF-INT Section 2](basetdf-int.md#2-segment-model) and
   [BaseTDF-ALG Section 3](basetdf-alg.md).

8. **Compute segment hashes** -- For each encrypted segment, compute the integrity
   hash using the selected segment hash algorithm (`"HS256"` or `"GMAC"`) keyed
   with the DEK. See
   [BaseTDF-INT Section 4](basetdf-int.md#4-segment-hash-computation).

9. **Compute the root signature** -- Concatenate all segment hashes and compute
   the root signature over the aggregate using the selected root signature
   algorithm, keyed with the DEK. See
   [BaseTDF-INT Section 5](basetdf-int.md#5-root-signature-computation).

### 7.5 Assertions

10. **Create assertions (if needed)** -- For each assertion:
    a. Compute the assertion hash (see [BaseTDF-ASN Section 6](basetdf-asn.md#6-assertion-hash-computation)).
    b. Combine the aggregate payload hash with the assertion hash.
    c. Sign the assertion binding using the assertion signing key (defaults to
       HS256 with the DEK). See
       [BaseTDF-ASN Section 7](basetdf-asn.md#7-signing-assertions).

### 7.6 Assembly

11. **Assemble the manifest** -- Populate the manifest JSON object with:
    - `schemaVersion` set to `"4.4.0"`.
    - `payload` object with entry metadata.
    - `encryptionInformation` containing key access objects, method, integrity
      information, and Base64-encoded policy.
    - `assertions` array (if any assertions were created).

12. **Package into the ZIP container** -- Write the ZIP archive with:
    a. The `0.payload` entry containing all encrypted segments (concatenated).
    b. The `0.manifest.json` entry containing the serialized manifest JSON.
    c. The ZIP central directory and end-of-central-directory record.

---

## 8. End-to-End TDF Reading Flow

This section describes the normative procedure for reading (decrypting) a TDF.

### 8.1 Container Extraction

1. **Open the ZIP archive** -- Parse the ZIP container and locate the
   `0.manifest.json` and `0.payload` entries.

2. **Parse the manifest** -- Deserialize the JSON manifest. Optionally validate
   against the manifest JSON Schema.

3. **Validate `schemaVersion`** -- Check that `schemaVersion` is an accepted
   version (see Section 6.2). If absent, treat as a pre-4.3.0 (legacy) TDF.

### 8.2 Key Reconstruction

4. **Identify key splits** -- Group the KAOs in `keyAccess` by their `sid` (split
   identifier). Each unique `sid` represents one key share that must be recovered.
   Multiple KAOs with the same `sid` represent redundant paths to the same share
   (the reader needs only one successful unwrap per `sid`).

5. **Unwrap key shares** -- For each unique split ID, select a KAO and send a
   rewrap request to the corresponding KAS. The KAS validates the requester's
   authorization against the policy before returning the unwrapped key share. See
   BaseTDF-KAS for the rewrap protocol.

6. **Reconstruct the DEK** -- XOR-combine the unwrapped key shares (one per unique
   split ID) to reconstruct the Data Encryption Key. See
   [BaseTDF-KAO Section 3](basetdf-kao.md#3-key-splitting).

### 8.3 Integrity Verification

7. **Verify the root signature** -- Recompute the root signature from the segment
   hashes stored in the manifest and compare against `rootSignature.sig`. See
   [BaseTDF-INT Section 5](basetdf-int.md#5-root-signature-computation). If
   verification fails, the reader MUST reject the TDF.

### 8.4 Payload Decryption

8. **Decrypt and verify each segment** -- For each segment:
   a. Read the encrypted segment data from `0.payload` at the appropriate offset.
   b. Verify the segment hash against the value in the manifest. See
      [BaseTDF-INT Section 7](basetdf-int.md#7-verification-procedure).
   c. Decrypt the segment using AES-256-GCM with the DEK.
   d. Validate that `segmentSize` matches expectations (the last segment MAY be
      smaller than `segmentSizeDefault`).

### 8.5 Assertion Verification

9. **Verify assertions (if present)** -- For each assertion in the `assertions`
   array:
   a. Verify the assertion binding signature. See
      [BaseTDF-ASN Section 8](basetdf-asn.md#8-verifying-assertions).
   b. Recompute the assertion hash and compare. See
      [BaseTDF-ASN Section 6](basetdf-asn.md#6-assertion-hash-computation).
   c. If verification fails, the reader MUST reject the TDF unless assertion
      verification has been explicitly disabled by the application.

### 8.6 Result

10. **Return plaintext** -- Concatenate the decrypted segments and return the
    plaintext to the application, along with the `mimeType` from the payload
    object and any unencrypted metadata recovered from the KAOs.

---

## 9. Backward Compatibility

### 9.1 Version Detection

Readers MUST use the following logic to determine the TDF version:

1. If `schemaVersion` is present and its major version is `4`:
   - If minor version is `4` or greater: treat as v4.4.0+ TDF.
   - If minor version is `3`: treat as v4.3.0 TDF.
   - Other minor versions within major `4`: treat as the closest known version.
2. If `schemaVersion` is absent: treat as a pre-4.3.0 (legacy) TDF.
3. If `schemaVersion` major version is not `4`: reject as unsupported.

### 9.2 Detecting v4.4.0 Features

The presence of a structured `policyBinding` object (with `alg` and `hash` fields)
in any KAO is a reliable indicator of a v4.4.0+ TDF. In v4.3.0 and earlier, the
`policyBinding` field was a plain string containing only the hash value, with HS256
assumed as the algorithm.

### 9.3 Legacy TDF Handling

When reading a legacy (pre-4.3.0) TDF:

- **Hash encoding**: Legacy TDFs encode intermediate hash values as hexadecimal
  strings rather than raw bytes. Readers MUST detect this based on the absence of
  `schemaVersion` and adjust hash computation accordingly. See
  [BaseTDF-INT Section 8](basetdf-int.md#8-legacy-tdf-handling).

- **Policy binding**: When `policyBinding` is a plain string (not an object),
  readers MUST assume the algorithm is HS256.

- **Assertions**: Legacy TDFs that include assertions use hex-encoded assertion
  hashes in the binding computation. Readers MUST account for this difference.

### 9.4 Forward Compatibility

- Writers MUST NOT add unregistered fields to the manifest. Readers SHOULD ignore
  unknown fields to allow for future extension.
- New optional fields MAY be added in patch or minor version increments without
  changing the `schemaVersion` major version.

---

## 10. Security Considerations

This section highlights security concerns specific to the container format and
manifest. For the complete security model, see
[BaseTDF-SEC](basetdf-sec.md).

### 10.1 Manifest Cleartext Exposure

The manifest is stored as cleartext JSON within the ZIP archive. This means:

- **Policy metadata is visible** -- An observer with access to the TDF file can
  read the policy object (attribute names, dissemination list) without decrypting
  the payload. See
  [BaseTDF-POL Section 10](basetdf-pol.md#10-security-considerations)
  for the implications and mitigations.
- **KAS URLs are visible** -- An observer can determine which Key Access Services
  govern the TDF.
- **Assertion statements MAY be visible** -- Unless the assertion statement value
  is itself encrypted, statement content is readable.

Applications that require metadata confidentiality MUST apply an additional layer
of encryption to the TDF container or use transport-layer protections.

### 10.2 ZIP Parsing Hardening

Implementations MUST harden ZIP parsing against the following attacks:

- **Zip bombs** -- Archives with extreme compression ratios that expand to consume
  disk or memory. Since TDF uses STORE (no compression), this is mitigated by
  design, but implementations MUST still enforce maximum size limits.
- **Path traversal** -- Entry names containing `..` or absolute paths that could
  cause writes outside the intended directory. Implementations MUST validate entry
  names and reject any that do not match the expected `0.payload` and
  `0.manifest.json` names.
- **Duplicate entries** -- ZIP archives with multiple entries sharing the same name.
  Implementations MUST reject archives with duplicate entry names.
- **Manifest size limits** -- Implementations SHOULD enforce a maximum manifest
  size to prevent memory exhaustion from a maliciously large manifest.

### 10.3 DEK as Root of Trust

The Data Encryption Key (DEK) is the root of trust for payload integrity:

- The DEK is used to key the HMAC or GMAC computations for segment hashes and the
  root signature. An attacker who does not possess the DEK cannot forge valid
  integrity information.
- The DEK is used (by default) to sign assertions. An attacker without the DEK
  cannot create or modify assertion bindings.
- The policy binding in each KAO is keyed with the per-split symmetric key. Since
  the DEK is derived by XOR-combining all split keys, compromising the policy
  binding requires access to at least one split key.

### 10.4 Segment Integrity and Streaming

When processing TDFs in streaming mode:

- Readers MUST verify each segment hash before exposing decrypted data to the
  application.
- The root signature SHOULD be verified before beginning segment decryption when
  the full manifest is available.
- Applications MUST be aware that partially-consumed streaming data has not been
  fully integrity-verified until all segments have been processed and the root
  signature has been checked.

### 10.5 Assertion Integrity

Assertions without a `binding` object provide no cryptographic integrity guarantee.
Applications that rely on assertion content for access control or handling decisions
MUST require bound assertions and MUST verify the binding before acting on the
assertion statement.

---

## 11. Normative References

### 11.1 BaseTDF Suite Documents

| Document | Title | Reference |
|---|---|---|
| [BaseTDF-SEC](basetdf-sec.md) | Security Model and Zero Trust Architecture | Security model, threat analysis, key lifecycle |
| [BaseTDF-ALG](basetdf-alg.md) | Algorithm Registry | Cryptographic algorithm identifiers and parameters |
| [BaseTDF-POL](basetdf-pol.md) | Policy and Attribute-Based Access Control | Policy object schema, ABAC evaluation |
| [BaseTDF-KAO](basetdf-kao.md) | Key Access Object | KAO schema, key splitting, policy binding |
| [BaseTDF-INT](basetdf-int.md) | Integrity Verification | Segment hashing, root signature computation |
| [BaseTDF-ASN](basetdf-asn.md) | Assertions | Assertion schema, binding, signing, verification |
| BaseTDF-KAS | Key Access Service Protocol | KAS rewrap protocol (forthcoming) |
| BaseTDF-EX | Examples and Test Vectors | Worked examples for implementers (forthcoming) |

### 11.2 External References

| Identifier | Title | URI |
|---|---|---|
| [RFC 2119][rfc2119] | Key words for use in RFCs to Indicate Requirement Levels | https://www.rfc-editor.org/rfc/rfc2119 |
| [RFC 8174][rfc8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | https://www.rfc-editor.org/rfc/rfc8174 |
| [RFC 8259][rfc8259] | The JavaScript Object Notation (JSON) Data Interchange Format | https://www.rfc-editor.org/rfc/rfc8259 |
| [RFC 5652][rfc5652] | Cryptographic Message Syntax (CMS) | https://www.rfc-editor.org/rfc/rfc5652 |
| [APPNOTE 6.3.10][appnote] | .ZIP File Format Specification | https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT |
| [NIST SP 800-38D][nist-gcm] | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) | https://doi.org/10.6028/NIST.SP.800-38D |
| [FIPS 197][fips197] | Advanced Encryption Standard (AES) | https://doi.org/10.6028/NIST.FIPS.197-upd1 |
| [JSON Schema 2020-12][jsonschema] | JSON Schema: A Media Type for Describing JSON Documents | https://json-schema.org/draft/2020-12/json-schema-core |

[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174
[rfc8259]: https://www.rfc-editor.org/rfc/rfc8259
[rfc5652]: https://www.rfc-editor.org/rfc/rfc5652
[appnote]: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
[nist-gcm]: https://doi.org/10.6028/NIST.SP.800-38D
[fips197]: https://doi.org/10.6028/NIST.FIPS.197-upd1
[jsonschema]: https://json-schema.org/draft/2020-12/json-schema-core
