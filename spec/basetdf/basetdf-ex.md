# BaseTDF-EX: Examples and Test Vectors

| | |
|---|---|
| **Document** | BaseTDF-EX |
| **Title** | Examples and Test Vectors |
| **Version** | 4.4.0 |
| **Status** | Informational |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |
| **References** | BaseTDF-ALG, BaseTDF-KAO, BaseTDF-INT, BaseTDF-ASN, BaseTDF-POL |

## Table of Contents

1. [Introduction](#1-introduction)
2. [Example: RSA-OAEP Key Protection (Legacy Compatibility)](#2-example-rsa-oaep-key-protection-legacy-compatibility)
3. [Example: ECDH-HKDF Key Protection (Current EC Mode)](#3-example-ecdh-hkdf-key-protection-current-ec-mode)
4. [Example: ML-KEM-768 Key Protection (Post-Quantum)](#4-example-ml-kem-768-key-protection-post-quantum)
5. [Example: Multi-Split with Mixed Algorithms](#5-example-multi-split-with-mixed-algorithms)
6. [Example: v4.3.0 Backward Compatibility Reading](#6-example-v430-backward-compatibility-reading)
7. [Example: Assertion with ML-DSA-44 Signing](#7-example-assertion-with-ml-dsa-44-signing)
8. [Test Vector Format Notes](#8-test-vector-format-notes)

---

## 1. Introduction

### 1.1 Purpose

This document provides worked examples to assist implementers of the BaseTDF
specification suite. Each example presents a complete, self-contained manifest
(or relevant fragment) that illustrates a specific feature or algorithm
combination defined in the normative documents.

### 1.2 Non-Normative Status

This document is **informational only**. It is NOT normative. The authoritative
definitions of all structures, fields, algorithms, and procedures are found in
the normative specifications:

- **BaseTDF-ALG** -- Algorithm identifiers and parameters
- **BaseTDF-KAO** -- Key Access Object schema and operations
- **BaseTDF-INT** -- Integrity verification model
- **BaseTDF-ASN** -- Assertions and binding mechanism
- **BaseTDF-POL** -- Policy and attribute-based access control
- **BaseTDF-CORE** -- Container format and manifest

In the event of any discrepancy between this document and a normative
specification, the normative specification takes precedence.

### 1.3 Placeholder Values

All examples use placeholder key material. Base64-encoded values are
illustrative of the format and approximate size but are NOT real cryptographic
outputs. Placeholder values are indicated by descriptive comments in the JSON
or by trailing ellipsis (`...`) within base64 strings. Real implementations
MUST use properly generated cryptographic material as specified in BaseTDF-ALG
and BaseTDF-SEC.

### 1.4 Conventions

Throughout these examples, the following shorthand conventions are used:

- `<N bytes of base64>` indicates a base64-encoded value of approximately N
  raw bytes.
- Segment hashes and signatures use truncated placeholder values for
  readability. Real values are the full output length of the algorithm.
- Policy objects are shown inline (decoded) for clarity, then shown as the
  base64-encoded string that actually appears in the manifest's
  `encryptionInformation.policy` field.

---

## 2. Example: RSA-OAEP Key Protection (Legacy Compatibility)

This example shows a complete v4.4.0 manifest using RSA-OAEP key wrapping for
backward compatibility with existing RSA-based KAS deployments. The manifest
protects a small payload (a single segment) with one KAO addressed to a single
KAS.

### 2.1 Scenario

- **Key protection**: `RSA-OAEP` (LEGACY algorithm, SHA-1 based OAEP)
- **Single KAS**: `https://kas.example.com`
- **Policy**: One attribute (`classification/value/confidential`) with an
  `anyOf` rule and a two-person dissemination list
- **Integrity**: `HS256` root signature, `GMAC` segment hashes
- **Payload**: Single segment, 1 MiB default segment size

### 2.2 Policy Object (Decoded)

The following policy object is base64-encoded and stored in the manifest's
`encryptionInformation.policy` field:

```json
{
  "uuid": "b1e8e7a4-3c0d-4a5f-9b1e-2f8d4c6a7e09",
  "body": {
    "dataAttributes": [
      {
        "attribute": "https://example.com/attr/classification/value/confidential",
        "displayName": "Classification: Confidential",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas.example.com"
      }
    ],
    "dissem": [
      "alice@example.com",
      "bob@example.com"
    ]
  }
}
```

### 2.3 Complete Manifest

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiYjFlOGU3YTQtM2MwZC00YTVmLTliMWUtMmY4ZDRjNmE3ZTA5IiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL2NvbmZpZGVudGlhbCIsImRpc3BsYXlOYW1lIjoiQ2xhc3NpZmljYXRpb246IENvbmZpZGVudGlhbCIsImlzRGVmYXVsdCI6ZmFsc2UsInB1YktleSI6IiIsImthc1VSTCI6Imh0dHBzOi8va2FzLmV4YW1wbGUuY29tIn1dLCJkaXNzZW0iOlsiYWxpY2VAZXhhbXBsZS5jb20iLCJib2JAZXhhbXBsZS5jb20iXX19",
    "keyAccess": [
      {
        "alg": "RSA-OAEP",
        "type": "wrapped",
        "kas": "https://kas.example.com",
        "url": "https://kas.example.com",
        "kid": "rsa-2048-legacy-2024",
        "sid": "",
        "protectedKey": "TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2a3RyNnlvaGRiRjRXOHBPVFhPWlZxZE1mR0dYU3hGQnFmbVFDUHpBTHdFR01sUkkzbjdGdXI0RVRTNkNGTHI3Qm5IZXhSM3hoYjVCZ1grNHlhN2lFPQ==",
        "wrappedKey": "TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2a3RyNnlvaGRiRjRXOHBPVFhPWlZxZE1mR0dYU3hGQnFmbVFDUHpBTHdFR01sUkkzbjdGdXI0RVRTNkNGTHI3Qm5IZXhSM3hoYjVCZ1grNHlhN2lFPQ==",
        "policyBinding": {
          "alg": "HS256",
          "hash": "ZjY4MDA2YTg0ZjczYzAyODk5MTJlOWIxNGRhNGIzNWE="
        }
      }
    ],
    "method": {
      "algorithm": "A256GCM"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "N2UzYjc2YjNhNjQ1NTdhMWRjOWIwNDcwOTgxYmFkNjc="
      },
      "segmentHashAlg": "GMAC",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "SqCnCERZHCHvPeKB",
          "segmentSize": 256,
          "encryptedSegmentSize": 284
        }
      ]
    }
  },
  "assertions": []
}
```

### 2.4 Notes

- The `alg` field (`"RSA-OAEP"`) is the v4.4.0 canonical field. The `type`
  field (`"wrapped"`) is included for backward compatibility with older readers
  that do not recognize `alg`.
- Both `kas` and `url` are present (with the same value) for backward
  compatibility. The `kas` field is the v4.4.0 canonical name.
- Both `protectedKey` and `wrappedKey` carry the same value. The `protectedKey`
  field is canonical; `wrappedKey` is the deprecated alias.
- No `ephemeralKey` is present because RSA-OAEP is a key wrapping algorithm
  (the DEK share is directly encrypted under the KAS public key).
- The `sid` field is empty because there is only a single KAO (no key
  splitting).
- The `segmentHashAlg` is `"GMAC"`, meaning the segment hash is the AES-GCM
  authentication tag extracted from the encrypted segment.
- The `rootSignature.alg` is `"HS256"` (HMAC-SHA256 over the aggregate hash).

---

## 3. Example: ECDH-HKDF Key Protection (Current EC Mode)

This example shows a manifest using ECDH key agreement with HKDF key
derivation, which is the current recommended classical key protection mode.

### 3.1 Scenario

- **Key protection**: `ECDH-HKDF` (P-256 curve)
- **Single KAS**: `https://kas.example.com`
- **Policy**: Two attributes with `anyOf` rules from the same authority
- **Integrity**: `HS256` for both root signature and segment hashes
- **Payload**: Two segments

### 3.2 Policy Object (Decoded)

```json
{
  "uuid": "a9c4e2f1-7b3d-48e6-a5f0-1d2c3b4a5e6f",
  "body": {
    "dataAttributes": [
      {
        "attribute": "https://example.com/attr/department/value/engineering",
        "displayName": "Department: Engineering",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas.example.com"
      },
      {
        "attribute": "https://example.com/attr/department/value/research",
        "displayName": "Department: Research",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas.example.com"
      }
    ],
    "dissem": []
  }
}
```

### 3.3 Complete Manifest

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiYTljNGUyZjEtN2IzZC00OGU2LWE1ZjAtMWQyYzNiNGE1ZTZmIiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2RlcGFydG1lbnQvdmFsdWUvZW5naW5lZXJpbmciLCJkaXNwbGF5TmFtZSI6IkRlcGFydG1lbnQ6IEVuZ2luZWVyaW5nIiwiaXNEZWZhdWx0IjpmYWxzZSwicHViS2V5IjoiIiwia2FzVVJMIjoiaHR0cHM6Ly9rYXMuZXhhbXBsZS5jb20ifSx7ImF0dHJpYnV0ZSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vYXR0ci9kZXBhcnRtZW50L3ZhbHVlL3Jlc2VhcmNoIiwiZGlzcGxheU5hbWUiOiJEZXBhcnRtZW50OiBSZXNlYXJjaCIsImlzRGVmYXVsdCI6ZmFsc2UsInB1YktleSI6IiIsImthc1VSTCI6Imh0dHBzOi8va2FzLmV4YW1wbGUuY29tIn1dLCJkaXNzZW0iOltdfX0=",
    "keyAccess": [
      {
        "alg": "ECDH-HKDF",
        "type": "ec-wrapped",
        "kas": "https://kas.example.com",
        "url": "https://kas.example.com",
        "kid": "ec-p256-2025-01",
        "sid": "",
        "protectedKey": "qL3tOVFaWDRJHgT8Q5Y9x1BSeHOmkfLEwEv6JhPOWsV2c5Ra3d0a6rk=",
        "wrappedKey": "qL3tOVFaWDRJHgT8Q5Y9x1BSeHOmkfLEwEv6JhPOWsV2c5Ra3d0a6rk=",
        "ephemeralKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3rJVMzpBIYMBpGa8ckMNTGK2aSaQ\nhZkFnzLvM0+ZvP1FDhqscbQPaYKNsitEcLcpRnPOXQFwsu2vIC5HbWjJKA==\n-----END PUBLIC KEY-----",
        "policyBinding": {
          "alg": "HS256",
          "hash": "YTczOTQ1NjEzOGJjN2JhOGVhMGRhNWIxZWQwNWY0Njk="
        }
      }
    ],
    "method": {
      "algorithm": "A256GCM"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "Mzk1ZjJlMjUzYmEwYjU4NjY5ODc5MTZjMjVhZjNjZjI="
      },
      "segmentHashAlg": "HS256",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "MWM0ZGU2YTE0NjdlMWFiNQ==",
          "segmentSize": 1048576,
          "encryptedSegmentSize": 1048604
        },
        {
          "hash": "ZWIxOWY2N2IzNjVlMjM2MA==",
          "segmentSize": 512,
          "encryptedSegmentSize": 540
        }
      ]
    }
  },
  "assertions": []
}
```

### 3.4 Notes

- The `ephemeralKey` field contains the ephemeral EC public key in PEM format.
  This is the public half of the ephemeral key pair generated by the TDF
  creator during encryption. The KAS uses this key together with its own EC
  private key to derive the shared secret via ECDH.
- The HKDF parameters for `ECDH-HKDF` are: salt = `SHA256("TDF")` (a fixed
  32-byte value), info = `""` (empty), output length = 32 bytes.
- The `protectedKey` is the AES-256-GCM ciphertext of the DEK share encrypted
  under the HKDF-derived key. This wire format is unchanged from v4.3.0; only
  the field names differ (see Section 6).
- Both `type: "ec-wrapped"` and `alg: "ECDH-HKDF"` are present. The `alg`
  field takes precedence; `type` is included for older readers.
- The two `anyOf` attributes share a single split (empty `sid`), meaning any
  one matching attribute is sufficient for access.
- Both segments use `HS256` hashing (HMAC-SHA256 with the DEK as key).

---

## 4. Example: ML-KEM-768 Key Protection (Post-Quantum)

This example shows a manifest using the ML-KEM-768 key encapsulation mechanism
for post-quantum key protection.

### 4.1 Scenario

- **Key protection**: `ML-KEM-768` (FIPS 203, NIST Level 3)
- **Single KAS**: `https://kas-pqc.example.com`
- **Policy**: One attribute (`classification/value/secret`)
- **Integrity**: `HS256` root signature and segment hashes
- **Payload**: Single segment

### 4.2 Complete Manifest

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiZDRlNWY2YTctOGIwYy00OWQxLWExZjItM2M0ZDVlNmY3YTg5IiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL3NlY3JldCIsImRpc3BsYXlOYW1lIjoiQ2xhc3NpZmljYXRpb246IFNlY3JldCIsImlzRGVmYXVsdCI6ZmFsc2UsInB1YktleSI6IiIsImthc1VSTCI6Imh0dHBzOi8va2FzLXBxYy5leGFtcGxlLmNvbSJ9XSwiZGlzc2VtIjpbXX19",
    "keyAccess": [
      {
        "alg": "ML-KEM-768",
        "type": "mlkem-wrapped",
        "kas": "https://kas-pqc.example.com",
        "kid": "kas-mlkem768-2025-03",
        "sid": "",
        "protectedKey": "MIIEgoCCBEBnFBfBXIO10t99MteIS4HwAHf0cfoGtqEogRnpwwl/AbE3xHCJ6aWZORiZeFBsPgu6Jl886QVhquJ4UbdJTnRZBIfM2b+pKtlgi7zmbbwaiYXSY4W2USdJrOMeA+PBeegn0MtDELLjL1sGQTTFSVwwlT3j61VcxASV1cNfPcxWwQ9hWRdjJoQX3mzbYvLfZ14ertjZJlCb2q21WLpsel3im8X90PC7LTcOsBmUI4iGjPZdQ91Z9Qm2FrYkMuSFJfF8YPIQXa8+BjDUZ39haW8JO++iPAzLGLm5Sb7dj2lOTaSBJrXh4YZCDpbam7aM3JFAWLAThI3pAyP2uo39lmfDWMH19VIOalcfOjGS+sMzJklNcGJlARaDZe2jw+MZy8GGiUR+CFeSaUMNh9CNnGuSVXNl6/lQygoviv/qTtaNA6TBYyMDJlp3BdjJ+hQo2WpsxsvPripYO9fP9GSYYsf675Ey5TewyP18hT4NJu0f0FJ+YfLopahflFkyQ8+J4kENDTuS9/CDuMCw3grV09vJqS98YNx43u2hQB6u+kuJokCXJ2qPJqHq6XutIdBfD/AA0ZhToiGnZseUmQBXbopmP8uOpr61/QWo0OxCLdIvP6GJWFt4PuDx6LkUhkbno8ytS538vwFUufe0P/NBddfRP8Ve8qRwprltMZx5ko0JqHMW4HH4H1w3AiczBPZ/sDm4bV2i9YEIr+vpTOFBpF+jxBLf94ozFtcw15xccyON7j+HZfRJEkMgrKSWXfmfImK/WuehMVmgtLpAwBRwRzL6+OQ7Leos8QVOwDvGSzhuK+46y9M7FUO4V6vaEW/H7kc/Tl7ad83VJu/ASXTO25scbsF3dXDMIYbRDFIm0PXKzrCLnnE5xc2tPfhDirfnPPrVwATniEc8z/ZodqzwhyM5+YkzcKzHv+DYWXKjXDu+HgyjXjANmOnlCmjIIA4tuL1eYHQrpp8MR4J/+3w058+gDA8PeCoVwEQyXjyw/uDJbfzBiapc6K91tr6dm3HUfJmO0ohCuADg619gSXbLPJQIuGBzfQqSU7vRR1+tkBdj0zVycAd4pKwhTnhm8l7Y1yVyek5pdm6sXk1OYXruvvdLy1zIbnwVn8LJkTQ9vaKDu8945POSvMU0JZlsGkFIYmXLddN7U1Q71BqHcE+TmJtJHeGiTDUJqds6C1dJwhnI4LUIDGj8/+7OHVObnU6joBMg18q6n2gXnnrxVjzRwAX+TQwtyLAM4hTlHJtyNHd3yrdgYD/pOC/0n/Gwmr5RSnJfWUvpJHm9X/JQg+DIhfG+NO+DhD8JZjmqjbc/xmugBkESdVTj6cXRyhNB4gqS88suhIVrGGOpwUCMvezC7mI2ojQcbi6Tb0cCaCMUIaa5yD0vpnNbJJB88jlRhKtPgsfFpvZsEcrGvAAqtsAzyPxPVQdn81uZvyz7mIkIS1ENo4E8h5ol3DZcri5nwMFoT0kdjQpB9OQS0T6LpYUXPn7Tyn4Jb456JSX3vzwLQ5nxSXhL/PUZ4WACsNr9ciS3",
        "policyBinding": {
          "alg": "HS256",
          "hash": "NDE2OGMxMDZhNjQ4YTczOTFkY2UxZjI5ZGU5OGM5ZmI="
        }
      }
    ],
    "method": {
      "algorithm": "A256GCM"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "YjRkNzI5NTE1MGRhM2Q0NTkxMjRiNmVjMTcxZjRmZWI="
      },
      "segmentHashAlg": "HS256",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "ZTEyYTk1NWQ4NDI4ZjBlMw==",
          "segmentSize": 4096,
          "encryptedSegmentSize": 4124
        }
      ]
    }
  },
  "assertions": []
}
```

### 4.3 Notes

- There is no `ephemeralKey` field. For ML-KEM the KEM ciphertext travels
  inside `protectedKey`, not in `ephemeralKey`.
- The `protectedKey` field is the base64 encoding of a DER `MLKEMWrappedKey`
  structure (BaseTDF-ALG Section 4.3), which decodes to:
  - `mlkemCiphertext` (`[0]`, 1088 bytes): the output of
    `ML-KEM.Encapsulate(kas_mlkem_pk)`. The KAS calls
    `ML-KEM.Decapsulate(kas_mlkem_sk, ct)` to recover the 32-byte shared secret.
  - `encryptedDEK` (`[1]`, 60 bytes here): a 12-byte GCM nonce, the AES-256-GCM
    ciphertext of the 32-byte DEK share, and the 16-byte GCM tag. No AAD is
    used.
- No KDF is applied. The 32-byte ML-KEM shared secret is used directly as the
  AES-256 key -- see BaseTDF-ALG Section 4.3.1 for the rationale.
- The `type` field carries the legacy value `"mlkem-wrapped"` for readers that
  do not recognize `alg`. Note that `"mlkem-wrapped"` alone does not distinguish
  ML-KEM-768 from ML-KEM-1024; `alg` is authoritative (BaseTDF-KAO
  Section 7.1).
- The `kid` field (`"kas-mlkem768-2025-03"`) identifies the specific ML-KEM-768
  key pair held by the KAS.

---

## 5. Example: Multi-Split with Mixed Algorithms

This example demonstrates key splitting across two KAS instances using different
algorithms, one classical and one post-quantum. The policy requires access
authorization from both KAS instances (an `allOf` rule with attributes from
different authorities).

### 5.1 Scenario

- **Policy**: Two `allOf` attributes from different authorities, each mapping
  to a different KAS
  - `classification/value/secret` at KAS-A (RSA-based)
  - `project/value/quantum-safe` at KAS-B (ML-KEM-based)
- **Split 0** (`sid: "s-0"`): `RSA-OAEP-256` to KAS-A
- **Split 1** (`sid: "s-1"`): `ML-KEM-768` to KAS-B
- **Integrity**: `HS256` root signature and segment hashes

### 5.2 Policy Object (Decoded)

```json
{
  "uuid": "c8d9e0f1-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "body": {
    "dataAttributes": [
      {
        "attribute": "https://authority-a.example.com/attr/classification/value/secret",
        "displayName": "Classification: Secret",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas-a.example.com"
      },
      {
        "attribute": "https://authority-b.example.com/attr/project/value/quantum-safe",
        "displayName": "Project: Quantum Safe",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas-b.example.com"
      }
    ],
    "dissem": []
  }
}
```

### 5.3 Complete Manifest

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiYzhkOWUwZjEtMmEzYi00YzVkLTZlN2YtOGE5YjBjMWQyZTNmIiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9hdXRob3JpdHktYS5leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL3NlY3JldCIsImRpc3BsYXlOYW1lIjoiQ2xhc3NpZmljYXRpb246IFNlY3JldCIsImlzRGVmYXVsdCI6ZmFsc2UsInB1YktleSI6IiIsImthc1VSTCI6Imh0dHBzOi8va2FzLWEuZXhhbXBsZS5jb20ifSx7ImF0dHJpYnV0ZSI6Imh0dHBzOi8vYXV0aG9yaXR5LWIuZXhhbXBsZS5jb20vYXR0ci9wcm9qZWN0L3ZhbHVlL3F1YW50dW0tc2FmZSIsImRpc3BsYXlOYW1lIjoiUHJvamVjdDogUXVhbnR1bSBTYWZlIiwiaXNEZWZhdWx0IjpmYWxzZSwicHViS2V5IjoiIiwia2FzVVJMIjoiaHR0cHM6Ly9rYXMtYi5leGFtcGxlLmNvbSJ9XSwiZGlzc2VtIjpbXX19",
    "keyAccess": [
      {
        "alg": "RSA-OAEP-256",
        "type": "wrapped",
        "kas": "https://kas-a.example.com",
        "url": "https://kas-a.example.com",
        "kid": "rsa-4096-kas-a-2025",
        "sid": "s-0",
        "protectedKey": "QUVTLTI1Ni1HQ00gY2lwaGVydGV4dCBvZiBERUsgc2hhcmUgMCBlbmNyeXB0ZWQgdW5kZXIgUlNBLU9BRVAtMjU2IHdpdGggdGhlIEtBUy1BIHB1YmxpYyBrZXkuIFRoaXMgaXMgYSBwbGFjZWhvbGRlci4=",
        "wrappedKey": "QUVTLTI1Ni1HQ00gY2lwaGVydGV4dCBvZiBERUsgc2hhcmUgMCBlbmNyeXB0ZWQgdW5kZXIgUlNBLU9BRVAtMjU2IHdpdGggdGhlIEtBUy1BIHB1YmxpYyBrZXkuIFRoaXMgaXMgYSBwbGFjZWhvbGRlci4=",
        "policyBinding": {
          "alg": "HS256",
          "hash": "YWJjZGVmMDEyMzQ1Njc4OTBhYmNkZWYwMTIzNDU2Nzg="
        }
      },
      {
        "alg": "ML-KEM-768",
        "type": "mlkem-wrapped",
        "kas": "https://kas-b.example.com",
        "kid": "mlkem768-kas-b-2025",
        "sid": "s-1",
        "protectedKey": "MIIEgoCCBEDYogtwz+pWduYpaP6triGbS0fqjj9gG2mZT7RhOLbgtCjA48d2+YumwfA+6/5Yi0PGUCJPhm4w5aqFI/yAgMQdtb9lnzSANdtizfxFqLqrAbJhjUyvYPTa8GSNCMWoGR2mPcoVqPjFmTOdjmGRkDyJhkSa+sGj0hyTtvekXtmGlAYUxuWk9qEj3zHcHEB04n7C0LKupKaALcvJnVSoN84ylHCrd+/ghzQL5+tGwTwDrOpwgizIAex0V7Zpgi+XBQP8PmApbBk1Nmx/f8kuLs56jX+EsYwK1nyqfkwq54A+taMIKkWPFD1LavjsIwqwsPfTcwQjgVjC+nYQeMjmLpOx7MqEqdiuehMQP9vjmr31LqBN3OtaeLvc4pJLP9PI7YESA1kbrJcwIEiCbL8TGQ/KDLCVgjPH1UGl87rHnY3BTw7a908q72RrOi334QHVIT+93BKIgZ7NWfzPdBBvSszYgaD1qhmfoUuKgBPRx0bXOPkt7YZ/0T8/eaNzJvAb7qYstV/UKtSdOYxDxXY5imLL1eM5N/UHflx0wiAF223io8K09u27TnWwLSmxMi88aJsKBKk4HUQe/17f7Uv+gtioJubcizCZ3ZhWALcJMUjg+QpY2rnRvTEnsjQi64j41DBl99ZXEiMzYP6dUWRkHPGnRs4UU2/LkNjkfkEH4UJpFOlrEOytc79WzCmIuRJ0bcRLttb4QUu/P896NaUMegLtv9aMANXAdJ1h9HKEJc6EIfk/8PKYl/1X9ICZxTltf9R3u86PgWFdLZmzTZo3iFExHdJDsNA7ZqOxSKKmKE0C99VCHd3BoN5LnakdzuDiZEA+RnYtbCUH1onzqbIDzI6/SfFN7kJ0x74af5WMe3CD5Mj0cv62nq1eO83i/unLe8zMu5QRnjS5tmPV4Qh9USQgXMq9QU41n+wivVhZaa8a6lhnDcHN4SuJgIWSNvgTITxEL1xXEZX53+fp8sf89/NZ+XGef/8PNV77fnMQWOsxv+oCcZdzDxALsKBkA/7PGxVgGo24G2SoeghBSJCyuUkCvKdKdLQo+WV3unkl4OOVNz90AUozFCQ9t/KKGc2ZKUDJnSkZYOs6jM6fWDSKp8w7/RVJaUXxExAHXdg10FZxy5j01qe/kfpQHiqgmXBcayMjGZLGtKQ2YQy/R/R2WKUVA3ul/H/HCAMgKvKdTW9BhzrJ9GaM7yiAS+jLRPglV92afvKFiX0+3ovY4puTkzYrSCTIDqIuI75vblMTAJ0y3XB9sQoqHjIk33ocUGrYTcYezkmTQMuEAauqzyJhz1ZWa2s5Q1zDTB33QOjbwBwJBVN8Ez3xtIs1g2aZPN7EqXkS4YEz67t+VJi0CylwC2+55j/s6I1vuUTiVPqfkKkC46Ae5bCzzX/gohf7XvDZj/L/gWJSE8UOgGn9oLDwoD0AH+3BnzRi4R7E1WZaoCqAhYE8F4bTfxhSeo8M5/sk5zCv/oTadm7+tzkLKJXmHCobujI95MdO5+nRSraFjjx/enXSEiR/zpWy3juzMWpr",
        "policyBinding": {
          "alg": "HS256",
          "hash": "ZmVkY2JhOTg3NjU0MzIxMGFiY2RlZjAxMjM0NTY3ODk="
        }
      }
    ],
    "method": {
      "algorithm": "A256GCM"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "YThiOWMwZDFlMmYzYTRiNWM2ZDdlOGY5MDAxMjIzMzQ="
      },
      "segmentHashAlg": "HS256",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "ZjBmMWYyZjNmNGY1ZjZmNw==",
          "segmentSize": 8192,
          "encryptedSegmentSize": 8220
        }
      ]
    }
  },
  "assertions": []
}
```

### 5.4 Key Splitting Explanation

The DEK is split into two shares using XOR-based n-of-n secret sharing
(BaseTDF-KAO Section 3):

```
share_0 = random(32)                    // 32 random bytes from CSPRNG
share_1 = DEK XOR share_0              // computed so that XOR reconstructs DEK
```

- **KAO 0** (`sid: "s-0"`): Protects `share_0` using `RSA-OAEP-256`, sent to
  KAS-A. The `protectedKey` is the RSA-OAEP ciphertext of `share_0`.
- **KAO 1** (`sid: "s-1"`): Protects `share_1` using `ML-KEM-768`, sent to
  KAS-B. The `protectedKey` is the AES-256-GCM ciphertext of `share_1`
  encrypted under the HKDF-derived key from the ML-KEM shared secret.

To reconstruct the DEK, a reader must:

1. Obtain `share_0` by sending KAO 0 to KAS-A for rewrap.
2. Obtain `share_1` by sending KAO 1 to KAS-B for rewrap.
3. Compute `DEK = share_0 XOR share_1`.

Both KAS instances must independently authorize the request based on their
respective attribute evaluations. This provides defense-in-depth: compromising
one KAS alone reveals nothing about the DEK.

### 5.5 Notes

- The two KAOs have **different** `sid` values (`"s-0"` and `"s-1"`),
  indicating they protect different shares of the DEK.
- The first KAO (`RSA-OAEP-256`) has no `ephemeralKey` because RSA-OAEP is a
  key wrapping algorithm.
- The second KAO (`ML-KEM-768`) also has no `ephemeralKey`: its KEM ciphertext
  is carried inside the `MLKEMWrappedKey` envelope in `protectedKey`.
- The `policyBinding` in each KAO is computed over the **same** base64-encoded
  policy string, but with **different** HMAC keys (each KAO uses its own DEK
  share as the HMAC key).
- The `allOf` attribute rule means the KAS authorization service requires the
  requesting entity to satisfy BOTH attributes. The key splitting mechanism
  enforces this cryptographically: the DEK cannot be recovered without both
  shares.

---

## 6. Example: v4.3.0 Backward Compatibility Reading

This section shows a v4.3.0-era manifest and explains how a v4.4.0 reader
interprets it. The v4.3.0 manifest uses the legacy field names and encoding
conventions.

### 6.1 Legacy v4.3.0 Manifest

```json
{
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiMTIzNDU2NzgtYWJjZC1lZmdoLWlqa2wtbW5vcHFyc3R1dnd4IiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL2NvbmZpZGVudGlhbCIsImRpc3BsYXlOYW1lIjoiIiwiaXNEZWZhdWx0IjpmYWxzZSwicHViS2V5IjoiIiwia2FzVVJMIjoiaHR0cHM6Ly9rYXMuZXhhbXBsZS5jb20ifV0sImRpc3NlbSI6W119fQ==",
    "keyAccess": [
      {
        "type": "ec-wrapped",
        "url": "https://kas.example.com",
        "protocol": "kas",
        "wrappedKey": "cGxhY2Vob2xkZXItYWVzLTI1Ni1nY20td3JhcHBlZC1kZWstc2hhcmU=",
        "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELegacyKeyValue0placeholder1\nabcdefghijklmnopqrstuvwxyz012345678ABCDEFGHIJKLMNOPQ==\n-----END PUBLIC KEY-----",
        "policyBinding": "ZjY4MDA2YTg0ZjczYzAyODk5MTJlOWIxNGRhNGIzNWE2OGQ0ZDVjMWI1ZThlOWQxYjk4ZTc1MjY0NzQ4MzAwOA=="
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "N2UzYjc2YjNhNjQ1NTdhMWRjOWIwNDcwOTgxYmFkNjc="
      },
      "segmentHashAlg": "GMAC",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "SqCnCERZHCHvPeKB",
          "segmentSize": 512,
          "encryptedSegmentSize": 540
        }
      ]
    }
  }
}
```

### 6.2 How a v4.4.0 Reader Interprets This Manifest

A conformant v4.4.0 reader applies the backward compatibility rules from
BaseTDF-KAO Section 7 as follows:

| Legacy Field / Value | v4.4.0 Interpretation | Reference |
|:---------------------|:----------------------|:----------|
| No `schemaVersion` | Legacy TDF; apply hex-then-base64 decoding for policy binding and integrity hashes | BaseTDF-KAO 7.3 |
| `type: "ec-wrapped"` | Infer `alg: "ECDH-HKDF"` | BaseTDF-KAO 7.1 |
| `url` | Treat as `kas` | BaseTDF-KAO 7.1 |
| `wrappedKey` | Treat as `protectedKey` | BaseTDF-KAO 7.1 |
| `ephemeralPublicKey` | Treat as `ephemeralKey` | BaseTDF-KAO 7.1 |
| `policyBinding` (bare string) | Treat as `{ "alg": "HS256", "hash": "<value>" }` | BaseTDF-KAO 7.1 |
| `protocol: "kas"` | Informational only; ignored | BaseTDF-KAO 2.3 |
| `algorithm: "AES-256-GCM"` | Treat as `"A256GCM"` | Legacy algorithm name |

### 6.3 Policy Binding Verification with Legacy Encoding

The legacy `policyBinding` value is a bare string (not an object). The v4.4.0
reader treats it as:

```json
{
  "alg": "HS256",
  "hash": "ZjY4MDA2YTg0ZjczYzAyODk5MTJlOWIxNGRhNGIzNWE2OGQ0ZDVjMWI1ZThlOWQxYjk4ZTc1MjY0NzQ4MzAwOA=="
}
```

To verify, the reader applies the hex-then-base64 detection logic from
BaseTDF-KAO Section 5.5:

1. Base64-decode the hash value. This produces 64 bytes.
2. Check if the decoded bytes consist entirely of valid hexadecimal ASCII
   characters (`0-9`, `a-f`, `A-F`). If so, this is the legacy
   hex-then-base64 encoding.
3. Hex-decode the 64 ASCII characters to obtain the 32-byte HMAC digest.
4. Compare the result against the locally computed
   `HMAC-SHA256(DEK_share, canonical_policy)` using constant-time comparison.

### 6.4 Key Agreement

The `ECDH-HKDF` unwrap procedure is identical to the v4.4.0 procedure in
Section 3; only the field names differ. The reader derives
`derived_key = HKDF-SHA256(salt=SHA256("TDF"), ikm=shared_secret, info="", len=32)`
from `ephemeralPublicKey` and the KAS private key, then AES-256-GCM-decrypts
`wrappedKey` under it.

### 6.5 Notes

- The absence of `schemaVersion` in the manifest is the primary signal that
  this is a legacy TDF.
- The `protocol` field (`"kas"`) is a legacy informational field and has no
  effect on processing.
- Real implementations should handle the `"AES-256-GCM"` legacy algorithm
  name as equivalent to the v4.4.0 identifier `"A256GCM"`.

---

## 7. Example: Assertion with ML-DSA-44 Signing

This example shows a handling assertion signed with the `ML-DSA-44`
post-quantum signature algorithm (FIPS 204, NIST Level 2). ML-DSA-44 is the
RECOMMENDED post-quantum algorithm for assertion signing.

### 7.1 Scenario

- **Assertion type**: `"handling"` -- a STANAG 5636 classification marking
- **Signing algorithm**: `ML-DSA-44` (asymmetric, post-quantum)
- **ML-DSA-44 signature size**: 2420 bytes
- **Binding method**: JWS Compact Serialization

### 7.2 Assertion Object

```json
{
  "id": "7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d",
  "type": "handling",
  "scope": "tdo",
  "appliesToState": "encrypted",
  "statement": {
    "format": "json+stanag5636",
    "schema": "urn:nato:stanag:5636:A:1:elements:json",
    "value": "{\"ocl\":{\"pol\":\"d4e5f6a7-8b0c-49d1-a1f2-3c4d5e6f7a89\",\"cls\":\"SECRET\",\"catl\":[{\"type\":\"P\",\"name\":\"Releasable To\",\"vals\":[\"usa\",\"gbr\"]}],\"dcr\":\"2025-06-15T00:00:00Z\"},\"context\":{\"@base\":\"urn:nato:stanag:5636:A:1:elements:json\"}}"
  },
  "binding": {
    "method": "jws",
    "signature": "eyJhbGciOiJNTC1EU0EtNDQifQ.eyJhc3NlcnRpb25IYXNoIjoiNGE0NDdhMTNjNWEzMjczMGQyMGJkZjdmZWVjYjlmZmUxNjY0OWJjNzMxOTE0YjU3NGQ4MDAzNWEzOTI3Zjg2MCIsImFzc2VydGlvblNpZyI6ImJHRnlaMlZmWW1GelpUWTBYM1poYkhWbFgyaGxjbVVfdGhpc19pc19hX3BsYWNlaG9sZGVyX2Zvcl90aGVfYmluZGluZ19pbnB1dF9jb25jYXRlbmF0aW9uIn0.ML-DSA-44-placeholder-signature-2420-bytes-base64url-encoded-the-actual-signature-would-be-approximately-3227-base64url-characters-representing-2420-bytes-of-ML-DSA-44-signature-data-per-FIPS-204-this-is-significantly-larger-than-classical-ECDSA-signatures-which-are-typically-64-bytes"
  }
}
```

### 7.3 JWS Structure Breakdown

The JWS Compact Serialization has three parts separated by `.` (period):

**Protected Header** (base64url-decoded):

```json
{
  "alg": "ML-DSA-44"
}
```

**Payload** (base64url-decoded):

```json
{
  "assertionHash": "4a447a13c5a32730d20bdf7feecb9ffe16649bc731914b574d80035a3927f860",
  "assertionSig": "bGFyZ2VfYmFzZTY0X3ZhbHVlX2hlcmVfdGhpc19pc19hX3BsYWNlaG9sZGVyX2Zvcl90aGVfYmluZGluZ19pbnB1dF9jb25jYXRlbmF0aW9u"
}
```

Where:

- `assertionHash`: The SHA-256 hash of the canonicalized assertion object
  (with `binding` removed), encoded as lowercase hex (64 characters).
- `assertionSig`: The base64-encoded concatenation of
  `aggregateHash || assertionHashBytes`, where `aggregateHash` is the
  concatenation of all decoded segment hashes, and `assertionHashBytes` is
  the hex-decoded assertion hash (32 bytes).

**Signature**: The third JWS component is the ML-DSA-44 signature
(2420 bytes, base64url-encoded). This is substantially larger than classical
signatures:

| Algorithm | Signature Size | Base64url Size (approx.) |
|:----------|:---------------|:-------------------------|
| `HS256` | 32 bytes | 43 characters |
| `ES256` | 64 bytes | 86 characters |
| `RS256` (2048-bit) | 256 bytes | 342 characters |
| `ML-DSA-44` | 2420 bytes | 3227 characters |
| `ML-DSA-65` | 3309 bytes | 4412 characters |

### 7.4 Complete Manifest with ML-DSA-44 Assertion

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiZDRlNWY2YTctOGIwYy00OWQxLWExZjItM2M0ZDVlNmY3YTg5IiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL3NlY3JldCIsImRpc3BsYXlOYW1lIjoiQ2xhc3NpZmljYXRpb246IFNlY3JldCIsImlzRGVmYXVsdCI6ZmFsc2UsInB1YktleSI6IiIsImthc1VSTCI6Imh0dHBzOi8va2FzLmV4YW1wbGUuY29tIn1dLCJkaXNzZW0iOltdfX0=",
    "keyAccess": [
      {
        "alg": "ML-KEM-1024",
        "type": "mlkem-wrapped",
        "kas": "https://kas.example.com",
        "kid": "kas-mlkem1024-2025-02",
        "sid": "",
        "protectedKey": "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",
        "policyBinding": {
          "alg": "HS256",
          "hash": "OWEzYjRjNWQ2ZTdmOGExMjM0NTY3ODkwYWJjZGVmMDE="
        }
      }
    ],
    "method": {
      "algorithm": "A256GCM"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "ZGQ3MjkxODVmNThhYmMzZDRlNjdmODkwMTIzNGFiY2Q="
      },
      "segmentHashAlg": "HS256",
      "segmentSizeDefault": 1048576,
      "encryptedSegmentSizeDefault": 1048604,
      "segments": [
        {
          "hash": "OTg3NjU0MzIxMGZlZGNiYQ==",
          "segmentSize": 2048,
          "encryptedSegmentSize": 2076
        }
      ]
    }
  },
  "assertions": [
    {
      "id": "7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d",
      "type": "handling",
      "scope": "tdo",
      "appliesToState": "encrypted",
      "statement": {
        "format": "json+stanag5636",
        "schema": "urn:nato:stanag:5636:A:1:elements:json",
        "value": "{\"ocl\":{\"pol\":\"d4e5f6a7-8b0c-49d1-a1f2-3c4d5e6f7a89\",\"cls\":\"SECRET\",\"catl\":[{\"type\":\"P\",\"name\":\"Releasable To\",\"vals\":[\"usa\",\"gbr\"]}],\"dcr\":\"2025-06-15T00:00:00Z\"},\"context\":{\"@base\":\"urn:nato:stanag:5636:A:1:elements:json\"}}"
      },
      "binding": {
        "method": "jws",
        "signature": "eyJhbGciOiJNTC1EU0EtNDQifQ.eyJhc3NlcnRpb25IYXNoIjoiNGE0NDdhMTNjNWEzMjczMGQyMGJkZjdmZWVjYjlmZmUxNjY0OWJjNzMxOTE0YjU3NGQ4MDAzNWEzOTI3Zjg2MCIsImFzc2VydGlvblNpZyI6ImJHRnlaMlZmWW1GelpUWTBYM1poYkhWbFgyaGxjbVVfdGhpc19pc19hX3BsYWNlaG9sZGVyX2Zvcl90aGVfYmluZGluZ19pbnB1dF9jb25jYXRlbmF0aW9uIn0.ML-DSA-44-placeholder-signature-2420-bytes-base64url-encoded-the-actual-signature-would-be-approximately-3227-base64url-characters-representing-2420-bytes-of-ML-DSA-44-signature-data-per-FIPS-204-this-is-significantly-larger-than-classical-ECDSA-signatures-which-are-typically-64-bytes"
      }
    }
  ]
}
```

### 7.5 Notes

- The JWS `alg` header is `"ML-DSA-44"`, matching the identifier in
  BaseTDF-ALG Section 3.4 and Section 6.5.
- ML-DSA-44 signatures (2420 bytes) are significantly larger than classical
  alternatives. Implementations should account for increased manifest size
  when using post-quantum assertion signatures.
- The ML-DSA-44 public key (1312 bytes) used for verification may be conveyed
  out-of-band or referenced by a key identifier in the JWS header. The spec
  permits including the public key in the JWS `jwk` header parameter
  (base64-encoded raw bytes) but does not require it.
- The `assertionHash` claim contains the SHA-256 hash of the assertion
  content (excluding the `binding` field), computed using the JCS
  canonicalization procedure from BaseTDF-ASN Section 6.
- The `assertionSig` claim contains the base64-encoded concatenation of the
  aggregate integrity hash (from segment hashes) and the decoded assertion
  hash bytes. This creates a two-way binding between the assertion and the
  specific TDF payload.
- The key protection algorithm (`ML-KEM-1024`) and the assertion signing
  algorithm (`ML-DSA-44`) are independent choices. This example demonstrates a
  fully post-quantum TDF: PQC key encapsulation and PQC assertion signing.
- The `protectedKey` envelope here carries a 1568-byte `mlkemCiphertext`, the
  ML-KEM-1024 ciphertext size.

---

## 8. Test Vector Format Notes

### 8.1 Placeholder Values

All base64-encoded values in this document are illustrative placeholders. They
demonstrate the correct structural format and approximate size of real values
but are NOT computed from actual cryptographic operations. The following
conventions are used:

- **Policy strings**: Real base64-encoded JSON that can be decoded to read the
  policy object.
- **Protected keys**: Placeholder base64 values of representative length.
- **Ephemeral keys**: EC PEM keys in Section 3 use syntactically valid PEM
  headers but placeholder key data. ML-KEM ciphertexts use placeholder base64
  of approximately correct decoded length (1088 bytes for ML-KEM-768).
- **Policy binding hashes**: Placeholder base64 values of 32-byte HMAC-SHA256
  output length.
- **Segment hashes**: Placeholder base64 values of appropriate length for the
  algorithm (32 bytes for HS256, 16 bytes for GMAC).
- **Root signatures**: Placeholder base64 values of 32 bytes (HS256).
- **JWS signatures**: Placeholder compact serialization with descriptive
  text in the signature component.

### 8.2 Real Test Vectors

Full test vectors with actual computed cryptographic values -- including
known key pairs, deterministic RNG output, and expected intermediate and
final values -- are planned for a separate test suite document. Such vectors
would include:

- Known RSA, EC, ML-KEM, and ML-DSA key pairs (private and public).
- Fixed plaintext payloads and policy objects.
- Deterministically generated ephemeral keys and nonces.
- Expected values at each step of the key protection procedure.
- Expected segment hashes, aggregate hashes, and root signatures.
- Expected policy binding HMAC values.
- Complete JWS tokens with verifiable signatures.

### 8.3 Implementer Guidance

When implementing against these examples:

1. **Validate structure**: Use the JSON schemas in `../schema/BaseTDF/` to
   validate that your implementation produces structurally correct manifests.
2. **Validate field names**: Ensure your implementation uses v4.4.0 canonical
   field names (`alg`, `kas`, `kid`, `sid`, `protectedKey`, `ephemeralKey`)
   and includes deprecated aliases (`type`, `url`, `wrappedKey`) where
   specified for backward compatibility.
3. **Validate base64 lengths**: For `ECDH-HKDF`, check that the base64-decoded
   `ephemeralKey` is a PEM-encoded EC public key (65 bytes for an uncompressed
   P-256 point). For ML-KEM, decode `protectedKey` as DER and check that
   `mlkemCiphertext` is 1088 bytes (ML-KEM-768) or 1568 bytes (ML-KEM-1024).
4. **Validate policy binding**: Verify that your policy binding computation
   uses the base64-encoded policy string (not the decoded JSON) as the HMAC
   message, and the DEK share (not the full DEK) as the HMAC key.
5. **Test backward compatibility**: Verify that your reader correctly handles
   the v4.3.0 manifest in Section 6, including `type`-to-`alg` inference,
   field name aliasing, bare-string policy binding, and hex-then-base64
   decoding.
