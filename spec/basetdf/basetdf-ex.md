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
5. [Example: X-ECDH-ML-KEM-768 Hybrid Key Protection](#5-example-x-ecdh-ml-kem-768-hybrid-key-protection)
6. [Example: Multi-Split with Mixed Algorithms](#6-example-multi-split-with-mixed-algorithms)
7. [Example: v4.3.0 Backward Compatibility Reading](#7-example-v430-backward-compatibility-reading)
8. [Example: Assertion with ML-DSA-44 Signing](#8-example-assertion-with-ml-dsa-44-signing)
9. [Test Vector Format Notes](#9-test-vector-format-notes)

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
  under the HKDF-derived key. For v4.3.0 backward compatibility, XOR wrapping
  may be encountered instead (see Section 7).
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
        "kas": "https://kas-pqc.example.com",
        "kid": "kas-mlkem768-2025-03",
        "sid": "",
        "protectedKey": "7fH2cMnJxP0kRr5qTgWvBdLs8+YaZOEiDhNuXw1A9Gp4KjQm6VC3oSU=",
        "ephemeralKey": "MIIB8gKCAWYAh1YJOSVrLnBqZm9xdGp2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4eg==",
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

- The `ephemeralKey` field carries the ML-KEM-768 ciphertext (1088 bytes,
  base64-encoded). This is the output of `ML-KEM.Encapsulate(kas_mlkem_pk)`.
  The KAS uses `ML-KEM.Decapsulate(kas_mlkem_sk, ct)` to recover the shared
  secret.
- No `type` field is present. ML-KEM has no legacy `type` equivalent; the
  `alg` field is the sole algorithm indicator.
- The HKDF parameters for ML-KEM key protection are: salt = `""` (empty),
  info = `"BaseTDF-KEM"`, output length = 32 bytes. The `"BaseTDF-KEM"` info
  string provides domain separation for KEM-derived keys.
- The `protectedKey` is the AES-256-GCM ciphertext of the DEK share encrypted
  under the HKDF-derived key.
- The `kid` field (`"kas-mlkem768-2025-03"`) identifies the specific ML-KEM-768
  key pair held by the KAS.

---

## 5. Example: X-ECDH-ML-KEM-768 Hybrid Key Protection

This example shows a manifest using the hybrid `X-ECDH-ML-KEM-768` algorithm,
which combines classical ECDH (P-256) with post-quantum ML-KEM-768. This is
the RECOMMENDED algorithm for PQC-ready deployments, providing security as long
as either the classical or post-quantum component remains unbroken.

### 5.1 Scenario

- **Key protection**: `X-ECDH-ML-KEM-768` (Hybrid: ECDH-P256 + ML-KEM-768)
- **Single KAS**: `https://kas.example.com`
- **Policy**: One attribute (`classification/value/top-secret`) with a
  dissemination list
- **Integrity**: `HS256` root signature and segment hashes
- **Payload**: Single segment

### 5.2 Complete Manifest

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiZjFhMmIzYzQtZDVlNi03Zjg5LWEwYjEtYzJkM2U0ZjVhNmI3IiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL3RvcC1zZWNyZXQiLCJkaXNwbGF5TmFtZSI6IkNsYXNzaWZpY2F0aW9uOiBUb3AgU2VjcmV0IiwiaXNEZWZhdWx0IjpmYWxzZSwicHViS2V5IjoiIiwia2FzVVJMIjoiaHR0cHM6Ly9rYXMuZXhhbXBsZS5jb20ifV0sImRpc3NlbSI6WyJhbGljZUBleGFtcGxlLmNvbSJdfX0=",
    "keyAccess": [
      {
        "alg": "X-ECDH-ML-KEM-768",
        "kas": "https://kas.example.com",
        "kid": "kas-hybrid-2025-02",
        "sid": "",
        "protectedKey": "Kp7mXvQ2dRa9Wn1Yg6BcTf0HjLsOeIuCxZwSt5Mk4JhNqDrEyGbAvFo=",
        "ephemeralKey": "BAN4cQ9k2p7xLMjZ+hG1sRbTv5Y3wUOeKiDf6qSrXtVuolyHWJmPgCBYAh1YJOSVrLnBqZm9xdGp2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eA==",
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
  "assertions": []
}
```

### 5.3 Notes

- The `ephemeralKey` field contains 1153 bytes (base64-encoded), structured as:
  - **Bytes 0--64** (65 bytes): Uncompressed EC P-256 ephemeral public key
    (`0x04 || x || y`). In this placeholder, the leading `BAN4cQ9k...` prefix
    represents the `0x04` tag and the x, y coordinates.
  - **Bytes 65--1152** (1088 bytes): ML-KEM-768 ciphertext. In this
    placeholder, this is the `Ah1YJOSVrLnBq...` portion through the end.
- The hybrid combiner parameters (from BaseTDF-ALG Section 4.4) are:
  - HKDF salt: `SHA256("BaseTDF-Hybrid")` -- a fixed 32-byte value.
  - HKDF IKM: `ss_classical || ss_pqc` (classical ECDH shared secret
    concatenated with ML-KEM shared secret).
  - HKDF info: `"BaseTDF-Hybrid-Key"`.
  - HKDF output length: 32 bytes.
- No `type` field is present. Hybrid algorithms have no legacy `type`
  equivalent.
- The KAS must hold **both** an EC P-256 key pair and an ML-KEM-768 key pair
  to process this KAO.
- The security property: the combined derived key is secure as long as
  **either** the ECDH or ML-KEM component remains unbroken. This provides
  defense-in-depth during the post-quantum transition.

---

## 6. Example: Multi-Split with Mixed Algorithms

This example demonstrates key splitting across two KAS instances using different
algorithms, one classical and one post-quantum. The policy requires access
authorization from both KAS instances (an `allOf` rule with attributes from
different authorities).

### 6.1 Scenario

- **Policy**: Two `allOf` attributes from different authorities, each mapping
  to a different KAS
  - `classification/value/secret` at KAS-A (RSA-based)
  - `project/value/quantum-safe` at KAS-B (ML-KEM-based)
- **Split 0** (`sid: "s-0"`): `RSA-OAEP-256` to KAS-A
- **Split 1** (`sid: "s-1"`): `ML-KEM-768` to KAS-B
- **Integrity**: `HS256` root signature and segment hashes

### 6.2 Policy Object (Decoded)

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

### 6.3 Complete Manifest

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
        "kas": "https://kas-b.example.com",
        "kid": "mlkem768-kas-b-2025",
        "sid": "s-1",
        "protectedKey": "RkVEQ0JBOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTBmZWRjYmE5ODc2NTQzMjEw",
        "ephemeralKey": "TUVNLVJFTS03NjggY2lwaGVydGV4dCAoMTA4OCBieXRlcykgZ2VuZXJhdGVkIGJ5IE1MLUtFTS5FbmNhcHN1bGF0ZShrYXNfYl9tbGtlbV9waykuIFRoaXMgaXMgYSBwbGFjZWhvbGRlciB2YWx1ZSByZXByZXNlbnRpbmcgdGhlIEtFTSBjaXBoZXJ0ZXh0IHNlbnQgdG8gS0FTLUIgZm9yIGRlY2Fwc3VsYXRpb24uIEluIGEgcmVhbCBpbXBsZW1lbnRhdGlvbiB0aGlzIHdvdWxkIGJlIGV4YWN0bHkgMTA4OCBieXRlcyBvZiBiaW5hcnkgZGF0YSwgYmFzZTY0LWVuY29kZWQu",
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

### 6.4 Key Splitting Explanation

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

### 6.5 Notes

- The two KAOs have **different** `sid` values (`"s-0"` and `"s-1"`),
  indicating they protect different shares of the DEK.
- The first KAO (`RSA-OAEP-256`) has no `ephemeralKey` because RSA-OAEP is a
  key wrapping algorithm.
- The second KAO (`ML-KEM-768`) has an `ephemeralKey` carrying the KEM
  ciphertext.
- The `policyBinding` in each KAO is computed over the **same** base64-encoded
  policy string, but with **different** HMAC keys (each KAO uses its own DEK
  share as the HMAC key).
- The `allOf` attribute rule means the KAS authorization service requires the
  requesting entity to satisfy BOTH attributes. The key splitting mechanism
  enforces this cryptographically: the DEK cannot be recovered without both
  shares.

---

## 7. Example: v4.3.0 Backward Compatibility Reading

This section shows a v4.3.0-era manifest and explains how a v4.4.0 reader
interprets it. The v4.3.0 manifest uses the legacy field names and encoding
conventions.

### 7.1 Legacy v4.3.0 Manifest

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
        "wrappedKey": "dGhlLXhvci13cmFwcGVkLWRlay1zaGFyZS1ieXRlcw==",
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

### 7.2 How a v4.4.0 Reader Interprets This Manifest

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

### 7.3 Policy Binding Verification with Legacy Encoding

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

### 7.4 Key Agreement with Legacy XOR Wrapping

Because this is a legacy `ECDH-HKDF` KAO, the `wrappedKey` (treated as
`protectedKey`) contains the XOR of the derived key and the DEK share, rather
than an AES-256-GCM ciphertext:

```
DEK_share = derived_key XOR Base64Decode(wrappedKey)
```

where `derived_key = HKDF-SHA256(salt=SHA256("TDF"), ikm=shared_secret, info="", len=32)`.

### 7.5 Notes

- The absence of `schemaVersion` in the manifest is the primary signal that
  this is a legacy TDF.
- The `protocol` field (`"kas"`) is a legacy informational field and has no
  effect on processing.
- Real implementations should handle the `"AES-256-GCM"` legacy algorithm
  name as equivalent to the v4.4.0 identifier `"A256GCM"`.

---

## 8. Example: Assertion with ML-DSA-44 Signing

This example shows a handling assertion signed with the `ML-DSA-44`
post-quantum signature algorithm (FIPS 204, NIST Level 2). ML-DSA-44 is the
RECOMMENDED post-quantum algorithm for assertion signing.

### 8.1 Scenario

- **Assertion type**: `"handling"` -- a STANAG 5636 classification marking
- **Signing algorithm**: `ML-DSA-44` (asymmetric, post-quantum)
- **ML-DSA-44 signature size**: 2420 bytes
- **Binding method**: JWS Compact Serialization

### 8.2 Assertion Object

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

### 8.3 JWS Structure Breakdown

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

### 8.4 Complete Manifest with ML-DSA-44 Assertion

```json
{
  "schemaVersion": "4.4.0",
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiZDRlNWY2YTctOGIwYy00OWQxLWExZjItM2M0ZDVlNmY3YTg5IiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL3NlY3JldCIsImRpc3BsYXlOYW1lIjoiQ2xhc3NpZmljYXRpb246IFNlY3JldCIsImlzRGVmYXVsdCI6ZmFsc2UsInB1YktleSI6IiIsImthc1VSTCI6Imh0dHBzOi8va2FzLmV4YW1wbGUuY29tIn1dLCJkaXNzZW0iOltdfX0=",
    "keyAccess": [
      {
        "alg": "X-ECDH-ML-KEM-768",
        "kas": "https://kas.example.com",
        "kid": "kas-hybrid-2025-02",
        "sid": "",
        "protectedKey": "Kp7mXvQ2dRa9Wn1Yg6BcTf0HjLsOeIuCxZwSt5Mk4JhNqDrEyGbAvFo=",
        "ephemeralKey": "BAN4cQ9k2p7xLMjZ+hG1sRbTv5Y3wUOeKiDf6qSrXtVuolyHWJmPgCBYAh1YJOSVrLnBqZm9xdGp2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eHpiZGZoamxucHJ0dnd4emJkZmhqbG5wcnR2eA==",
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

### 8.5 Notes

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
- The key protection algorithm (`X-ECDH-ML-KEM-768`) and the assertion
  signing algorithm (`ML-DSA-44`) are independent choices. This example
  demonstrates a fully post-quantum-ready TDF using hybrid key protection
  and PQC assertion signing.

---

## 9. Test Vector Format Notes

### 9.1 Placeholder Values

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

### 9.2 Real Test Vectors

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

### 9.3 Implementer Guidance

When implementing against these examples:

1. **Validate structure**: Use the JSON schemas in `../schema/BaseTDF/` to
   validate that your implementation produces structurally correct manifests.
2. **Validate field names**: Ensure your implementation uses v4.4.0 canonical
   field names (`alg`, `kas`, `kid`, `sid`, `protectedKey`, `ephemeralKey`)
   and includes deprecated aliases (`type`, `url`, `wrappedKey`) where
   specified for backward compatibility.
3. **Validate base64 lengths**: Check that the base64-decoded lengths of
   `ephemeralKey` match the expected sizes for each algorithm (65 bytes for
   EC P-256 uncompressed point, 1088 bytes for ML-KEM-768 ciphertext,
   1153 bytes for X-ECDH-ML-KEM-768 combined).
4. **Validate policy binding**: Verify that your policy binding computation
   uses the base64-encoded policy string (not the decoded JSON) as the HMAC
   message, and the DEK share (not the full DEK) as the HMAC key.
5. **Test backward compatibility**: Verify that your reader correctly handles
   the v4.3.0 manifest in Section 7, including `type`-to-`alg` inference,
   field name aliasing, bare-string policy binding, and hex-then-base64
   decoding.
