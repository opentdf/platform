# BaseTDF-KAS: Key Access Service Protocol

| | |
|---|---|
| **Document** | BaseTDF-KAS |
| **Title** | Key Access Service Protocol |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG, BaseTDF-KAO, BaseTDF-POL |
| **Referenced by** | BaseTDF-CORE |

## Table of Contents

1. [Introduction](#1-introduction)
2. [Service Discovery](#2-service-discovery)
3. [Rewrap Endpoint](#3-rewrap-endpoint)
4. [Authentication Requirements](#4-authentication-requirements)
5. [Error Semantics](#5-error-semantics)
6. [Audit Requirements](#6-audit-requirements)
7. [Rate Limiting](#7-rate-limiting)
8. [Bulk Operations](#8-bulk-operations)
9. [Algorithm Negotiation for PQC Transition](#9-algorithm-negotiation-for-pqc-transition)
10. [Key Management](#10-key-management)
11. [Security Considerations](#11-security-considerations)
12. [Normative References](#12-normative-references)

---

## 1. Introduction

### 1.1 Purpose

The Key Access Service (KAS) is the trusted intermediary in the BaseTDF
architecture that enforces access control on TDF-protected data. The KAS holds
(or has delegated access to) the private keys corresponding to the KAS public
keys used to protect DEK shares in Key Access Objects (KAOs). When an
authorized entity requests access to TDF-protected data, the KAS:

1. Verifies the identity of the requesting entity.
2. Unwraps the DEK share from the KAO using its private key.
3. Verifies the integrity of the policy binding (SI-1).
4. Evaluates the TDF's policy against the entity's current entitlements via the
   authorization service (SI-2).
5. Enforces dissemination restrictions (SI-3).
6. Re-encrypts (rewraps) the DEK share to the client's ephemeral public key.
7. Logs the access attempt (SI-8).

The KAS is the root of trust for key release decisions. Compromise of the KAS
private key material allows decryption of any TDF whose KAO references that
key. Implementations SHOULD use hardware security modules (HSMs) or equivalent
key protection mechanisms (see BaseTDF-SEC Section 3.1.1).

### 1.2 Scope

This document defines:

- The public key discovery endpoint for algorithm and key negotiation.
- The rewrap endpoint: request format, processing flow, and response format.
- Authentication requirements, including DPoP binding.
- Error semantics and their security rationale.
- Audit logging requirements for rewrap operations.
- Rate limiting recommendations.
- Bulk operation semantics for processing multiple KAOs and policies.
- Algorithm negotiation for PQC transition scenarios.
- Key management requirements for KAS key pairs.

This document does NOT define:

- The KAO structure or policy binding computation (see BaseTDF-KAO).
- The policy object schema or ABAC evaluation rules (see BaseTDF-POL).
- The algorithm parameters or key protection categories (see BaseTDF-ALG).
- The container format in which KAOs are embedded (see BaseTDF-CORE).
- The security model, threat analysis, or security invariant definitions
  (see BaseTDF-SEC).

### 1.3 Relationship to Other BaseTDF Documents

- **BaseTDF-SEC** defines the security invariants (SI-1 through SI-8) that the
  KAS protocol enforces. This document describes HOW the KAS satisfies each
  invariant; BaseTDF-SEC defines WHAT each invariant requires.
- **BaseTDF-ALG** defines the algorithm identifiers and parameters that the KAS
  advertises through its public key endpoint and validates during rewrap
  operations.
- **BaseTDF-KAO** defines the Key Access Object structure that the KAS
  processes during rewrap, including the policy binding that the KAS verifies.
- **BaseTDF-POL** defines the policy object and ABAC evaluation rules that the
  KAS applies during policy evaluation.
- **BaseTDF-CORE** defines the manifest structure that carries KAOs and policy
  data to the KAS via the client.

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][RFC2119] [RFC
8174][RFC8174] when, and only when, they appear in ALL CAPITALS, as shown here.

### 1.5 Terminology

| Term | Definition |
|---|---|
| **DEK** | Data Encryption Key. The symmetric key used to encrypt the TDF payload. |
| **DEK share** | One share of a split DEK, protected within a single KAO. |
| **DPoP** | Demonstrating Proof of Possession. An OAuth 2.0 mechanism for binding access tokens to client-held cryptographic keys ([RFC 9449][RFC9449]). |
| **KAO** | Key Access Object. The cryptographic structure in a TDF manifest that carries a protected DEK share and its policy binding (see BaseTDF-KAO). |
| **KAS** | Key Access Service. The trusted service that unwraps DEK shares and rewraps them to authorized clients. |
| **Rewrap** | The operation of unwrapping a DEK share using the KAS private key, then re-encrypting it to the client's ephemeral public key. |
| **SRT** | Signed Request Token. A JWT signed with the client's DPoP key that contains the rewrap request payload. |
| **kid** | Key identifier. A string that identifies a specific KAS key pair. |

---

## 2. Service Discovery

### 2.1 Public Key Endpoint

The KAS MUST expose a public key endpoint that allows clients to discover the
KAS's supported algorithms and retrieve public keys for TDF creation.

**Endpoint**: `GET /kas/v2/kas_public_key`

This endpoint is idempotent and has no side effects. It does NOT require
authentication.

### 2.2 Request Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | OPTIONAL | Algorithm identifier requesting a specific key type. Format: `rsa:<keysize>` or `ec:<curvename>`. Defaults to `rsa:2048` if omitted. |
| `fmt` | string | OPTIONAL | Desired response format. Values: `pkcs8` (PEM-encoded PKCS#8 public key, default), `jwk` (JSON Web Key). |
| `v` | string | OPTIONAL | Protocol version. When set to `"1"`, the response omits the `kid` field for backward compatibility with legacy clients. |

### 2.3 Response Format

```json
{
  "publicKey": "<PEM-encoded public key or JWK>",
  "kid": "<key identifier>"
}
```

| Field | Type | Description |
|---|---|---|
| `publicKey` | string | The KAS public key in the requested format. For `pkcs8` (default): PEM-encoded SPKI public key. For `jwk`: JSON Web Key representation. |
| `kid` | string | Key identifier for this public key. Clients MUST include this `kid` value in KAOs created with this key. Omitted when `v=1` is requested. |

### 2.4 Algorithm Support

The KAS MUST advertise support for at least the following algorithms:

| Algorithm Identifier | Key Type | Status |
|---|---|---|
| `rsa:2048` | RSA 2048-bit | REQUIRED (backward compatibility) |
| `ec:secp256r1` | EC P-256 | RECOMMENDED |

The KAS MAY additionally support:

| Algorithm Identifier | Key Type | Status |
|---|---|---|
| `rsa:4096` | RSA 4096-bit | OPTIONAL |
| `ec:secp384r1` | EC P-384 | OPTIONAL |
| `ec:secp521r1` | EC P-521 | OPTIONAL |

For post-quantum and hybrid algorithms, the KAS MAY support additional key
types as defined in BaseTDF-ALG Section 5. See Section 9 for algorithm
negotiation during PQC transition.

### 2.5 Error Responses

| Condition | Status Code | gRPC Code |
|---|---|---|
| Invalid or unrecognized algorithm | 404 | `NOT_FOUND` |
| No key configured for requested algorithm | 404 | `NOT_FOUND` |
| Internal configuration error | 500 | `INTERNAL` |

### 2.6 Example

**Request**:

```
GET /kas/v2/kas_public_key?algorithm=ec:secp256r1&fmt=pkcs8
```

**Response**:

```json
{
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----\n",
  "kid": "ec-p256-2025-01"
}
```

### 2.7 Legacy Public Key Endpoint

For backward compatibility, the KAS SHOULD also expose:

**Endpoint**: `GET /kas/kas_public_key` (DEPRECATED)

This legacy endpoint returns the public key as a plain string value instead of
a structured response. For RSA keys, the response is a PEM-encoded PKCS#8
public key. For EC keys, the response is a PEM-encoded certificate.

New implementations MUST use the `/kas/v2/kas_public_key` endpoint. The legacy
endpoint MAY be removed in a future version.

---

## 3. Rewrap Endpoint

### 3.1 Overview

The rewrap endpoint is the primary operational endpoint of the KAS. It receives
a request containing one or more KAOs and their associated policies, evaluates
access control, and returns re-encrypted DEK shares to authorized clients.

**Endpoint**: `POST /kas/v2/rewrap`

### 3.2 Request Format

The rewrap request contains a single field: the Signed Request Token (SRT).

```json
{
  "signedRequestToken": "<JWT string>"
}
```

The `signedRequestToken` is a JWT signed by the client's DPoP private key. The
JWT payload contains a `requestBody` claim whose value is a JSON-serialized
`UnsignedRewrapRequest` (see Section 3.3).

### 3.3 Unsigned Rewrap Request

The `requestBody` claim within the SRT contains the following structure:

```json
{
  "clientPublicKey": "<PEM-encoded client ephemeral public key>",
  "requests": [
    {
      "policy": {
        "id": "<policy-identifier>",
        "body": "<base64-encoded policy JSON>"
      },
      "keyAccessObjects": [
        {
          "keyAccessObjectId": "<kao-identifier>",
          "keyAccessObject": { ... }
        }
      ],
      "algorithm": "<algorithm-identifier>"
    }
  ]
}
```

#### 3.3.1 Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `clientPublicKey` | string | REQUIRED | The client's ephemeral public key in PEM format. The KAS uses this key to re-encrypt DEK shares for secure delivery to the client. |
| `requests` | array | REQUIRED | Array of policy requests. MUST contain at least one entry. Each entry groups a policy with its associated KAOs. |

#### 3.3.2 Policy Request Fields

Each entry in the `requests` array contains:

| Field | Type | Required | Description |
|---|---|---|---|
| `policy` | object | REQUIRED | Policy metadata with `id` (unique identifier within the request) and `body` (base64-encoded policy JSON). |
| `keyAccessObjects` | array | REQUIRED | Array of KAO wrappers, each with a `keyAccessObjectId` and a `keyAccessObject`. MUST contain at least one entry. |
| `algorithm` | string | OPTIONAL | Algorithm identifier for this group. Defaults to `rsa:2048` if omitted. Values: `ec:secp256r1`, `rsa:2048`, or other identifiers from BaseTDF-ALG. |

#### 3.3.3 Key Access Object Wrapper

Each entry in `keyAccessObjects` contains:

| Field | Type | Required | Description |
|---|---|---|---|
| `keyAccessObjectId` | string | REQUIRED | An ephemeral identifier for this KAO, unique within the request. Used to correlate request KAOs with response results. |
| `keyAccessObject` | object | REQUIRED | The Key Access Object as defined in BaseTDF-KAO Section 2. Contains `wrappedKey` (or `protectedKey`), `policyBinding`, `kid`, and other fields. |

#### 3.3.4 Example Request Body

```json
{
  "clientPublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...\n-----END PUBLIC KEY-----",
  "requests": [
    {
      "policy": {
        "id": "policy-0",
        "body": "eyJ1dWlkIjoiNWUyZjdmYTYtYTkzZS00YjliLThmNzMtMmZkNjk0YzBiNGQ4IiwiYm9keSI6ey4uLn19"
      },
      "keyAccessObjects": [
        {
          "keyAccessObjectId": "kao-0",
          "keyAccessObject": {
            "type": "wrapped",
            "kid": "rsa-2048-2025-01",
            "url": "https://kas.example.com",
            "wrappedKey": "TUlJQ0lqQU5CZ2txaGtpRzl3...",
            "policyBinding": {
              "alg": "HS256",
              "hash": "YTgzNWQ2ZjRlN2IxNDg5OGJjZjQ3..."
            }
          }
        }
      ],
      "algorithm": "rsa:2048"
    }
  ]
}
```

### 3.4 Processing Flow

For each policy request in the `requests` array, the KAS MUST perform the
following steps. Each policy request is processed independently; a failure in
one policy request MUST NOT affect the processing of other policy requests.

```
┌──────────────────────────────────────────────────────────┐
│ 1. Extract and verify Signed Request Token (SRT)         │
│    - Parse JWT from signedRequestToken                   │
│    - Validate temporal claims (iat, exp)                 │
│    - Verify SRT signature against DPoP key (Section 4)   │
│    - Extract UnsignedRewrapRequest from requestBody      │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│ 2. Verify entity identity                                │
│    - Extract entity info from authenticated context      │
│    - Verify DPoP binding to access token (SI-4)          │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
        ┌────────────────┴────────────────┐
        │  FOR EACH policy request:       │
        └────────────────┬────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│ 3. For each KAO in the policy request:                   │
│    a. Look up KAS private key by kid                     │
│    b. Unwrap DEK share using KAS private key             │
│    c. Verify policy binding (SI-1):                      │
│       - Compute HMAC-SHA256(DEK_share, policy_base64)    │
│       - Constant-time compare with policyBinding.hash    │
│       - REJECT KAO if mismatch                          │
│    d. Record KAO result (success or per-KAO error)       │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│ 4. Evaluate policy via authorization service (SI-2)      │
│    - Submit data attributes + entity token               │
│    - Receive PERMIT or DENY decision                     │
│    - DENY if authorization service unavailable           │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│ 5. Check dissemination list (SI-3)                       │
│    - If dissem list is non-empty:                        │
│      verify entity identity appears in list              │
│    - DENY if entity not found                            │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│ 6. For each verified KAO where access is PERMITTED:      │
│    - Rewrap DEK share to client's ephemeral public key   │
│    - Record rewrapped key in result                      │
│ 7. Log audit event for each KAO (SI-8)                   │
│    - Entity identity, policy UUID, algorithm, kid        │
│    - permit/deny result                                  │
│    - Erase plaintext DEK share from memory (SI-7)        │
└──────────────────────────────────────────────────────────┘
```

### 3.5 Rewrap Operation

The rewrap operation re-encrypts a DEK share from the KAS's private key domain
to the client's ephemeral public key domain. The specific procedure depends on
the client's public key type:

**RSA client key**: The DEK share is encrypted using the client's RSA public
key with RSA-OAEP.

**EC client key**: The KAS generates an ephemeral key pair, performs ECDH key
agreement with the client's public key, derives a symmetric key via HKDF, and
encrypts the DEK share with AES-256-GCM. The KAS's ephemeral public key is
returned in the `sessionPublicKey` field of the response.

In both cases, the plaintext DEK share MUST be securely erased from KAS memory
immediately after the rewrap operation completes (SI-7).

### 3.6 Response Format

```json
{
  "sessionPublicKey": "<PEM-encoded KAS ephemeral public key>",
  "responses": [
    {
      "policyId": "policy-0",
      "results": [
        {
          "keyAccessObjectId": "kao-0",
          "status": "permit",
          "kasWrappedKey": "<base64-encoded rewrapped DEK share>"
        }
      ]
    }
  ]
}
```

#### 3.6.1 Top-Level Response Fields

| Field | Type | Description |
|---|---|---|
| `sessionPublicKey` | string | KAS's ephemeral session public key in PEM format. REQUIRED for EC-based rewrap operations. Empty for RSA-based rewrap. The client uses this key to perform ECDH key agreement and derive the symmetric key needed to decrypt the `kasWrappedKey` values. |
| `responses` | array | Array of per-policy results. One entry per policy request in the original request. |

#### 3.6.2 Policy Result Fields

| Field | Type | Description |
|---|---|---|
| `policyId` | string | Matches the `policy.id` from the corresponding request entry. |
| `results` | array | Array of per-KAO results for this policy. One entry per KAO in the original request. |

#### 3.6.3 KAO Result Fields

| Field | Type | Description |
|---|---|---|
| `keyAccessObjectId` | string | Matches the `keyAccessObjectId` from the corresponding request entry. |
| `status` | string | `"permit"` if the rewrap succeeded, `"fail"` if it did not. |
| `kasWrappedKey` | bytes | Present when `status` is `"permit"`. The DEK share re-encrypted to the session key derived from the client's ephemeral public key. |
| `error` | string | Present when `status` is `"fail"`. A human-readable error description. See Section 5 for error semantics. |
| `metadata` | object | OPTIONAL. Key-value metadata associated with this result. MAY contain `X-Required-Obligations` with an array of obligation FQNs that the client MUST fulfill. |

#### 3.6.4 Example Response

```json
{
  "sessionPublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...\n-----END PUBLIC KEY-----",
  "responses": [
    {
      "policyId": "policy-0",
      "results": [
        {
          "keyAccessObjectId": "kao-0",
          "status": "permit",
          "kasWrappedKey": "dGhlIHJld3JhcHBlZCBrZXkgbWF0ZXJpYWw..."
        },
        {
          "keyAccessObjectId": "kao-1",
          "status": "fail",
          "error": "permission denied"
        }
      ]
    }
  ]
}
```

### 3.7 Legacy V1 Request Format

For backward compatibility, the KAS MUST support a legacy single-KAO request
format where the `requestBody` within the SRT contains:

```json
{
  "authToken": "<access token>",
  "keyAccess": { ... },
  "policy": "<base64-encoded policy>",
  "clientPublicKey": "<PEM-encoded public key>",
  "algorithm": "<algorithm identifier>"
}
```

When the KAS receives an SRT whose `requestBody` has no `requests` array, it
MUST interpret the request as a v1 legacy request and convert it internally to
the v2 bulk format with a single policy request containing a single KAO.

The legacy response format uses the `entityWrappedKey` field (a single
rewrapped key) instead of the structured `responses` array. The KAS MUST
return the legacy response format when processing a v1 request.

---

## 4. Authentication Requirements

### 4.1 DPoP-Bound Access Tokens (SI-4)

For production deployments, rewrap requests MUST include DPoP (Demonstrating
Proof of Possession) binding per [RFC 9449][RFC9449]. DPoP provides a
cryptographic proof that the client presenting the access token possesses the
private key associated with the token, preventing token theft and replay
attacks.

The authentication chain for a rewrap request is:

```
DPoP private key
    │
    ├── signs DPoP proof ──────────── presented with access token
    │
    └── signs SRT ─────────────────── contains rewrap request body
                                       (clientPublicKey, KAOs, policies)
```

### 4.2 DPoP Verification

The KAS MUST perform the following verification steps:

1. **Extract DPoP key**: The KAS MUST extract the DPoP public key (JWK) from
   the authenticated request context. This key is established during the DPoP
   proof verification performed by the authentication layer.

2. **Verify SRT signature**: The KAS MUST verify that the SRT (the
   `signedRequestToken` JWT) is signed with the same key as the DPoP proof.
   This binds the rewrap request body to the authenticated entity.

3. **Validate SRT claims**: The KAS MUST validate the temporal claims in the
   SRT:
   - `iat` (issued at): MUST be present. The KAS SHOULD reject tokens issued
     more than a reasonable skew window in the past (implementation-specific,
     typically 5 minutes).
   - `exp` (expiration): If present, the KAS MUST reject expired tokens.

### 4.3 Non-DPoP Deployments

Deployments that do not enforce DPoP MUST document this as a known deviation
from the security model (see BaseTDF-SEC Section 5, SI-4). When DPoP is not
available:

- The KAS MUST still verify the SRT structure and extract the request body.
- The KAS SHOULD log a warning indicating that the request lacks DPoP binding.
- The KAS MUST implement compensating controls such as short-lived access
  tokens and network-level access restrictions.

### 4.4 Entity Identity Extraction

The KAS MUST extract the entity identity from the authenticated access token.
The following claims are used:

| Claim | Purpose |
|---|---|
| `sub` | The entity's unique identifier. Used for dissemination list checks (SI-3) and audit logging (SI-8). |
| `clientId` | The client application identifier, where available. Used for audit logging. |

---

## 5. Error Semantics

### 5.1 Design Principle: Uniform Denial

The KAS error response design is driven by a security requirement: an attacker
MUST NOT be able to distinguish between different denial reasons through error
codes or messages. Specifically, the KAS MUST NOT reveal whether a failure was
caused by:

- Policy binding verification failure (SI-1).
- Authorization denial (SI-2).
- Dissemination list exclusion (SI-3).

If these failures returned distinguishable error codes, an attacker with valid
credentials could use the KAS as a **chosen-policy oracle**: by crafting TDFs
with known policies and observing the specific error code returned, the
attacker could determine whether a policy binding is valid (revealing
information about the DEK share) or whether specific attribute entitlements are
held (enabling attribute enumeration).

### 5.2 Error Code Mapping

| HTTP Status | gRPC Code | Condition | Description |
|---|---|---|---|
| 400 | `INVALID_ARGUMENT` | Malformed request | Missing required fields, unparseable SRT, invalid JSON structure, invalid client public key, missing KAOs. |
| 401 | `UNAUTHENTICATED` | Authentication failure | Invalid access token, expired token, missing DPoP proof, DPoP key mismatch, invalid SRT signature. |
| 403 | `PERMISSION_DENIED` | Access denied | Policy binding failure, authorization denial, dissemination exclusion, or any combination thereof. |
| 500 | `INTERNAL` | Server error | Unexpected internal errors, HSM failures, authorization service communication failures. |

### 5.3 Uniform 403 Requirement

**CRITICAL**: The KAS MUST return the same error code (`403` /
`PERMISSION_DENIED`) for ALL of the following conditions:

1. Policy binding verification failure (HMAC mismatch).
2. Authorization service denial (entity lacks required entitlements).
3. Dissemination list exclusion (entity not in `dissem` list).

The error message accompanying a 403 response MUST NOT contain information
that distinguishes between these conditions. A generic message such as
`"permission denied"` or `"access denied"` MUST be used.

The KAS MAY log detailed failure reasons internally for operational
diagnostics (see Section 6), but these details MUST NOT be exposed to the
client.

### 5.4 Per-KAO Error Reporting

In bulk requests, each KAO result carries its own `status` and optional
`error` field. Per-KAO errors follow the same uniformity principle:

- A KAO with status `"fail"` and error `"permission denied"` does not reveal
  whether the failure was due to binding, authorization, or dissemination.
- KAOs that fail due to structural issues (missing `kid`, unrecognized
  algorithm) MAY return more specific error messages, as these do not reveal
  information about policy evaluation or key material.

### 5.5 Request-Level vs. KAO-Level Errors

Errors are reported at two levels:

1. **Request-level errors** (HTTP status codes): Returned when the entire
   request is invalid. Examples: malformed SRT, authentication failure,
   unparseable request body. When a request-level error occurs, no per-KAO
   results are returned.

2. **KAO-level errors** (per-result status): Returned within the structured
   response when individual KAOs fail while others may succeed. The HTTP
   response code is 200 even when individual KAOs have `status: "fail"`.

---

## 6. Audit Requirements

### 6.1 Audit Obligation (SI-8)

The KAS MUST log an audit event for every rewrap attempt. Audit logging is a
normative requirement defined in BaseTDF-SEC Section 5, SI-8. Failure to
produce audit records for rewrap operations is a conformance violation.

### 6.2 Audit Event Structure

Each audit record MUST include at minimum the following fields:

| Field | Description | Source |
|---|---|---|
| **Entity identity** | The `sub` claim from the authenticated access token. | Access token |
| **Policy UUID** | The unique identifier of the policy being evaluated. | Policy `uuid` field |
| **Algorithm** | The key access algorithm identifier (e.g., `rsa:2048`, `ec:secp256r1`). | Request `algorithm` field |
| **KAS key identifier** | The `kid` of the KAS key used for unwrapping. When a legacy KAO omits `kid`, an indication that legacy key lookup was used. | KAO `kid` field |
| **Policy binding** | The `policyBinding.hash` value from the KAO. | KAO `policyBinding.hash` |
| **Access decision** | `permit` or `deny` (recorded as action result). | Evaluation outcome |
| **Timestamp** | The time of the rewrap attempt in [RFC 3339][RFC3339] format. | System clock |
| **Request context** | The requesting client's IP address and user agent, where available. | Request headers |

### 6.3 Audit Event Example

```json
{
  "object": {
    "type": "key_object",
    "id": "5e2f7fa6-a93e-4b9b-8f73-2fd694c0b4d8",
    "attributes": {
      "attrs": [
        "https://example.com/attr/classification/value/secret"
      ],
      "assertions": [],
      "permissions": []
    }
  },
  "action": {
    "type": "rewrap",
    "result": "success"
  },
  "actor": {
    "id": "alice@example.com",
    "attributes": []
  },
  "eventMetaData": {
    "keyID": "rsa-2048-2025-01",
    "policyBinding": "YTgzNWQ2ZjRlN2IxNDg5OGJjZjQ3...",
    "tdfFormat": "tdf3",
    "algorithm": "rsa:2048"
  },
  "clientInfo": {
    "platform": "kas",
    "userAgent": "opentdf-sdk-js/4.4.0",
    "requestIP": "192.0.2.1"
  },
  "requestId": "req-abc123",
  "timestamp": "2025-02-15T14:32:00Z"
}
```

### 6.4 Key Material Exclusion

Audit records MUST NOT contain key material under any circumstances:

- Audit records for **denied** requests MUST NOT include the wrapped key,
  unwrapped DEK share, or rewrapped key.
- Audit records for **permitted** requests MUST NOT include the plaintext DEK
  share or the rewrapped key. The `policyBinding.hash` MAY be included as it
  is a one-way function output and does not reveal key material.

### 6.5 Audit Record Format

Audit records SHOULD be emitted as structured data (JSON) suitable for
ingestion by SIEM (Security Information and Event Management) platforms.
Implementations MAY additionally emit audit records in other formats (e.g.,
syslog, OpenTelemetry spans) as appropriate for the deployment environment.

---

## 7. Rate Limiting

### 7.1 Recommendation

The KAS SHOULD implement rate limiting on the rewrap endpoint to mitigate:

- **Oracle attacks**: An attacker with valid credentials probing policy
  evaluation by submitting crafted TDFs at high volume (see BaseTDF-SEC
  Section 4.3).
- **Attribute enumeration**: Systematic probing to discover which attributes
  an entity holds (see BaseTDF-SEC Section 4.3).
- **Denial of service**: Overwhelming the KAS with rewrap requests to degrade
  service for legitimate users.

### 7.2 Per-Entity Rate Limiting

Rate limits SHOULD be applied per authenticated entity, not globally. Global
rate limits do not prevent a single attacker from consuming the entire budget,
and they impose unnecessary restrictions on legitimate concurrent access
patterns.

### 7.3 Implementation Guidance

The specific rate limit thresholds are deployment-dependent and outside the
scope of this specification. Implementations SHOULD consider:

- The expected volume of legitimate rewrap requests per entity per time
  window.
- The computational cost of each rewrap operation (asymmetric decryption and
  encryption).
- The detection latency for anomalous access patterns from audit logs.

Rate limit responses SHOULD use HTTP 429 (Too Many Requests) with a
`Retry-After` header indicating when the client may retry.

---

## 8. Bulk Operations

### 8.1 Overview

The v2 rewrap endpoint supports bulk operations: multiple policy requests, each
containing multiple KAOs, in a single rewrap request. Bulk operations improve
efficiency by amortizing the authentication overhead and reducing round trips
between the client and KAS.

### 8.2 Multiple Policies per Request

A single rewrap request MAY contain multiple policy requests in the `requests`
array. Each policy request is evaluated independently:

- A policy that fails authorization does not affect other policies in the same
  request.
- The KAS MUST return per-policy results for all policies in the request.

### 8.3 Multiple KAOs per Policy

Each policy request MAY contain multiple KAOs in the `keyAccessObjects` array.
KAOs within the same policy request share the same policy and algorithm
identifier but represent different key splits or alternative KAS paths.

Each KAO is processed independently:

- A KAO that fails binding verification does not block processing of other
  KAOs in the same policy request.
- Each KAO result carries its own `status` (permit or fail) and either a
  `kasWrappedKey` or an `error`.

### 8.4 Result Correlation

Clients correlate request entries with response results using the identifiers:

- `policy.id` in the request maps to `policyId` in the response.
- `keyAccessObjectId` in the request maps to `keyAccessObjectId` in the
  response.

These identifiers are ephemeral (scoped to the request) and carry no semantic
meaning beyond correlation.

### 8.5 Partial Success

A bulk rewrap response MAY contain a mix of successful and failed results. The
HTTP response code is 200 even when individual KAOs or policies fail. Clients
MUST inspect the per-KAO `status` field to determine which DEK shares were
successfully rewrapped.

### 8.6 Authorization Batching

When a request contains multiple policies, the KAS MAY batch the authorization
queries to the authorization service for efficiency. However, each policy MUST
be independently evaluated; the KAS MUST NOT merge or combine policy
evaluations across different policy requests.

---

## 9. Algorithm Negotiation for PQC Transition

### 9.1 Discovery-Based Negotiation

Algorithm negotiation in BaseTDF is discovery-based: the client queries the KAS
public key endpoint (Section 2) to determine which algorithms and key types the
KAS supports, then selects an algorithm at TDF creation time.

The negotiation flow is:

```
1. Client queries  GET /kas/v2/kas_public_key?algorithm=<preferred>
2. If the KAS supports the algorithm, it returns the public key and kid.
3. If the KAS does not support the algorithm, it returns 404 (NOT_FOUND).
4. Client falls back to a different algorithm and retries.
5. Client creates the TDF using the negotiated algorithm and the returned kid.
```

### 9.2 PQC Transition Requirements

During the transition from classical to post-quantum cryptography (see
BaseTDF-SEC Section 8), the KAS MUST support the following:

1. **Concurrent algorithm support**: The KAS MUST support classical and
   post-quantum algorithms simultaneously. A KAS that only supports
   post-quantum algorithms cannot process existing TDFs created with classical
   algorithms.

2. **Algorithm validation**: The KAS MUST reject KAOs with unrecognized
   algorithm identifiers (SI-6). The KAS MUST NOT silently downgrade or
   substitute algorithms.

3. **Key type coexistence**: The KAS MUST maintain key pairs for all supported
   algorithm families concurrently. For example, during hybrid transition,
   the KAS needs RSA key pairs (for legacy TDFs), EC key pairs (for ECDH-based
   TDFs), and ML-KEM key pairs (for post-quantum TDFs).

### 9.3 Hybrid Algorithm Support

For hybrid algorithms (e.g., `X-ECDH-ML-KEM-768`), the KAS MUST hold both the
classical and post-quantum key pairs required for the combined operation:

- EC P-256 key pair for the ECDH component.
- ML-KEM-768 key pair for the KEM component.

The KAS MAY advertise hybrid support through the public key endpoint by
accepting hybrid algorithm identifiers and returning a key identifier that
references both key pairs. See BaseTDF-ALG Section 4.4 for the hybrid
algorithm specification and BaseTDF-KAO Section 4.4 for the hybrid KAO
processing procedure.

### 9.4 Client Algorithm Selection

Clients SHOULD select algorithms based on the following priority:

1. Hybrid (classical + PQC) if the KAS supports it and the data's
   confidentiality requirements warrant quantum resistance.
2. EC-based (ECDH-HKDF) for new TDFs when hybrid is not available.
3. RSA-based (RSA-OAEP) for maximum backward compatibility.

The client's algorithm choice is recorded in the KAO's `alg` field and the
request's `algorithm` field, enabling the KAS to select the correct processing
path during rewrap.

---

## 10. Key Management

### 10.1 Key Identification

Every KAS key pair MUST be assigned a unique key identifier (`kid`). The `kid`
is:

- Included in the public key endpoint response (Section 2.3).
- Recorded in the KAO by the client at TDF creation time (see BaseTDF-KAO
  Section 2.2).
- Used by the KAS during rewrap to select the correct private key for
  unwrapping.

Key identifiers MUST be unique within a KAS instance and SHOULD be unique
across KAS instances in a deployment.

### 10.2 Supported Key Types

The KAS MUST support the following key types:

| Key Type | Algorithm Family | Status |
|---|---|---|
| RSA 2048-bit | RSA-OAEP | REQUIRED (backward compatibility) |
| EC P-256 | ECDH-HKDF | RECOMMENDED |

The KAS MAY additionally support:

| Key Type | Algorithm Family | Status |
|---|---|---|
| RSA 4096-bit | RSA-OAEP-256 | OPTIONAL |
| EC P-384 | ECDH-HKDF | OPTIONAL |
| EC P-521 | ECDH-HKDF | OPTIONAL |
| ML-KEM-768 | ML-KEM | OPTIONAL (PQC) |
| ML-KEM-1024 | ML-KEM | OPTIONAL (PQC) |

### 10.3 Key Rotation

The KAS MUST support key rotation -- the process of introducing new key pairs
while maintaining the ability to process KAOs created with older keys.

Key rotation requirements:

1. **Multiple active keys**: The KAS MUST support multiple active key pairs
   concurrently. During rotation, both the old and new keys MUST be available
   for unwrapping.

2. **New key preference**: The public key endpoint SHOULD return the newest
   non-legacy key for a given algorithm. This ensures new TDFs are created with
   current keys while old TDFs remain accessible.

3. **Legacy key support**: Keys that are no longer advertised via the public
   key endpoint MUST remain available for unwrap operations until all TDFs
   referencing those keys have either expired or been re-encrypted.

4. **Key decommissioning**: When a key pair is decommissioned, the private key
   MUST be securely destroyed per SI-7. Organizations SHOULD re-encrypt
   affected TDFs to active keys before decommissioning.

### 10.4 Key Delegation

The KAS MAY delegate key storage and cryptographic operations to an external
key management system (e.g., HSM, cloud KMS, or a key index service). When
delegation is used:

- The KAS MUST resolve key identifiers through the delegator before falling
  back to local key storage.
- The delegator MUST support the same `kid`-based key lookup semantics.
- Cryptographic operations (unwrap, rewrap) MAY be performed by the delegator
  or by the KAS after retrieving key material from the delegator, depending on
  the security requirements of the deployment.

### 10.5 Legacy KAOs Without `kid`

KAOs created by older TDF implementations MAY omit the `kid` field. When
processing a KAO without a `kid`:

1. The KAS MUST attempt to unwrap the DEK share using available keys for the
   indicated algorithm, trying non-legacy keys first.
2. The KAS SHOULD log a warning when processing `kid`-less KAOs, as this
   increases computational cost and the surface for potential oracle attacks
   (see BaseTDF-SEC Section 4.4).
3. New TDF implementations MUST include a `kid` field in all KAOs.

---

## 11. Security Considerations

### 11.1 KAS as Root of Trust

The KAS operates as the root of trust for key release decisions in the BaseTDF
architecture (see BaseTDF-SEC Section 3.1.1). All access control enforcement
depends on the KAS correctly implementing the security invariants. A
compromised KAS can release key material to unauthorized entities. Deployments
MUST protect the KAS with appropriate physical, logical, and operational
security controls.

### 11.2 Security Invariant Compliance

The following table maps BaseTDF-SEC security invariants to the KAS protocol
mechanisms that enforce them:

| Invariant | Requirement | KAS Mechanism |
|---|---|---|
| **SI-1** | Policy binding integrity | KAS verifies HMAC-SHA256 binding before key release (Section 3.4, step 3c). Constant-time comparison prevents timing side channels. |
| **SI-2** | Authorization before key release | KAS submits policy to authorization service and requires explicit PERMIT before rewrapping (Section 3.4, step 4). |
| **SI-3** | Dissemination enforcement | KAS checks entity identity against `dissem` list when non-empty (Section 3.4, step 5). |
| **SI-4** | DPoP binding | SRT is signed with DPoP key; KAS verifies signature chain (Section 4). |
| **SI-5** | Payload integrity | Not directly enforced by KAS (client-side); KAS verifies KAO integrity via policy binding. |
| **SI-6** | Algorithm validation | KAS validates KAO algorithm fields against supported set; rejects unrecognized algorithms (Section 9.2). |
| **SI-7** | Key material hygiene | Plaintext DEK shares erased from KAS memory after rewrap (Section 3.5). |
| **SI-8** | Audit logging | Every rewrap attempt logged with required fields (Section 6). |

### 11.3 Transport Security

All communication with the KAS MUST be protected by TLS. However, the security
model does not depend solely on TLS:

- The SRT is signed by the client's DPoP key, providing request integrity
  independent of TLS.
- Rewrapped key material is encrypted to the client's ephemeral public key,
  providing end-to-end key confidentiality even when TLS is terminated at an
  intermediary (reverse proxy, load balancer, or CDN node).

This layered approach ensures that a TLS-terminating proxy cannot observe
plaintext key material in transit.

### 11.4 Oracle Attack Mitigation

The uniform error semantics (Section 5) are the primary defense against oracle
attacks:

- **Chosen-policy oracle**: By returning identical error codes for binding
  failure, authorization denial, and dissemination exclusion, the KAS prevents
  an attacker from distinguishing these conditions and thereby probing policy
  evaluation or key material validity.
- **Timing oracle**: Policy binding verification MUST use constant-time
  comparison. Implementations SHOULD ensure that the total processing time
  for denied requests does not systematically differ from permitted requests,
  though this is challenging to achieve perfectly.

Rate limiting (Section 7) provides a complementary defense by limiting the
volume of probing attempts.

### 11.5 SRT Replay Prevention

The SRT contains temporal claims (`iat`, `exp`) that bound its validity window.
The KAS validates these claims with an acceptable clock skew to prevent replay
attacks. Even if an SRT is replayed within the validity window, the rewrapped
key is encrypted to the client's ephemeral public key from the original
request; an attacker who replays the SRT cannot decrypt the response without
the corresponding private key.

### 11.6 Client Public Key Validation

The KAS MUST validate the `clientPublicKey` provided in the rewrap request
before using it for key encapsulation. Invalid or malicious public keys could
cause cryptographic errors or, in pathological cases, enable key recovery
attacks. The KAS MUST reject requests with malformed or unsupported client
public keys with a 400 error.

### 11.7 Fail-Closed Behavior

The KAS MUST implement fail-closed behavior throughout:

- If the authorization service is unreachable, the KAS MUST deny access.
- If policy binding verification encounters an error (not just a mismatch),
  the KAS MUST deny access.
- If a KAO contains an unrecognized algorithm, the KAS MUST deny access.
- If the DPoP verification fails, the KAS MUST deny access.

The KAS MUST NOT fall back to a default-permit decision under any failure
condition.

---

## 12. Normative References

| Reference | Title |
|---|---|
| [BaseTDF-SEC][BaseTDF-SEC] | Security Model and Zero Trust Architecture, v4.4.0 |
| [BaseTDF-ALG][BaseTDF-ALG] | Algorithm Registry, v4.4.0 |
| [BaseTDF-KAO][BaseTDF-KAO] | Key Access Object, v4.4.0 |
| [BaseTDF-POL][BaseTDF-POL] | Policy and Attribute-Based Access Control, v4.4.0 |
| [RFC 2119][RFC2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 3339][RFC3339] | Date and Time on the Internet: Timestamps |
| [RFC 8174][RFC8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |
| [RFC 9449][RFC9449] | OAuth 2.0 Demonstrating Proof of Possession (DPoP) |
| [NIST FIPS 203][FIPS203] | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) |
| [NIST SP 800-38D][SP800-38D] | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC |

[BaseTDF-SEC]: basetdf-sec.md
[BaseTDF-ALG]: basetdf-alg.md
[BaseTDF-KAO]: basetdf-kao.md
[BaseTDF-POL]: basetdf-pol.md
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC3339]: https://www.rfc-editor.org/rfc/rfc3339
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC9449]: https://www.rfc-editor.org/rfc/rfc9449
[FIPS203]: https://doi.org/10.6028/NIST.FIPS.203
[SP800-38D]: https://doi.org/10.6028/NIST.SP.800-38D
