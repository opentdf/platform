# BaseTDF-ASN: Assertions

| Field | Value |
|-------|-------|
| **Title** | Assertions |
| **Document** | BaseTDF-ASN |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Depends on** | BaseTDF-ALG, BaseTDF-SEC, BaseTDF-INT |
| **Referenced by** | BaseTDF-CORE |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Assertion Object Schema](#2-assertion-object-schema)
3. [Statement Object](#3-statement-object)
4. [Assertion Types](#4-assertion-types)
5. [Binding Mechanism](#5-binding-mechanism)
6. [Assertion Hash Computation](#6-assertion-hash-computation)
7. [Signing Assertions](#7-signing-assertions)
8. [Verifying Assertions](#8-verifying-assertions)
9. [PQC Considerations](#9-pqc-considerations)
10. [Security Considerations](#10-security-considerations)
11. [Normative References](#11-normative-references)

---

## 1. Introduction

### 1.1 Purpose

Assertions are optional verifiable statements that can be bound to a Trusted
Data Format (TDF) object. They provide a mechanism for attaching metadata,
handling instructions, and other claims to protected data in a way that is
cryptographically linked to the TDF itself.

Assertions serve two primary functions:

1. **Handling instructions**: Conveying data handling requirements such as
   classification markings, distribution restrictions, retention policies, and
   processing obligations.
2. **General metadata**: Attaching provenance, audit, or application-specific
   metadata to the TDF.

### 1.2 Scope

This document defines:

- The structure and fields of an assertion object within the TDF manifest.
- The statement formats and assertion types.
- The cryptographic binding mechanism that prevents assertions from being
  tampered with or replayed across different TDFs.
- The procedures for creating and verifying signed assertions.
- Post-quantum considerations for assertion signatures.

This document does **not** define:

- The assertion signing algorithms themselves (see BaseTDF-ALG Section 3.4 and
  Section 6).
- The manifest container format in which assertions reside (see BaseTDF-CORE).
- The security model and trust assumptions (see BaseTDF-SEC).

### 1.3 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][rfc2119]
[RFC 8174][rfc8174] when, and only when, they appear in ALL CAPITALS, as shown
here.

### 1.4 Relationship to Other Documents

- **BaseTDF-ALG**: Defines the assertion signing algorithms (`HS256`, `RS256`,
  `ES256`, `ES384`, `ML-DSA-44`, `ML-DSA-65`) and their parameters.
- **BaseTDF-SEC**: Establishes the security model and cryptographic
  requirements that assertions MUST satisfy.
- **BaseTDF-INT**: Defines the integrity verification scheme whose aggregate
  hash is incorporated into the assertion binding payload.
- **BaseTDF-CORE**: Defines the manifest structure that carries assertions.

---

## 2. Assertion Object Schema

An assertion is a JSON object within the `assertions` array of the TDF
manifest. The following is a complete example:

```json
{
  "id": "424ff3a3-50ca-4f01-a2ae-ef851cd3cac0",
  "type": "handling",
  "scope": "tdo",
  "appliesToState": "encrypted",
  "statement": {
    "format": "json+stanag5636",
    "schema": "urn:nato:stanag:5636:A:1:elements:json",
    "value": "{\"ocl\":{\"pol\":\"62c76c68-...\",\"cls\":\"SECRET\"}}"
  },
  "binding": {
    "method": "jws",
    "signature": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

### 2.1 Field Definitions

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `id` | string | REQUIRED | Unique identifier for this assertion within the TDF instance. Implementations SHOULD use UUIDs or other globally unique identifiers. |
| `type` | string | REQUIRED | The category of the assertion. See [Section 4](#4-assertion-types). |
| `scope` | string | REQUIRED | What the assertion applies to. MUST be one of `"tdo"` or `"payload"`. See [Section 2.2](#22-scope-values). |
| `appliesToState` | string | REQUIRED | Whether the statement applies to data in the `"encrypted"` or `"unencrypted"` state. See [Section 2.3](#23-appliesToState-values). |
| `statement` | object | REQUIRED | The assertion content. See [Section 3](#3-statement-object). |
| `binding` | object | OPTIONAL | Cryptographic binding that prevents modification and cross-TDF replay. See [Section 5](#5-binding-mechanism). |

**Uniqueness**: The `id` field MUST be unique within the `assertions` array of
a single TDF manifest. Implementations MUST reject manifests containing
duplicate assertion IDs.

### 2.2 Scope Values

| Value | Name | Description |
|:------|:-----|:------------|
| `"tdo"` | Trusted Data Object | The assertion applies to the entire TDF object, including the manifest, key access objects, and payload. |
| `"payload"` | Payload | The assertion applies only to the encrypted payload data. |

Implementations MUST reject assertions with unrecognized `scope` values.

### 2.3 appliesToState Values

| Value | Description |
|:------|:------------|
| `"encrypted"` | The statement applies to the data in its encrypted state. Consuming applications SHOULD evaluate such assertions before attempting decryption. |
| `"unencrypted"` | The statement applies to the data in its decrypted (plaintext) state. Consuming applications SHOULD evaluate such assertions after successful decryption. |

Implementations MUST reject assertions with unrecognized `appliesToState`
values.

---

## 3. Statement Object

The `statement` field carries the actual content of the assertion. It is a JSON
object with the following fields:

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `format` | string | REQUIRED | Describes the encoding format of the `value` field. See [Section 3.1](#31-statement-formats). |
| `schema` | string | REQUIRED | Identifies the schema or vocabulary that the `value` conforms to. This is typically a URI or well-known identifier. |
| `value` | string | REQUIRED | The assertion payload, encoded according to `format`. |

### 3.1 Statement Formats

The `format` field indicates how the `value` field is encoded. The following
formats are defined:

| Format Identifier | Description | Value Encoding |
|:------------------|:------------|:---------------|
| `"json-structured"` | A JSON object serialized as a string. | The `value` field contains a JSON object. When serialized in the manifest, the value MAY appear either as an inline JSON object or as a JSON-encoded string. Implementations MUST accept both representations. |
| `"json"` | A JSON string value. | The `value` field contains a JSON-encoded string. |
| `"base64binary"` | Base64-encoded binary data. | The `value` field contains base64-encoded ([RFC 4648][rfc4648] Section 4) binary data. |
| `"string"` | Plain text. | The `value` field contains a plain text string with no additional encoding. |

Additional format identifiers MAY be defined by applications. Format
identifiers SHOULD follow a naming convention that avoids collision with future
standardized formats (e.g., use a reverse-domain prefix for
application-specific formats).

### 3.2 Statement Value Deserialization

When the `format` is `"json-structured"`, the `value` field in the serialized
manifest MAY be either:

- A JSON object (inline), or
- A JSON string containing the serialized JSON object.

Implementations MUST handle both representations. When deserializing a
`json-structured` value that appears as an inline JSON object, the
implementation MUST re-serialize it to a JSON string for internal
representation. This ensures consistent hashing behavior (see [Section 6](#6-assertion-hash-computation)).

**Example -- inline JSON object**:

```json
{
  "statement": {
    "format": "json-structured",
    "schema": "urn:example:handling",
    "value": {
      "classification": "SECRET",
      "releasableTo": ["usa"]
    }
  }
}
```

**Example -- JSON-encoded string**:

```json
{
  "statement": {
    "format": "json-structured",
    "schema": "urn:example:handling",
    "value": "{\"classification\":\"SECRET\",\"releasableTo\":[\"usa\"]}"
  }
}
```

Both representations MUST produce the same assertion hash after
canonicalization (see [Section 6](#6-assertion-hash-computation)).

---

## 4. Assertion Types

### 4.1 Handling Assertions (type: "handling")

Handling assertions carry instructions that govern how the protected data
SHOULD be processed, distributed, retained, or destroyed by consuming
applications. Examples include:

- **Classification markings**: Security classification levels and caveats
  (e.g., STANAG 5636 markings).
- **Distribution restrictions**: Limits on who may receive or forward the data.
- **Retention policies**: How long the data must or may be retained.
- **Processing obligations**: Actions that MUST be performed before, during, or
  after data access.

Consuming applications SHOULD evaluate handling assertions and apply the
specified instructions. An application that does not understand a handling
assertion's schema SHOULD treat the data with the highest applicable
restriction or refuse to process it.

### 4.2 Other Assertions (type: "other")

Other assertions provide general-purpose metadata that is not directly related
to data handling. Examples include:

- **System metadata**: Information about the TDF creation environment (SDK
  version, operating system, creation timestamp).
- **Provenance**: Origin and lineage information for the protected data.
- **Audit markers**: Tracking identifiers for compliance and audit trails.
- **Application-specific metadata**: Custom metadata defined by the consuming
  application.

Other assertions are informational. Consuming applications MAY ignore other
assertions that they do not understand.

### 4.3 System Metadata Assertion

A well-known assertion with `id` value `"system-metadata"` and schema
`"system-metadata-v1"` is defined for recording TDF creation context. This
assertion has type `"other"`, scope `"payload"`, and `appliesToState`
`"unencrypted"`.

The statement value is a JSON object with the following fields:

| Field | Type | Description |
|:------|:-----|:------------|
| `tdf_spec_version` | string | The TDF specification version (e.g., `"4.4.0"`). |
| `creation_date` | string | The creation timestamp in [RFC 3339][rfc3339] format. |
| `operating_system` | string | The OS identifier (e.g., `"linux"`, `"darwin"`, `"windows"`). |
| `sdk_version` | string | The SDK implementation version (e.g., `"Go-0.5.0"`). |
| `go_version` | string | The Go runtime version (if applicable). |
| `architecture` | string | The CPU architecture (e.g., `"amd64"`, `"arm64"`). |

**Example**:

```json
{
  "id": "system-metadata",
  "type": "other",
  "scope": "payload",
  "appliesToState": "unencrypted",
  "statement": {
    "format": "json",
    "schema": "system-metadata-v1",
    "value": "{\"tdf_spec_version\":\"4.4.0\",\"creation_date\":\"2025-02-15T10:30:00Z\",\"operating_system\":\"linux\",\"sdk_version\":\"Go-0.5.0\",\"go_version\":\"go1.23.0\",\"architecture\":\"amd64\"}"
  },
  "binding": {
    "method": "jws",
    "signature": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

### 4.4 Extensibility

The `type` field is extensible. Applications MAY define additional assertion
types beyond `"handling"` and `"other"`. Custom types SHOULD use a namespaced
identifier (e.g., `"x-myapp-audit"`) to avoid collisions with future
standardized types.

Implementations that encounter an unrecognized assertion type MUST NOT reject
the TDF. The unrecognized assertion SHOULD be preserved if the TDF is
re-serialized.

---

## 5. Binding Mechanism

The binding mechanism cryptographically links an assertion to a specific TDF
instance. This prevents two categories of attack:

1. **Assertion tampering**: Modifying the content of an assertion after TDF
   creation.
2. **Cross-TDF replay**: Copying an assertion from one TDF and inserting it
   into another TDF's manifest.

### 5.1 Binding Object

The `binding` field is a JSON object with the following fields:

| Field | Type | Description |
|:------|:-----|:------------|
| `method` | string | The binding method. MUST be `"jws"` when present. |
| `signature` | string | A JWS Compact Serialization ([RFC 7515][rfc7515]) containing the signed binding payload. |

**Example**:

```json
{
  "binding": {
    "method": "jws",
    "signature": "eyJhbGciOiJIUzI1NiJ9.eyJhc3NlcnRpb25IYXNoIjoiNGE0NDdhMTNjNWEzMjczMGQyMGJkZjdmZWVjYjlmZmUxNjY0OWJjNzMxOTE0YjU3NGQ4MDAzNWEzOTI3Zjg2MCIsImFzc2VydGlvblNpZyI6ImJHRnlaMlZmWW1GelpUWTBYM1poYkhWbCJ9.XYZ_signature_bytes"
  }
}
```

### 5.2 JWS Binding (method: "jws")

When the binding method is `"jws"`, the `signature` field contains a JWS
Compact Serialization as defined in [RFC 7515][rfc7515], Section 3.1.

The JWS encodes a JWT ([RFC 7519][rfc7519]) whose payload contains two claims
that together bind the assertion to the specific TDF:

| JWT Claim | Key | Type | Description |
|:----------|:----|:-----|:------------|
| Assertion Hash | `assertionHash` | string | The SHA-256 hash of the canonicalized assertion object (excluding the `binding` field), encoded as a lowercase hexadecimal string. See [Section 6](#6-assertion-hash-computation). |
| Assertion Signature | `assertionSig` | string | A base64-encoded value computed over the concatenation of the TDF's aggregate integrity hash and the assertion hash. See [Section 7.2](#72-binding-payload-construction). |

The `assertionHash` claim binds the JWS to the specific assertion content. If
the assertion is modified, the hash will not match.

The `assertionSig` claim binds the assertion to the specific TDF instance by
incorporating the aggregate integrity hash of the TDF payload. This hash is
unique to each TDF and prevents the assertion from being replayed to a
different TDF.

### 5.3 Signing Algorithms

The JWS `alg` header parameter indicates which signing algorithm was used.
Assertion signing algorithms are defined in BaseTDF-ALG Section 3.4 and
Section 6. The following table summarizes their status:

| Algorithm | Description | Status |
|:----------|:------------|:-------|
| `HS256` | HMAC-SHA256 | REQUIRED |
| `RS256` | RSASSA-PKCS1-v1_5 with SHA-256 | OPTIONAL |
| `ES256` | ECDSA P-256 with SHA-256 | OPTIONAL |
| `ES384` | ECDSA P-384 with SHA-384 | OPTIONAL |
| `ML-DSA-44` | ML-DSA-44 (FIPS 204), NIST Level 2 | RECOMMENDED |
| `ML-DSA-65` | ML-DSA-65 (FIPS 204), NIST Level 3 | OPTIONAL |

All conformant implementations MUST support `HS256` for both signing and
verification of assertions.

### 5.4 Key Sources for Signing

#### 5.4.1 HS256 (Symmetric / DEK-Based)

When using `HS256`, the HMAC key is typically the TDF's Data Encryption Key
(DEK), which is the payload encryption key. This creates an **implicit
binding**: only entities that possess the DEK (i.e., entities authorized to
decrypt the TDF) can create or verify HS256-bound assertions.

If no explicit signing key is provided for an assertion, implementations MUST
default to `HS256` with the DEK as the signing key.

#### 5.4.2 RS256 / ES256 / ES384 (Asymmetric / Classical)

When using asymmetric algorithms, the signing key is an asymmetric key pair
that is independent of the DEK. The private key signs the assertion, and the
public key verifies it.

The public key MAY be conveyed in the JWS protected header using one of the
following mechanisms:

- The `jwk` header parameter ([RFC 7515][rfc7515], Section 4.1.3), containing
  the public key as a JWK ([RFC 7517][rfc7517]).
- The `x5c` header parameter ([RFC 7515][rfc7515], Section 4.1.6), containing
  an X.509 certificate chain with the signing certificate first.

When the public key is included in the JWS header, verifiers MAY use it as a
candidate verification key. Verifiers SHOULD still validate the key against a
trust store or expected key identifier before accepting the signature.

#### 5.4.3 ML-DSA-44 / ML-DSA-65 (Asymmetric / Post-Quantum)

ML-DSA signing keys are used in the same manner as classical asymmetric keys.
The private key signs and the public key verifies. ML-DSA keys are encoded as
raw bytes (per [FIPS 204][fips204]) and base64-encoded when embedded in JWS
header fields.

See [Section 9](#9-pqc-considerations) for additional post-quantum guidance.

#### 5.4.4 Hardware-Backed Keys

The signing key interface MUST support hardware-backed keys. Implementations
MUST accept any object that implements a standard cryptographic signer interface
(e.g., Go's `crypto.Signer`) as the key material. This enables assertion
signing via Hardware Security Modules (HSMs), Trusted Platform Modules (TPMs),
and cloud Key Management Services (KMS).

### 5.5 Binding is RECOMMENDED

The `binding` field is OPTIONAL in the assertion schema but is RECOMMENDED for
all assertions that influence security decisions, handling behavior, or access
control.

Assertions without a binding MUST NOT be used for security-critical decisions
(see [Section 10.1](#101-unbound-assertions)).

---

## 6. Assertion Hash Computation

The assertion hash uniquely identifies the content of an assertion. It is used
as the `assertionHash` claim in the JWS binding payload and is the primary
mechanism for detecting assertion tampering.

### 6.1 Procedure

To compute the hash of an assertion:

1. **Exclude the binding**: Create a copy of the assertion object with the
   `binding` field removed entirely (not set to null or empty -- removed from
   the JSON structure).

2. **Serialize to JSON**: Marshal the assertion object (without binding) to
   JSON.

3. **Canonicalize**: Apply JSON Canonicalization Scheme (JCS) as defined in
   [RFC 8785][rfc8785] to the serialized JSON. JCS produces a deterministic
   byte-level representation that is independent of field ordering, whitespace,
   and Unicode normalization differences.

4. **Hash**: Compute SHA-256 over the canonicalized bytes.

5. **Hex-encode**: Encode the 32-byte SHA-256 digest as a lowercase
   hexadecimal string (64 characters).

### 6.2 Pseudocode

```
function computeAssertionHash(assertion):
    // Step 1: Remove binding
    assertionCopy = deepCopy(assertion)
    delete assertionCopy.binding

    // Step 2: Serialize to JSON
    jsonBytes = JSON.serialize(assertionCopy)

    // Step 3: Canonicalize with JCS (RFC 8785)
    canonicalBytes = JCS(jsonBytes)

    // Step 4-5: Hash and hex-encode
    return hexEncode(SHA-256(canonicalBytes))
```

### 6.3 Example

Given the following assertion (without binding):

```json
{
  "id": "424ff3a3-50ca-4f01-a2ae-ef851cd3cac0",
  "type": "handling",
  "scope": "tdo",
  "appliesToState": "encrypted",
  "statement": {
    "format": "json+stanag5636",
    "schema": "urn:nato:stanag:5636:A:1:elements:json",
    "value": "{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"catl\":[{\"type\":\"P\",\"name\":\"Releasable To\",\"vals\":[\"usa\"]}],\"dcr\":\"2024-10-21T20:47:36Z\"},\"context\":{\"@base\":\"urn:nato:stanag:5636:A:1:elements:json\"}}"
  }
}
```

The assertion hash is:

```
4a447a13c5a32730d20bdf7feecb9ffe16649bc731914b574d80035a3927f860
```

---

## 7. Signing Assertions

This section defines the procedure for creating a signed assertion during TDF
creation.

### 7.1 Prerequisites

Before signing an assertion, the following MUST be available:

- The fully constructed assertion object (all required fields populated).
- The aggregate integrity hash from the TDF's integrity verification layer
  (see BaseTDF-INT). This is the concatenation of all segment hashes.
- A signing key (either the DEK for HS256 or an asymmetric key pair for other
  algorithms).

### 7.2 Binding Payload Construction

The binding payload incorporates both the assertion content and the TDF's
integrity context, creating a two-way binding:

1. **Compute the assertion hash**: Follow the procedure in
   [Section 6](#6-assertion-hash-computation) to obtain `assertionHash` as a
   hexadecimal string.

2. **Decode the assertion hash**: Decode the hexadecimal `assertionHash`
   string to raw bytes.

3. **Concatenate with aggregate hash**: Concatenate the aggregate integrity
   hash (the concatenation of all decoded segment hashes from BaseTDF-INT) with
   the decoded assertion hash bytes:

   ```
   bindingInput = aggregateHash || assertionHashBytes
   ```

4. **Base64-encode**: Encode the concatenated bytes using base64
   ([RFC 4648][rfc4648], Section 4):

   ```
   assertionSig = base64encode(bindingInput)
   ```

The two claim values for the JWT are:

- `assertionHash`: The hexadecimal assertion hash string (from step 1).
- `assertionSig`: The base64-encoded binding input (from step 4).

### 7.3 JWS Construction

1. **Create the JWT**: Construct a JWT with the following claims:

   ```json
   {
     "assertionHash": "<hex-encoded SHA-256 of canonicalized assertion>",
     "assertionSig": "<base64-encoded aggregateHash || assertionHashBytes>"
   }
   ```

2. **Select the signing algorithm**: Use the algorithm specified in the
   assertion's signing key configuration. If no explicit key is configured,
   default to `HS256` with the DEK as the key.

3. **Sign the JWT**: Sign the JWT using the JWS Compact Serialization format
   ([RFC 7515][rfc7515]) with the selected algorithm and key.

4. **Populate the binding**: Set the assertion's `binding` field:

   ```json
   {
     "method": "jws",
     "signature": "<JWS Compact Serialization>"
   }
   ```

### 7.4 Complete Signing Procedure (Pseudocode)

```
function signAssertion(assertion, aggregateHash, signingKey):
    // 1. Compute assertion hash
    assertionHash = computeAssertionHash(assertion)  // hex string

    // 2. Decode hex to bytes
    assertionHashBytes = hexDecode(assertionHash)

    // 3. Build binding input
    bindingInput = aggregateHash + assertionHashBytes

    // 4. Base64-encode
    assertionSig = base64encode(bindingInput)

    // 5. Create JWT
    jwt = newJWT()
    jwt.setClaim("assertionHash", assertionHash)
    jwt.setClaim("assertionSig", assertionSig)

    // 6. Sign
    if signingKey is empty:
        signingKey = { alg: "HS256", key: DEK }
    jwsCompact = jwt.sign(signingKey.alg, signingKey.key)

    // 7. Set binding
    assertion.binding = {
        method: "jws",
        signature: jwsCompact
    }
```

### 7.5 Legacy Compatibility

TDFs created prior to version 4.3.0 (identified by an absent or empty
`schemaVersion` field in the manifest) use the hexadecimal-encoded assertion
hash bytes directly in the concatenation (step 3 of Section 7.2) instead of
the decoded raw bytes. Implementations creating new TDFs MUST use decoded raw
bytes. Implementations reading existing TDFs MUST detect the legacy format
(by checking for an absent `schemaVersion` field) and apply the legacy
concatenation method during verification.

---

## 8. Verifying Assertions

This section defines the procedure for verifying an assertion when reading a
TDF.

### 8.1 Verification Procedure

For each assertion in the manifest's `assertions` array:

1. **Validate required fields**: Verify that `id`, `type`, `scope`,
   `appliesToState`, and `statement` are present and contain recognized values.
   If any required field is missing or unrecognized, the assertion MUST be
   rejected.

2. **Check for binding**: If the `binding` field is absent or empty, the
   assertion is unbound. Skip to step 8.

3. **Determine the verification key**:
   - If the application has registered a verification key for this assertion's
     `id`, use that key.
   - Otherwise, if a default verification key is configured, use it.
   - Otherwise, use the DEK with `HS256` as the default.

4. **Parse the JWS**: Parse the `binding.signature` field as a JWS Compact
   Serialization.

5. **Resolve the signing key**: The verification key is resolved in the
   following priority order:
   a. The explicitly configured key for this assertion ID.
   b. The configured default verification key.
   c. A public key embedded in the JWS protected header (`jwk` or `x5c`
      parameter), if present and trusted.
   d. The DEK (for `HS256` verification).

   If multiple candidate keys are available, the implementation SHOULD attempt
   verification with each until one succeeds or all fail.

6. **Verify the JWS signature**: Verify the JWS using the resolved key and
   algorithm. If verification fails, the assertion MUST be rejected with an
   error.

7. **Validate the claims**:
   a. Extract the `assertionHash` and `assertionSig` claims from the verified
      JWT.
   b. Recompute the assertion hash using the procedure in
      [Section 6](#6-assertion-hash-computation).
   c. Compare the recomputed hash with the `assertionHash` claim. If they do
      not match, the assertion MUST be rejected (the assertion content has been
      modified).
   d. Recompute the expected `assertionSig` value using the aggregate
      integrity hash from the TDF and the assertion hash bytes (following the
      procedure in [Section 7.2](#72-binding-payload-construction)).
   e. Compare the recomputed `assertionSig` with the claim value. If they do
      not match, the assertion MUST be rejected (the assertion has been
      replayed from a different TDF).

8. **Unbound assertions**: If the assertion has no binding, it MUST be treated
   as informational only. The consuming application MUST NOT use unbound
   assertions for security decisions, access control, or handling instructions
   that affect data confidentiality or integrity.

### 8.2 Verification Pseudocode

```
function verifyAssertion(assertion, aggregateHash, verificationKeys, dek):
    // Step 1: Validate fields
    validateRequiredFields(assertion)

    // Step 2: Check binding
    if assertion.binding is empty:
        return UNBOUND  // informational only

    // Step 3-5: Resolve key
    key = resolveVerificationKey(assertion.id, verificationKeys, dek)

    // Step 6: Verify JWS
    jwt = JWS.verify(assertion.binding.signature, key)
    if jwt is invalid:
        return ERROR("signature verification failed")

    // Step 7a: Extract claims
    claimedHash = jwt.getClaim("assertionHash")
    claimedSig  = jwt.getClaim("assertionSig")

    // Step 7b-c: Verify assertion hash
    computedHash = computeAssertionHash(assertion)
    if computedHash != claimedHash:
        return ERROR("assertion hash mismatch")

    // Step 7d-e: Verify TDF binding
    assertionHashBytes = hexDecode(computedHash)
    expectedSig = base64encode(aggregateHash + assertionHashBytes)
    if expectedSig != claimedSig:
        return ERROR("assertion signature mismatch - cross-TDF replay")

    return VERIFIED
```

### 8.3 Error Handling

Implementations MUST distinguish between the following error conditions:

| Error | Cause | Action |
|:------|:------|:-------|
| Signature verification failed | The JWS signature does not verify with any available key. | Reject the assertion. The signing key may be wrong or the JWS has been tampered with. |
| Assertion hash mismatch | The `assertionHash` claim does not match the recomputed hash. | Reject the assertion. The assertion content has been modified after signing. |
| Assertion signature mismatch | The `assertionSig` claim does not match the expected value. | Reject the assertion. The assertion has likely been replayed from a different TDF. |
| Missing required claims | The `assertionHash` or `assertionSig` claim is absent from the JWT. | Reject the assertion. The JWS payload is malformed. |

When an assertion fails verification, implementations SHOULD include the
assertion `id` in the error message to assist debugging but MUST NOT include
any key material.

---

## 9. PQC Considerations

### 9.1 Recommended Algorithm

`ML-DSA-44` is RECOMMENDED for new deployments concerned with quantum threats
to assertion integrity. ML-DSA-44 provides NIST Level 2 security
(approximately equivalent to 128-bit classical security against quantum
adversaries), which is appropriate for assertions where the primary concern is
signature forgery.

### 9.2 Signature Size Impact

ML-DSA signatures are significantly larger than classical signatures:

| Algorithm | Signature Size | Public Key Size |
|:----------|:---------------|:----------------|
| `HS256` | 32 bytes (HMAC tag) | N/A (symmetric) |
| `RS256` (2048-bit) | 256 bytes | 256 bytes |
| `ES256` | 64 bytes | 33 bytes (compressed) |
| `ES384` | 96 bytes | 49 bytes (compressed) |
| `ML-DSA-44` | 2420 bytes | 1312 bytes |
| `ML-DSA-65` | 3309 bytes | 1952 bytes |

The JWS Compact Serialization base64-encodes the signature, increasing its
on-wire size by approximately 33%. For TDFs with many assertions signed with
ML-DSA, the manifest size increase may be significant. Implementations SHOULD
account for this when designing systems that process large numbers of
assertions.

### 9.3 Migration Guidance

For assertion signatures, the recommended migration path is:

```
Phase 1 (Current)       Phase 2 (PQC)          Phase 3 (PQC-Only)
-----------------       ---------------        ------------------
HS256 / RS256 / ES256   ML-DSA-44 / ML-DSA-65  ML-DSA-44 / ML-DSA-65
                        (alongside classical)   (classical deprecated)
```

During Phase 2, implementations SHOULD support both classical and post-quantum
algorithms for verification. The algorithm used for a specific assertion is
indicated by the JWS `alg` header parameter, so there is no ambiguity during
verification.

### 9.4 HS256 Quantum Resistance

`HS256` (HMAC-SHA256) is not affected by Shor's algorithm and provides 128-bit
post-quantum security (via Grover's bound). For assertions that use HS256 with
the DEK, no migration to post-quantum algorithms is necessary for the assertion
signing itself. However, the DEK's availability depends on the key protection
algorithm, which may be quantum-vulnerable (see BaseTDF-SEC Section 8).

---

## 10. Security Considerations

### 10.1 Unbound Assertions

Assertions without a `binding` field are NOT authenticated. They carry no
cryptographic guarantee of origin or integrity. Implementations:

- MUST NOT use unbound assertions for security decisions.
- MUST NOT use unbound assertions for access control.
- MUST NOT use unbound assertions to determine handling behavior that affects
  data confidentiality or integrity.
- SHOULD treat unbound assertions as untrusted metadata that may have been
  inserted or modified by any party with access to the TDF manifest.

### 10.2 Cross-TDF Replay Prevention

The inclusion of the aggregate integrity hash (from BaseTDF-INT) in the
`assertionSig` claim binds each assertion to a specific TDF instance. Because
the aggregate hash depends on the encrypted payload content, an assertion
signed for one TDF will fail verification when inserted into a different TDF.

This binding is effective because:

- The aggregate hash is derived from the segment hashes of the encrypted
  payload, which are unique to each encryption operation.
- The `assertionSig` combines the aggregate hash with the assertion hash,
  creating a value that is specific to both the assertion content and the TDF
  instance.

### 10.3 Symmetric vs. Asymmetric Binding

| Property | HS256 (Symmetric) | RS256 / ES256 / ML-DSA (Asymmetric) |
|:---------|:-------------------|:-------------------------------------|
| **Authentication** | Yes -- any holder of the DEK can verify. | Yes -- anyone with the public key can verify. |
| **Non-repudiation** | No -- any holder of the DEK can also forge assertions. | Yes -- only the private key holder can sign. |
| **Key management** | Implicit (DEK), no additional key distribution needed. | Requires distribution of public keys or certificates. |
| **Use case** | Self-asserted metadata bound to TDF encryption. | Third-party attestations, regulatory markings, multi-party workflows. |

When non-repudiation is required (e.g., a third party attests to the
classification of the data), asymmetric algorithms (RS256, ES256, ES384,
ML-DSA-44, or ML-DSA-65) MUST be used.

### 10.4 Assertion Ordering

The `assertions` array in the manifest is ordered. Implementations MUST
preserve assertion ordering when reading and re-serializing a TDF. The
assertion hash computation is independent of ordering (each assertion is hashed
individually), but downstream applications MAY assign semantic meaning to
assertion order.

### 10.5 Key Selection Security

When the JWS protected header contains a `jwk` or `x5c` parameter,
implementations MUST exercise caution:

- A `jwk` header provides a candidate public key but does NOT establish trust.
  The verifier MUST validate the key against a trusted key store, certificate
  authority, or pre-configured expectation before accepting the signature.
- An `x5c` header provides a certificate chain. The verifier MUST validate the
  chain against a trusted certificate authority.
- Implementations MUST NOT blindly trust keys embedded in JWS headers without
  external validation.

### 10.6 Assertion Integrity and BaseTDF-SEC

Assertion verification supports the following security invariants from
BaseTDF-SEC:

- **SI-5 (Payload Integrity Verification)**: The `assertionSig` claim
  incorporates the aggregate integrity hash, establishing a dependency between
  assertion validity and payload integrity.
- **SI-6 (Algorithm Validation)**: The JWS `alg` header MUST specify a
  recognized algorithm from BaseTDF-ALG Section 3.4. Unrecognized algorithms
  MUST be rejected.

---

## 11. Normative References

- <a id="rfc7515"></a>**[RFC 7515]** -- Jones, M., Bradley, J., and N.
  Sakimura, "JSON Web Signature (JWS)", RFC 7515, May 2015.
  https://www.rfc-editor.org/rfc/rfc7515

- <a id="rfc7517"></a>**[RFC 7517]** -- Jones, M., "JSON Web Key (JWK)",
  RFC 7517, May 2015.
  https://www.rfc-editor.org/rfc/rfc7517

- <a id="rfc7519"></a>**[RFC 7519]** -- Jones, M., Bradley, J., and N.
  Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
  https://www.rfc-editor.org/rfc/rfc7519

- <a id="rfc8785"></a>**[RFC 8785]** -- Rundgren, A., Jordan, B., and S.
  Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
  https://www.rfc-editor.org/rfc/rfc8785

- <a id="rfc4648"></a>**[RFC 4648]** -- Josefsson, S., "The Base16, Base32,
  and Base64 Data Encodings", RFC 4648, October 2006.
  https://www.rfc-editor.org/rfc/rfc4648

- <a id="fips204"></a>**[NIST FIPS 204]** -- "Module-Lattice-Based Digital
  Signature Standard", Federal Information Processing Standards Publication
  204, August 2024.
  https://csrc.nist.gov/publications/detail/fips/204/final

- <a id="rfc2104"></a>**[RFC 2104]** -- Krawczyk, H., Bellare, M., and R.
  Canetti, "HMAC: Keyed-Hashing for Message Authentication", RFC 2104,
  February 1997.
  https://www.rfc-editor.org/rfc/rfc2104

- <a id="rfc2119"></a>**[BCP 14 / RFC 2119]** -- Bradner, S., "Key words for
  use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
  https://www.rfc-editor.org/rfc/rfc2119

- <a id="rfc8174"></a>**[RFC 8174]** -- Leiba, B., "Ambiguity of Uppercase vs
  Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
  https://www.rfc-editor.org/rfc/rfc8174

- <a id="rfc3339"></a>**[RFC 3339]** -- Klyne, G. and C. Newman, "Date and
  Time on the Internet: Timestamps", RFC 3339, July 2002.
  https://www.rfc-editor.org/rfc/rfc3339

---

[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519
[rfc8785]: https://www.rfc-editor.org/rfc/rfc8785
[rfc4648]: https://www.rfc-editor.org/rfc/rfc4648
[fips204]: https://csrc.nist.gov/publications/detail/fips/204/final
[rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174
[rfc3339]: https://www.rfc-editor.org/rfc/rfc3339
