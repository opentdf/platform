# BaseTDF-SEC: Security Model and Zero Trust Architecture

| | |
|---|---|
| **Document** | BaseTDF-SEC |
| **Title** | Security Model and Zero Trust Architecture |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |

## Table of Contents

1. [Introduction](#1-introduction)
2. [NIST SP 800-207 Zero Trust Alignment](#2-nist-sp-800-207-zero-trust-alignment)
3. [Trust Assumptions and Boundaries](#3-trust-assumptions-and-boundaries)
4. [Threat Model and Attack Analysis](#4-threat-model-and-attack-analysis)
5. [Security Invariants](#5-security-invariants)
6. [Cryptographic Requirements](#6-cryptographic-requirements)
7. [Key Lifecycle](#7-key-lifecycle)
8. [Post-Quantum Cryptography Migration](#8-post-quantum-cryptography-migration)
9. [Normative References](#9-normative-references)

---

## 1. Introduction

### 1.1 Purpose

This document defines the security model for the Trusted Data Format (TDF) as
specified by the BaseTDF suite. It establishes the threat model, trust
assumptions, security invariants, and cryptographic requirements that all other
documents in the suite depend upon.

All normative security requirements in the BaseTDF suite trace back to this
document. Implementers MUST satisfy the security invariants defined herein
(Section 5) to claim conformance with any BaseTDF specification.

### 1.2 Scope

BaseTDF provides **data-centric zero trust security** for data objects that
travel through untrusted channels. The security model addresses:

- Protection of data at rest and in transit, independent of network or storage
  security controls.
- Cryptographic binding of access policy to encrypted content, such that policy
  cannot be separated from or substituted on protected data.
- Authorization decisions enforced at the point of key release, not at the
  point of data access.
- Algorithm agility to support migration from classical to post-quantum
  cryptographic primitives.

The scope explicitly includes data objects that may be copied, forwarded,
stored on untrusted media, or transmitted over untrusted networks. The security
model does NOT depend on the trustworthiness of any storage or transport layer.

### 1.3 Relationship to Other BaseTDF Documents

This document is the **foundation layer** of the BaseTDF specification suite.
All other documents in the suite reference this document for their security
requirements:

- **BaseTDF-ALG** (Algorithm Registry) implements the cryptographic
  requirements defined in Section 6 and the algorithm agility framework
  described in Section 8.
- **BaseTDF-POL** (Policy and ABAC) defines the policy structures whose
  integrity is protected by the security invariants in Section 5.
- **BaseTDF-KAO** (Key Access Object) implements the key protection and policy
  binding mechanisms analyzed in Section 4.
- **BaseTDF-KAS** (Key Access Service Protocol) implements the authorization
  and key release protocol subject to the trust boundaries defined in
  Section 3.
- **BaseTDF-INT** (Integrity Verification) provides the payload integrity
  mechanisms required by SI-5.
- **BaseTDF-ASN** (Assertions) provides verifiable claims subject to the
  cryptographic requirements in Section 6.
- **BaseTDF-CORE** (Container Format) defines the manifest structure that
  carries all security-relevant metadata.

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][RFC2119] [RFC
8174][RFC8174] when, and only when, they appear in ALL CAPITALS, as shown here.

---

## 2. NIST SP 800-207 Zero Trust Alignment

BaseTDF implements a data-centric zero trust architecture aligned with NIST SP
800-207. This section maps BaseTDF components to the NIST reference
architecture and enumerates how BaseTDF satisfies each zero trust tenet.

### 2.1 Component Mapping

| NIST SP 800-207 Component | BaseTDF Equivalent |
|---|---|
| Policy Engine (PE) | KAS authorization logic: attribute evaluation combined with the trust algorithm (see BaseTDF-KAS Section 4) |
| Policy Administrator (PA) | KAS key release via the rewrap endpoint; issues rewrapped key material only after successful policy evaluation |
| Policy Enforcement Point (PEP) | Client SDK: performs encrypt and decrypt operations, enforces local integrity checks |
| Trust Algorithm | ABAC evaluation: attribute rules, entity entitlements, dissemination list checks, and obligation resolution |
| Subject Identity | Authenticated entity, identified by a DPoP-bound access token (see [RFC 9449][RFC9449]) |
| Resource | The TDF-protected data object (manifest, encrypted payload, and associated metadata) |
| Resource Requirements | The policy object embedded in the TDF: `dataAttributes` and `dissem` list (see BaseTDF-POL Section 3) |
| Session Credentials | Rewrapped key share, scoped to a single rewrap session and bound to the client's ephemeral public key |
| CDM / Posture Assessment | Entity attribute entitlements, externally provisioned by the identity provider and attribute authority |
| Control Plane | KAS protocol: key management, policy evaluation, and audit (see BaseTDF-KAS) |
| Data Plane | Encrypted TDF payload: traverses untrusted channels without requiring control plane availability |

### 2.2 Zero Trust Tenets

The following enumerates the seven zero trust tenets from NIST SP 800-207
Section 2.1 and describes how BaseTDF satisfies each.

#### Tenet 1: All data sources and computing services are considered resources

Every TDF-protected data object is a self-contained resource. The TDF manifest
carries its own policy, key access information, integrity metadata, and
assertions. No external resource catalog is required to identify or locate the
resource; the TDF itself is the authoritative record of what it protects and
under what conditions access is granted.

#### Tenet 2: All communication is secured regardless of network location

BaseTDF separates data-plane security from transport-layer security. The
encrypted payload is protected by authenticated encryption (AES-256-GCM; see
Section 6) independent of any network controls. Key shares are protected by
asymmetric encryption to the KAS public key. The rewrap protocol operates over
TLS-protected channels, and the rewrapped key material is re-encrypted to the
client's ephemeral public key, providing end-to-end protection of key material
even if TLS is terminated at an intermediary.

#### Tenet 3: Access to individual enterprise resources is granted on a per-session basis

Each rewrap request is independently authorized. The KAS evaluates the entity's
current entitlements against the TDF's policy at the time of each rewrap
request. There is no session token or cached authorization that permits
subsequent access without re-evaluation. The rewrapped key share is bound to
the client's ephemeral public key and MUST NOT be reusable across sessions.

#### Tenet 4: Access to resources is determined by dynamic policy

Policy evaluation occurs at rewrap time, not at creation time. When an entity
requests access to a TDF, the KAS evaluates the policy embedded in the TDF
against the entity's **current** attribute entitlements as reported by the
authorization service. Changes to entity entitlements, attribute definitions, or
policy rules take effect on the next rewrap request without requiring
re-encryption of the TDF.

#### Tenet 5: The enterprise monitors and measures the integrity and security posture of all owned and associated assets

The KAS MUST log every rewrap attempt (see SI-8). These audit records include
the entity identity, policy UUID, algorithm, KAS key identifier, and the
permit/deny result. These records provide the observability surface required for
security monitoring, anomaly detection, and compliance reporting.

#### Tenet 6: All resource authentication and authorization are dynamic and strictly enforced before access is allowed

Entity authentication uses DPoP-bound access tokens ([RFC 9449][RFC9449]),
which provide proof-of-possession binding between the access token and the
client's cryptographic key. The KAS verifies the DPoP proof, validates the
access token, evaluates the policy, and only then releases the rewrapped key
material. The Signed Request Token (SRT) further binds the rewrap request
payload to the DPoP key, preventing token replay and request substitution.

#### Tenet 7: The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture

Rewrap audit events (SI-8) provide structured data suitable for ingestion into
SIEM and analytics platforms. Each event captures the entity, the policy, the
access decision, the algorithm used, and the KAS key involved. Aggregation of
these events enables detection of anomalous access patterns, policy
misconfiguration, and credential compromise.

---

## 3. Trust Assumptions and Boundaries

### 3.1 Trusted Components

The following components are assumed to operate in a trusted environment with
adequate physical, logical, and operational security controls.

#### 3.1.1 Key Access Service (KAS)

The KAS is the root of trust for key release. It holds or has delegated access
to the private keys corresponding to the KAS public keys used to wrap DEK
shares. The KAS:

- Operates in a trusted execution environment with access controls on its
  private key material.
- Is trusted to correctly evaluate policy and enforce authorization decisions.
- Is trusted to correctly perform cryptographic operations (unwrap, rewrap,
  HMAC verification).
- Is trusted to produce accurate and complete audit logs.

Compromise of the KAS private key material allows an attacker to decrypt any
TDF whose KAO references that key. Implementations SHOULD use hardware
security modules (HSMs) or equivalent key protection mechanisms for KAS private
keys.

#### 3.1.2 Authorization Service

The authorization service (policy decision point) is trusted to:

- Correctly resolve entity attribute entitlements from the identity provider.
- Correctly evaluate attribute-based access control rules.
- Return accurate permit/deny decisions to the KAS.

The authorization service operates within the same trust boundary as the KAS
and communicates with it over authenticated, integrity-protected channels.

#### 3.1.3 Identity Provider

The identity provider is trusted to:

- Correctly authenticate entities.
- Issue access tokens that accurately represent entity identity and, where
  applicable, bind to DPoP keys.
- Maintain the confidentiality of signing keys used for token issuance.

### 3.2 Partially Trusted Components

#### 3.2.1 Client SDK

The client SDK is trusted to:

- Correctly implement encryption and integrity operations during TDF creation.
- Correctly implement decryption, integrity verification, and policy binding
  validation during TDF consumption.
- Enforce local security controls (e.g., discarding decrypted data on
  integrity failure per SI-5).

The client SDK is NOT trusted to:

- Hold decrypted key material beyond the duration of a single operation. Key
  material MUST be securely erased after use (SI-7).
- Cache or persist authorization decisions. Each access MUST result in a new
  rewrap request.
- Make access control decisions independently of the KAS.

### 3.3 Untrusted Components

The following components are considered untrusted. The security model provides
confidentiality and integrity guarantees even when these components are fully
compromised.

#### 3.3.1 Storage

TDF objects MAY be stored on any medium, including public cloud storage,
removable media, email systems, or shared file systems. The storage layer is
not trusted for confidentiality or integrity. The authenticated encryption of
the payload and the cryptographic binding of the policy provide these
guarantees independent of storage.

#### 3.3.2 Network

TDF objects MAY traverse any network, including the public internet, without
loss of confidentiality or integrity. While TLS SHOULD be used for rewrap
protocol communications, the security model does not depend solely on transport
encryption: key material in transit during rewrap is protected by asymmetric
encryption to the client's public key.

#### 3.3.3 Intermediaries

Any entity that handles, forwards, caches, or indexes TDF objects (e.g., email
gateways, CDN nodes, search indexers) is untrusted. These intermediaries can
observe the encrypted payload and the cleartext manifest metadata, but cannot
access the plaintext content or modify the payload without detection.

### 3.4 Trust Boundaries

```
                    TRUSTED BOUNDARY
   ┌─────────────────────────────────────────────┐
   │                                             │
   │  ┌──────────┐    ┌────────────────────┐     │
   │  │   KAS    │◄──►│ Authorization Svc  │     │
   │  │          │    │ (Policy Decision)  │     │
   │  └────▲─────┘    └────────────────────┘     │
   │       │                                     │
   └───────┼─────────────────────────────────────┘
           │ Boundary B1: rewrap protocol (TLS + DPoP)
           │
   ┌───────┼─────────────────────────────────────┐
   │       │         PARTIALLY TRUSTED            │
   │  ┌────▼─────┐                               │
   │  │  Client  │                               │
   │  │  SDK     │                               │
   │  └────┬─────┘                               │
   └───────┼─────────────────────────────────────┘
           │ Boundary B2: data plane (no trust required)
           │
   ┌───────┼─────────────────────────────────────┐
   │       ▼              UNTRUSTED              │
   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
   │  │ Storage  │  │ Network  │  │ Intermed. │  │
   │  └──────────┘  └──────────┘  └──────────┘  │
   └─────────────────────────────────────────────┘
```

**Boundary B1** (Client to KAS): This is the critical trust boundary. The
rewrap protocol crosses this boundary. Communications MUST be protected by TLS.
Entity authentication MUST use DPoP-bound access tokens for production
deployments (SI-4). The SRT binds the request payload to the authenticated
entity.

**Boundary B2** (Client to Untrusted): TDF objects cross this boundary. No
trust is required. The encrypted payload and cryptographic policy binding
provide the necessary security guarantees.

---

## 4. Threat Model and Attack Analysis

### 4.1 Adversary Model

The adversary is assumed to have the following capabilities:

- Full read access to all TDF objects (encrypted payload, manifest, metadata).
- Full control of the network between the client and any service (active
  man-in-the-middle), subject to TLS protections.
- Ability to create, modify, and replay TDF objects and rewrap requests.
- Access to their own valid credentials and entitlements for the KAS.
- Computational resources bounded by classical (and, for Section 8,
  quantum) computing limits.

The adversary does NOT have:

- Access to the KAS private key material.
- Access to another entity's valid credentials or private keys.
- The ability to compromise the authorization service's decision logic.

### 4.2 Attacks That Are Mitigated

| Attack | Description | Why It Fails |
|---|---|---|
| **Policy tampering** | Attacker modifies the base64-encoded policy object in the manifest to alter access rules. | The policy binding (HMAC of the policy computed with the DEK share as key) detects any modification. KAS verifies the binding before key release (SI-1). The attacker cannot recompute the HMAC without the DEK share, which is encrypted to the KAS public key. |
| **KAO substitution** | Attacker replaces a KAO with one they created, wrapping a known key to a KAS they control or to the legitimate KAS. | If the attacker wraps to their own KAS, the legitimate KAS will not have the corresponding private key and cannot unwrap. If the attacker wraps to the legitimate KAS, the DEK share they chose will not reconstruct the correct DEK (the other splits remain unknown), and the policy binding will not match the original policy unless the attacker also controls all other splits. |
| **Split manipulation** | Attacker attempts to recover the DEK by manipulating or observing individual key splits. | XOR-based key splitting is information-theoretically secure: any individual split is uniformly random and independent of the DEK. An attacker must obtain all splits to reconstruct the DEK. Each split is independently encrypted to a different KAS key. |
| **Cross-TDF replay** | Attacker copies a KAO from one TDF and inserts it into another TDF's manifest to gain unauthorized access. | Each KAO contains a policy binding that is an HMAC computed over the specific policy of the TDF it belongs to, keyed by the DEK share. Since different TDFs have different policies and different DEK shares, the binding will not verify against the target TDF's policy. |
| **Policy binding forgery** | Attacker attempts to forge a valid policy binding for a modified policy without knowing the DEK share. | The DEK share is protected by IND-CCA2 asymmetric encryption (RSA-OAEP or ECIES). Without the KAS private key, the attacker cannot recover the DEK share and therefore cannot compute a valid HMAC for any policy. |
| **Algorithm downgrade** | Attacker modifies algorithm identifiers in the manifest to force use of weaker algorithms. | Algorithm fields are validated by the KAS against the algorithm registry (see BaseTDF-ALG). KAS MUST reject KAOs with unrecognized algorithm identifiers (SI-6). For implicit key types (e.g., `wrapped` implies RSA, `ec-wrapped` implies ECDH), the algorithm is determined by the key type and cannot be overridden by manifest fields. |
| **Rewrap request replay** | Attacker captures a valid rewrap request and replays it to obtain the rewrapped key. | The SRT contains temporal claims (`iat`, `exp`) and is signed with the DPoP key. The KAS validates these claims with a bounded acceptable skew. Replayed requests will fail temporal validation. The rewrapped key is encrypted to the client's ephemeral public key from the original request; even if replay succeeds, the attacker cannot decrypt the response without the corresponding private key. |
| **Payload modification** | Attacker modifies the encrypted payload (ciphertext, segment data). | AES-GCM authenticated encryption detects any modification of ciphertext or associated data. Segment hashes and the root signature provide additional integrity verification (SI-5). Clients MUST verify integrity before returning decrypted data. |

### 4.3 Attacks with Residual Risk

| Attack | Risk Level | Description | Mitigation |
|---|---|---|---|
| **MITM without DPoP** | MEDIUM | If DPoP is not enforced, an attacker who compromises a bearer access token can perform rewrap requests on behalf of the token holder. The attacker obtains the rewrapped key encrypted to their chosen public key. | DPoP MUST be required for production deployments (SI-4). Without DPoP, access tokens are bearer tokens and susceptible to theft via token exfiltration, log leakage, or TLS interception. |
| **Chosen-policy oracle** | LOW | An attacker with valid credentials creates TDFs with crafted policies and observes whether rewrap succeeds or fails, potentially mapping the attribute entitlements of other entities if the KAS returns distinguishable error responses for policy evaluation failures versus other failures. | KAS SHOULD return uniform error responses for all access denial reasons. Specifically, policy evaluation failures, dissemination check failures, and attribute resolution failures SHOULD produce identical error codes and messages to the client. The KAS MAY log detailed failure reasons internally for audit purposes. |
| **Encrypted metadata processing** | LOW | The `encryptedMetadata` field in a KAO is encrypted with the DEK share. If a KAS implementation decrypts and processes this metadata before verifying the policy binding, a crafted TDF could exploit parsing vulnerabilities in the metadata processor. | `encryptedMetadata` MUST NOT be decrypted or processed until after successful policy binding verification (SI-1) and authorization (SI-2). Implementations SHOULD treat decrypted metadata as untrusted input subject to validation. |
| **Timing side channels** | LOW | Timing differences in HMAC comparison or cryptographic operations could leak information about key material or policy binding values. | Policy binding verification MUST use constant-time comparison (SI-1). Implementations SHOULD use constant-time cryptographic primitives throughout the rewrap path. |
| **Entity attribute enumeration** | LOW | An attacker with valid credentials systematically probes the KAS with TDFs containing different attribute combinations to map which attributes they hold. | KAS SHOULD implement rate limiting on rewrap requests per entity (see Section 4.4). Rewrap audit logs (SI-8) enable detection of enumeration patterns. |

### 4.4 Identified Implementation Gaps

The following gaps represent areas where the specification requires behavior
that implementations MUST or SHOULD address but where current practice may be
inconsistent.

| Gap | Severity | Specification Treatment |
|---|---|---|
| **Dissemination list not enforced** | CRITICAL | When the policy body contains a non-empty `dissem` list, the KAS MUST verify that the authenticated entity's identity appears in the dissemination list before releasing any key material (SI-3). Implementations that skip this check are non-conformant. See BaseTDF-POL Section 4. |
| **`policyBinding.alg` not validated** | MEDIUM | When the policy binding is expressed as an object with `alg` and `hash` fields, the KAS MUST validate the `alg` field against the set of supported binding algorithms (currently: `HS256` for HMAC-SHA256). The KAS MUST reject KAOs whose `policyBinding.alg` specifies an unrecognized or unsupported algorithm (SI-6). When the policy binding is a bare string (legacy format), the binding algorithm MUST default to `HS256`. |
| **No rate limiting on rewrap** | LOW | Implementations SHOULD enforce rate limits on rewrap requests per authenticated entity to mitigate credential abuse and attribute enumeration attacks. The specific rate limits are deployment-dependent and outside the scope of this specification. |
| **All splits assigned to the same KAS** | LOW | When all KAOs in a split key configuration reference the same KAS URL, the security benefit of key splitting is reduced to a single point of compromise. Implementations SHOULD warn when creating TDFs where all splits are assigned to a single KAS. This does not affect correctness but reduces the defense-in-depth benefit of the split key architecture. |
| **Legacy KAOs without `kid` field** | MEDIUM | KAOs that omit the `kid` (key identifier) field force the KAS to attempt decryption with multiple legacy keys, increasing computational cost and potential for oracle attacks. New TDF implementations MUST include a `kid` field in all KAOs. KAS implementations MUST support `kid`-less KAOs for backward compatibility but SHOULD log a warning. |

---

## 5. Security Invariants

The following security invariants are normative requirements. Other documents
in the BaseTDF suite reference these invariants by their identifiers (SI-1
through SI-8). An implementation MUST satisfy all security invariants to claim
conformance with this specification.

### SI-1: Policy Binding Integrity

**KAS MUST verify that the policy binding matches the policy before any key
release.**

Specifically:

1. The KAS MUST compute HMAC-SHA256 over the base64-encoded policy body using
   the unwrapped DEK share as the HMAC key.
2. The KAS MUST compare the computed HMAC with the `policyBinding.hash` value
   from the KAO.
3. The comparison MUST use a constant-time algorithm (e.g., `hmac.Equal` in Go,
   `crypto.timingSafeEqual` in Node.js) to prevent timing side-channel attacks.
4. If the comparison fails, the KAS MUST reject the KAO and MUST NOT return
   any key material derived from the corresponding DEK share.
5. The KAS MUST NOT decrypt or process `encryptedMetadata` before successful
   policy binding verification.

### SI-2: Authorization Before Key Release

**KAS MUST evaluate the policy against the entity's current entitlements
BEFORE returning any rewrapped key material.**

Specifically:

1. The KAS MUST extract the data attributes from the TDF's policy object.
2. The KAS MUST submit the data attributes and the entity's token to the
   authorization service for evaluation.
3. The KAS MUST receive an explicit permit decision before proceeding with
   key rewrap.
4. If the authorization service returns a deny decision or is unavailable,
   the KAS MUST NOT return any key material.
5. Authorization evaluation MUST occur for every rewrap request. Caching of
   authorization decisions across requests is NOT RECOMMENDED, as it defeats
   the dynamic policy evaluation principle (Section 2.2, Tenet 4).

### SI-3: Dissemination Enforcement

**When the policy body contains a non-empty `dissem` list, the KAS MUST verify
that the authenticated entity is in the dissemination list.**

Specifically:

1. The KAS MUST extract the `dissem` array from the policy body.
2. If the `dissem` array is non-empty, the KAS MUST verify that the
   authenticated entity's identity (as determined from the access token's
   `sub` claim or equivalent) matches at least one entry in the `dissem` list.
3. The matching algorithm SHOULD be case-insensitive for email-format
   identifiers.
4. If the entity is not in the dissemination list, the KAS MUST deny the
   rewrap request and MUST NOT return any key material.
5. Dissemination checks are in addition to, not a replacement for, attribute-
   based access control evaluation (SI-2).

### SI-4: DPoP Binding

**For production deployments, rewrap requests MUST include DPoP proof binding
the client's public key to the access token.**

Specifically:

1. The client MUST include a DPoP proof as defined in [RFC 9449][RFC9449] with
   the rewrap request.
2. The KAS MUST verify that the DPoP proof is bound to the access token
   presented with the request.
3. The KAS MUST verify the DPoP proof signature using the public key embedded
   in the DPoP proof header.
4. The Signed Request Token (SRT) MUST be signed with the same key as the DPoP
   proof, establishing a binding chain: DPoP key -> access token -> SRT ->
   rewrap request body.
5. Deployments that do not enforce DPoP MUST document this as a known
   deviation from the security model and MUST implement compensating controls
   (e.g., short-lived tokens, network-level access controls).

### SI-5: Payload Integrity Verification

**Clients MUST verify segment hashes and the root signature after decryption.
Integrity failure MUST abort processing and discard all decrypted data.**

Specifically:

1. After decrypting each segment, the client MUST compute the segment hash
   using the algorithm specified in `integrityInformation.segmentHashAlg`.
2. The client MUST compare the computed hash with the expected hash from the
   `segments` array in the manifest.
3. After all segments are verified, the client MUST verify the root signature
   in `integrityInformation.rootSignature` using the algorithm specified in
   `rootSignature.alg`.
4. If any segment hash or the root signature fails verification, the client
   MUST immediately abort decryption and MUST securely discard all decrypted
   plaintext data already produced.
5. The client MUST NOT return partial plaintext to the application when
   integrity verification fails, even for streaming use cases.
6. See BaseTDF-INT for the detailed integrity verification procedure.

### SI-6: Algorithm Validation

**KAS MUST reject KAOs with unrecognized `alg` or `policyBinding.alg` values.**

Specifically:

1. The KAS MUST maintain a set of supported algorithms consistent with the
   BaseTDF-ALG registry.
2. When processing a KAO, the KAS MUST validate that the key type (`type`
   field: `wrapped`, `ec-wrapped`) is recognized and supported.
3. When the `policyBinding` is an object, the KAS MUST validate that the
   `alg` field is a recognized policy binding algorithm.
4. The KAS MUST reject the KAO and return an error if any algorithm field
   contains an unrecognized value.
5. The KAS MUST NOT fall back to a default algorithm when an explicitly
   specified algorithm is unrecognized.

### SI-7: Key Material Hygiene

**Plaintext DEK shares MUST be securely erased from memory after use, on both
the client and KAS side.**

Specifically:

1. After the KAS has verified the policy binding and re-encrypted the DEK
   share to the client's public key, the plaintext DEK share MUST be erased
   from KAS memory.
2. After the client has reconstructed the DEK from its shares and decrypted
   the payload, the DEK and all individual shares MUST be erased from client
   memory.
3. Secure erasure MUST overwrite the memory occupied by key material with
   zeros or random data before deallocation.
4. Implementations SHOULD use language-specific secure erasure facilities
   (e.g., `crypto/subtle.XORBytes` with zeroing in Go, `SecureZeroMemory` on
   Windows, `explicit_bzero` on POSIX systems) to prevent compiler
   optimizations from eliding the erasure.
5. Key material MUST NOT be written to persistent storage in plaintext, logged,
   or included in error messages.

### SI-8: Audit Logging

**KAS MUST log every rewrap attempt with sufficient detail for security
monitoring and forensic analysis.**

Each audit record MUST include at minimum:

1. **Entity identity**: The `sub` claim from the authenticated access token,
   and the client identifier where available.
2. **Policy UUID**: The unique identifier of the policy being evaluated.
3. **Algorithm**: The key access algorithm (e.g., `rsa:2048`, `ec:secp256r1`).
4. **KAS key identifier**: The `kid` of the KAS key used for unwrapping (or
   an indication that legacy key lookup was used).
5. **Policy binding**: The `policyBinding.hash` value from the KAO.
6. **Access decision**: `permit` or `deny`.
7. **Timestamp**: The time of the rewrap attempt in [RFC 3339][RFC3339] format.
8. **Request context**: The requesting client's IP address and user agent,
   where available.

Audit records for denied requests MUST NOT include any key material. Audit
records for permitted requests MUST NOT include the plaintext DEK share or the
rewrapped key.

Audit records SHOULD be emitted as structured data (e.g., JSON) suitable for
ingestion by SIEM platforms.

---

## 6. Cryptographic Requirements

### 6.1 Symmetric Encryption

The payload MUST be encrypted using an AEAD (Authenticated Encryption with
Associated Data) algorithm.

| Algorithm | Key Size | Status | Reference |
|---|---|---|---|
| AES-256-GCM | 256 bits | REQUIRED | [NIST SP 800-38D][SP800-38D] |
| AES-128-GCM | 128 bits | NOT RECOMMENDED | [NIST SP 800-38D][SP800-38D] |

Implementations MUST support AES-256-GCM. AES-128-GCM MAY be supported for
backward compatibility but MUST NOT be used for new TDF creation.

See BaseTDF-ALG Section 3 for the complete algorithm registry.

### 6.2 Asymmetric Key Encapsulation

DEK shares are encapsulated (wrapped) using the KAS public key. The following
algorithms are defined:

| Algorithm | Minimum Key Size | Status | Reference |
|---|---|---|---|
| RSA-OAEP (SHA-1 MGF) | 2048 bits | REQUIRED (legacy) | [RFC 8017][RFC8017] |
| RSA-OAEP (SHA-256 MGF) | 4096 bits | RECOMMENDED | [RFC 8017][RFC8017] |
| ECDH + HKDF-SHA256 + AES-256-GCM | P-256 / P-384 / P-521 | RECOMMENDED | [NIST SP 800-56A][SP800-56A] |

- RSA key sizes below 2048 bits MUST NOT be used.
- RSA-2048 MUST be supported for backward compatibility with existing TDFs.
- RSA-4096 is RECOMMENDED for new deployments.
- ECDH with NIST P-256 or stronger curves is RECOMMENDED for new TDF creation.
- See BaseTDF-ALG Section 4 for algorithm identifiers and detailed parameters.

### 6.3 Policy Binding

| Algorithm | Identifier | Status |
|---|---|---|
| HMAC-SHA256 | `HS256` | REQUIRED |

The policy binding MUST be computed as:

```
HMAC-SHA256(key=DEK_share, message=base64encode(policy))
```

The result is hex-encoded and then base64-encoded for storage in the
`policyBinding.hash` field. See BaseTDF-KAO Section 5 for the detailed
procedure.

### 6.4 Integrity

| Purpose | Algorithm | Status |
|---|---|---|
| Segment hashing | GMAC (from AES-GCM) or HMAC-SHA256 | REQUIRED |
| Root signature | HMAC-SHA256 | REQUIRED |

See BaseTDF-INT for the detailed integrity verification scheme.

### 6.5 Random Number Generation

All key generation and nonce/IV generation MUST use a cryptographically secure
pseudorandom number generator (CSPRNG) seeded from an operating system entropy
source.

Specifically:

- Go implementations MUST use `crypto/rand`.
- JavaScript implementations MUST use `crypto.getRandomValues()` or the Node.js
  `crypto.randomBytes()` API.
- Implementations MUST NOT use non-cryptographic PRNGs (e.g., `math/rand` in
  Go, `Math.random()` in JavaScript) for any security-relevant purpose.

### 6.6 IV/Nonce Uniqueness

For AES-GCM:

- The IV/nonce MUST be 96 bits (12 bytes).
- The IV/nonce MUST be unique for every encryption operation under the same
  key.
- For segmented encryption, each segment MUST use a distinct IV/nonce. The
  segment counter approach (base IV + segment index) is RECOMMENDED to
  guarantee uniqueness without additional random generation.
- Nonce reuse under the same key catastrophically compromises both
  confidentiality and integrity. Implementations MUST ensure uniqueness
  through deterministic construction or verified-random generation.

### 6.7 Minimum Key Sizes

| Key Type | Minimum | Recommended | Maximum |
|---|---|---|---|
| AES (payload encryption) | 256 bits | 256 bits | 256 bits |
| RSA (key encapsulation) | 2048 bits | 4096 bits | -- |
| EC (key encapsulation) | P-256 (256 bits) | P-384 (384 bits) | P-521 (521 bits) |
| HMAC (policy binding) | 256 bits (from DEK share) | 256 bits | -- |

---

## 7. Key Lifecycle

This section defines the lifecycle stages for cryptographic key material in the
BaseTDF system.

### 7.1 Generation

**DEK (Data Encryption Key)**:

- The DEK MUST be generated using a CSPRNG (Section 6.5).
- The DEK MUST be at least 256 bits for AES-256-GCM.
- The DEK MUST have full entropy (i.e., generated uniformly at random, not
  derived from low-entropy sources such as passwords).

**DEK Shares**:

- When key splitting is used (see BaseTDF-KAO Section 3), the DEK MUST be
  split into N shares using XOR-based splitting.
- Each share MUST be the same size as the DEK.
- All shares except the last MUST be generated independently using a CSPRNG.
  The last share is computed as the XOR of the DEK and all preceding shares.

**KAS Key Pairs**:

- KAS asymmetric key pairs MUST be generated using a CSPRNG with key sizes
  meeting the minimums in Section 6.7.
- Key generation SHOULD occur within an HSM or equivalent trusted key
  management system.

### 7.2 Wrapping

- Each DEK share MUST be wrapped (encrypted) to the public key of the KAS
  identified in the KAO's `url` field.
- The wrapping algorithm is determined by the KAO `type` field: `wrapped` for
  RSA-OAEP, `ec-wrapped` for ECDH-based key encapsulation.
- The wrapped key MUST be stored in the KAO's `wrappedKey` field.
- The wrapping operation MUST use the algorithm parameters specified in
  BaseTDF-ALG for the indicated key type.
- A policy binding MUST be computed and stored alongside the wrapped key, as
  specified in BaseTDF-KAO Section 5.

### 7.3 Storage

- Wrapped DEK shares are stored within the TDF manifest as part of the KAO.
  They are encrypted and MAY be stored on untrusted media.
- Plaintext DEK material (the DEK itself and unwrapped shares) MUST NOT be
  persisted to any storage medium.
- KAS private keys MUST be stored encrypted at rest when not in active use.
  HSM-based storage is RECOMMENDED.

### 7.4 Rewrap

- During a rewrap operation, the KAS unwraps the DEK share using its private
  key, then re-encrypts (rewraps) the share to the client's ephemeral public
  key.
- The rewrap operation MUST follow the procedure specified in BaseTDF-KAS.
- The rewrapped key is scoped to the single rewrap session: it is encrypted
  to the client's ephemeral public key provided in the rewrap request.
- The KAS MUST NOT return the plaintext DEK share; it MUST only return the
  re-encrypted form.

### 7.5 Destruction

- After the KAS completes the rewrap operation, the plaintext DEK share MUST
  be securely erased from KAS memory (SI-7).
- After the client reconstructs the DEK and completes decryption, the DEK and
  all shares MUST be securely erased from client memory (SI-7).
- When KAS key pairs are rotated or decommissioned, the private key material
  MUST be securely destroyed after a transition period during which existing
  TDFs are either re-encrypted to the new key or archived.
- Key destruction MUST follow the same secure erasure requirements as SI-7.

---

## 8. Post-Quantum Cryptography Migration

### 8.1 Harvest-Now-Decrypt-Later (HNDL) Threat

Adversaries with access to TDF objects today may store the encrypted data and
the accompanying manifest (including wrapped DEK shares) with the intent of
decrypting them once a cryptographically relevant quantum computer (CRQC)
becomes available. This "harvest-now-decrypt-later" (HNDL) threat applies to
any TDF whose confidentiality requirements extend beyond the expected timeline
for CRQC development.

Organizations SHOULD assess their data's confidentiality lifetime against
current CRQC timelines. Data with confidentiality requirements exceeding 10
years SHOULD be protected with post-quantum or hybrid algorithms.

### 8.2 Quantum-Vulnerable Components

The following BaseTDF components rely on classical asymmetric cryptography that
is vulnerable to quantum attacks:

| Component | Classical Algorithm | Quantum Vulnerability |
|---|---|---|
| DEK share wrapping (RSA) | RSA-OAEP | Shor's algorithm breaks RSA |
| DEK share wrapping (EC) | ECDH + HKDF | Shor's algorithm breaks ECDH |
| DPoP proof signatures | RS256, ES256 | Shor's algorithm breaks RSA/ECDSA |
| Assertion signatures (JWS) | RS256, ES256 | Shor's algorithm breaks RSA/ECDSA |

The following components are NOT vulnerable to quantum attacks at their
specified security levels:

| Component | Algorithm | Quantum Security |
|---|---|---|
| Payload encryption | AES-256-GCM | Grover's algorithm reduces to 128-bit (sufficient) |
| Policy binding | HMAC-SHA256 | Quantum-resistant |
| Segment hashing | HMAC-SHA256 / GMAC | Quantum-resistant |

### 8.3 Hybrid Transition Strategy

To mitigate the HNDL threat while maintaining interoperability with existing
systems, BaseTDF adopts a **hybrid transition strategy** that combines
classical and post-quantum algorithms.

In a hybrid KAO, the `wrappedKey` field contains the output of a combined key
encapsulation mechanism where both a classical and a post-quantum KEM
contribute to the shared secret. The security of the combined scheme is at
least as strong as the stronger of the two constituent algorithms: if either
the classical or the post-quantum algorithm remains unbroken, the DEK share
remains protected.

The specific hybrid algorithm constructions are defined in BaseTDF-ALG
Section 6. This document defines the security properties they MUST satisfy:

1. **Hybrid binding**: The combined shared secret MUST be derived from both
   the classical and post-quantum key agreement outputs using a KDF (e.g.,
   HKDF-SHA256), such that an attacker must break BOTH algorithms to recover
   the shared secret.
2. **Independent keys**: The classical and post-quantum key pairs MUST be
   generated independently.
3. **Combined ciphertext**: The KAO MUST carry sufficient information for the
   KAS to perform both the classical and post-quantum decapsulation.

### 8.4 Algorithm Agility

The BaseTDF-ALG registry provides the algorithm agility framework. New
algorithms (including post-quantum algorithms) can be added to the registry
without modifying the core TDF structure. The `type` field of the KAO and the
`alg` fields throughout the manifest serve as extension points for new
algorithms.

Implementations MUST be prepared to encounter KAOs with algorithm identifiers
they do not recognize. Unrecognized algorithms MUST be rejected (SI-6), not
silently ignored or downgraded.

### 8.5 Recommended Migration Path

The recommended migration path for key encapsulation algorithms is:

```
Phase 1 (Current)          Phase 2 (Hybrid)              Phase 3 (Post-Quantum)
─────────────────          ────────────────               ──────────────────────
ECDH + HKDF (P-256+)  →   X-ECDH-ML-KEM-768         →   ML-KEM-768
RSA-OAEP (2048+)       →   (classical + PQC combined) →   (pure PQC)
```

**Phase 1** (current): Classical algorithms as specified in Section 6.2.
Suitable for data with confidentiality requirements under 10 years or where
PQC support is not yet available.

**Phase 2** (hybrid): Combined classical and post-quantum algorithms as
defined in BaseTDF-ALG Section 6. The hybrid identifier `X-ECDH-ML-KEM-768`
denotes ECDH (P-256 or P-384) combined with ML-KEM-768. This phase provides
quantum resistance while maintaining a classical security floor. This is the
RECOMMENDED configuration for new deployments concerned with HNDL threats.

**Phase 3** (post-quantum): Pure post-quantum algorithms (e.g., ML-KEM-768,
ML-KEM-1024) once classical algorithm support is no longer required for
interoperability. The timeline for this phase depends on ecosystem readiness
and the deprecation schedule for classical algorithms.

### 8.6 Signature Migration

For assertion signatures and DPoP proofs, the migration path is:

```
Phase 1 (Current)    Phase 2 (Hybrid)           Phase 3 (Post-Quantum)
────────────────     ────────────────           ──────────────────────
ES256 / RS256    →   Composite signatures   →   ML-DSA-65 / ML-DSA-87
```

ML-DSA (FIPS 204) is the RECOMMENDED post-quantum signature algorithm for
BaseTDF. The specific composite signature construction and algorithm
identifiers are defined in BaseTDF-ALG Section 7.

### 8.7 Timeline Considerations

This specification does not mandate specific migration deadlines. The
following NIST publications inform timeline planning:

- **FIPS 203** (ML-KEM): Finalized August 2024. Implementations MAY begin
  adoption.
- **FIPS 204** (ML-DSA): Finalized August 2024. Implementations MAY begin
  adoption.
- **NIST deprecation timeline**: NIST has indicated intent to deprecate
  112-bit classical security (RSA-2048, P-256) by 2030 and disallow by 2035.

Organizations SHOULD develop PQC migration plans that align with their data
retention and confidentiality requirements.

---

## 9. Normative References

| Reference | Title |
|---|---|
| [NIST SP 800-207][SP800-207] | Zero Trust Architecture |
| [NIST SP 800-38D][SP800-38D] | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC |
| [NIST SP 800-56A][SP800-56A] | Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography |
| [NIST FIPS 203][FIPS203] | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) |
| [NIST FIPS 204][FIPS204] | Module-Lattice-Based Digital Signature Standard (ML-DSA) |
| [RFC 2119][RFC2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 8174][RFC8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |
| [RFC 8017][RFC8017] | PKCS #1: RSA Cryptography Specifications Version 2.2 |
| [RFC 9449][RFC9449] | OAuth 2.0 Demonstrating Proof of Possession (DPoP) |
| [RFC 3339][RFC3339] | Date and Time on the Internet: Timestamps |

[SP800-207]: https://doi.org/10.6028/NIST.SP.800-207
[SP800-38D]: https://doi.org/10.6028/NIST.SP.800-38D
[SP800-56A]: https://doi.org/10.6028/NIST.SP.800-56Ar3
[FIPS203]: https://doi.org/10.6028/NIST.FIPS.203
[FIPS204]: https://doi.org/10.6028/NIST.FIPS.204
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC8017]: https://www.rfc-editor.org/rfc/rfc8017
[RFC9449]: https://www.rfc-editor.org/rfc/rfc9449
[RFC3339]: https://www.rfc-editor.org/rfc/rfc3339
