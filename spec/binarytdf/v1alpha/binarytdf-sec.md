# BinaryTDF-SEC: Security Considerations

| | |
|---|---|
| Document | BinaryTDF-SEC |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-CORE |
| Referenced by | All BinaryTDF components |

## 1. Parser limits

Every parser MUST enforce limits before allocation, hashing, or authority contact. The
following are frame version 2 baselines; profiles MAY set lower limits.

| Input | Required handling |
|---|---|
| Frame section length | Check overflow and remaining bytes before conversion or allocation; enforce a finite maximum |
| Ciphertext | Streaming is permitted; never allocate directly from the untrusted `uint64` length |
| CBOR nesting | Reject depth greater than 32 |
| CBOR array | Reject more than 4096 elements |
| CBOR map | Reject more than 4096 pairs |

## 2. Cryptographic boundaries

- AES-GCM nonce reuse under one key is catastrophic. Producers MUST use a secure random
  source for random object keys, shares, identifiers, and nonces. Derivation schemes
  MUST guarantee distinct object-key inputs.
- Exact wire bytes are cryptographic inputs. Re-encoding is forbidden wherever the
  suite requires original bytes.
- Authorities MUST reject unknown suites, schemes, core fields, and critical
  extensions before authorization or release.
- Capability selection is not in-object negotiation. Silent fallback is forbidden.
- ECDH, ML-KEM, wrapped-key authentication, context, and policy-binding failures MUST
  return the same `KEY_RECOVERY_FAILED` class. ML-KEM implicit-rejection state MUST NOT
  be exposed.
- An XOR_ALL share is sensitive. Fewer than all shares do not reconstruct the object
  key, but malicious shares may cause denial of service. Every recovered share is
  authenticated; payload authentication failure fails the complete open.
- Plaintext, object keys, and unwrapped shares MUST NOT be logged or returned on
  failure. Implementations SHOULD clear transient key material when practical.

## 3. Trust boundaries

`authority_id` is not a trusted endpoint. It MUST be resolved through trusted local
configuration and MUST NOT be dereferenced as an arbitrary URL. URI ownership gives
uniqueness, not trust.

The authority recipient key is distributed outside the object. The deployment remains
responsible for authenticating that key and its mapping to authority identity and
`kid`.

## 4. Metadata and signatures

Carriage is not endorsement. AEAD proves that metadata belongs to the object as
produced, not that claims are true or signers trusted. Trust anchors, certificate
processing, and revocation belong to extension and deployment specifications.

A signature inside Protected Metadata cannot sign the object that contains it because
ciphertext depends on the metadata through payload AAD. Such a signature binds only
what its extension defines. Complete-object attestations are detached and reference a
hash of exact object bytes.

A detached attestation may be removed. Applications requiring one identify the claim
and signer and reject its absence or invalidity.

External labels and handling metadata are not access policy. Mapping to Canonical
Policy must be explicit and deterministic.

## 5. Failure and release

The opener MUST authenticate the payload under the selected suite before treating it
as complete. A registered streaming suite may release authenticated prefix or selected
segment plaintext only under explicit completion and failure semantics.
