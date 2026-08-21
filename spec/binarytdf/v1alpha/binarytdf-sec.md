# BinaryTDF-SEC: Security Considerations

| | |
|---|---|
| Document | BinaryTDF-SEC |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | None |
| Referenced by | All BinaryTDF components |

## 1. Parser limits

Every parser MUST enforce limits before allocation, hashing, or authority contact. The
following are frame version 2 baselines; profiles MAY set lower limits.

| Input | Required handling |
|---|---|
| Frame section length | Check overflow and remaining bytes before conversion or allocation; enforce a finite maximum |
| Ciphertext | Streaming is permitted; never allocate directly from the untrusted `uint64` length |
| Content volume | Reject a frame whose declared plaintext exceeds the suite limits of Section 3 before decryption |
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

## 3. AEAD usage bounds

AES-256-GCM security degrades with the volume of data protected under one key. Two
bounds apply, from the analysis of Iwata, Ohashi, and Minematsu as applied to TLS by
Luykx and Paterson. RFC 8446 Section 5.5 derives its record limits from the same
analysis. BinaryTDF-CORE Section 5 lists all three works.

For `sigma` total 16-byte plaintext blocks and `q` encryption invocations under one
key, confidentiality is bounded by:

```text
Adv_IND-CPA <= (sigma + q + 1)^2 / 2^129
```

For `v` forgery attempts against messages of at most `l` blocks with a `tau`-bit tag,
integrity is bounded by:

```text
Adv_INT-CTXT <= 2 * v * (l + 1) / 2^tau
```

### 3.1 Volume limit

`sigma` dominates `q` at every segment size BinaryTDF permits, so the confidentiality
bound is a function of total plaintext bytes under one key:

| Total plaintext under one key | IND-CPA advantage |
|---|---:|
| 2^38 bytes (256 GiB) | 2^-61 |
| 2^40 bytes (1 TiB) | 2^-57 |
| 2^42 bytes (4 TiB) | 2^-53 |
| 2^43 bytes (8 TiB) | 2^-51 |
| 2^45 bytes (32 TiB) | 2^-47 |
| 2^63 bytes (8 EiB) | 2^-11 |

RFC 8446 Section 5.5 targets approximately 2^-57 for AES-GCM. Its record limit of
2^24.5 records of 2^14 bytes is 2^38.5 bytes, about 389 GB, which attains 2^-60.
BinaryTDF adopts that margin at the round volume reaching it exactly.

A single content-encryption key MUST NOT protect more than 2^40 bytes
(1099511627776) of plaintext. The limit is cumulative over the life of the key and is
independent of how the plaintext is divided.

| Suite | Key bounded by this limit | Effect |
|---:|---|---|
| 1 | payload key | unreachable; Section 3.6 binds first at 68719476704 bytes |
| 2 | payload key | complete object at most 2^40 bytes, BinaryTDF-STREAM Section 8.1 |
| 3 | partition key `K_p` | each partition at most 2^40 bytes, no ceiling on the object |

A suite 3 payload key performs no AES-GCM encryption. It is only the pseudorandom key
from which each `K_p` is expanded, so this bound does not apply to it.

### 3.2 Segmentation is not rekeying

`sigma` counts plaintext blocks however they are divided into segments, and `q` is
negligible beside it. At 2^40 bytes under one key with 1 MiB segments, `sigma` is 2^36
blocks and `q` is about 2^20 invocations, which moves the bound by less than a
thousandth of a bit. Halving the segment size doubles `q` and leaves `sigma`
unchanged.

Smaller segments therefore do not extend the volume one key may protect, and a
segmented suite does not escape the volume bound that constrains a single-message
suite. A segmented suite escapes only the per-invocation limit of Section 3.6, which
is a framing limit on one GCM call. Rekeying is the only mechanism that extends the
volume bound, and in BinaryTDF that mechanism is suite 3 partition-key derivation.

### 3.3 Scale example

The Amazon S3 single-object maximum is 5 TiB, or 5497558138880 bytes. Protected under
one key it gives `sigma = 5 * 2^36` blocks and an advantage of about 2^-52.4, past the
target margin. Suite 2 therefore tops out at 2^40 bytes, a fifth of such an object.
Suite 3 places at most 2^40 bytes under each partition key, so the same object needs
no more than six partition keys and no key exceeds the limit. BinaryTDF-STREAM Section
9 gives the parameters and the resulting maximum object size, which is about 1.7
million times the S3 maximum.

### 3.4 Integrity bound

BinaryTDF uses 16-byte tags in every suite, so integrity is not a constraint. The
largest message any suite permits is one 2147483647-byte segment, which is
`l = 2^27` blocks, or 134217728 after rounding up. Against 2^32 forgery attempts the
bound is `2 * 2^32 * (2^27 + 1) / 2^128`, about 2^-68. At a 1 MiB segment, `l = 2^16`,
the same expression is about 2^-79. Integrity imposes no rekeying requirement at any
registered parameter.

### 3.5 Object-key freshness

Every object key protects exactly one object. BinaryTDF-PAY Section 1 states that
requirement; the AEAD bounds are its reason.

Suite 1 draws a fresh 12-byte nonce for its single message, so one object key means
one AES-GCM message under one payload key. That is why suite 1 needs no volume rule
beyond the per-invocation limit.

Suites 2 and 3 derive the payload key from the object key and a fresh 32-byte
`stream_salt`, and their nonce prefix is only 56 bits. A repeated object key alone
does not repeat a payload key, but a repeated object key and salt together do, and
`N` streams under one payload key collide on the nonce prefix with probability about
`N^2 / 2^57`: about 2^-17 at 2^20 streams and even odds at 2^28. A repeated prefix
repeats the exact key and nonce at every common segment index, which is the
catastrophic failure Section 2 forbids. Partition derivation does not reduce this
risk, because `K_p` is a deterministic function of the payload key alone.

### 3.6 Per-invocation limit

NIST SP 800-38D Section 5.2.1.1 caps one GCM invocation at 2^39 - 256 bits, that is
68719476704 bytes, or 64 GiB - 32 bytes. No suite may exceed it in one AES-GCM call.
Suite 1 encrypts the complete payload in one call, so this is its hard object ceiling;
the 64-bit Ciphertext Length of BinaryTDF-PKG frames far more than GCM can protect,
and only the normative requirement in BinaryTDF-PAY Section 4 closes that gap. Suites
2 and 3 encrypt one segment per call, and their 2147483647-byte maximum segment is far
below the cap.

Suites 2 and 3 construct nonces deterministically in the sense of SP 800-38D Section
8.2.1, with `nonce_prefix` as the fixed field and `uint32_be(i) || final_byte` as the
invocation field. The 2^32-invocation cap of SP 800-38D Section 8.3 applies to
RBG-based construction and therefore does not apply to them; their 2^32 segment
ceiling comes from the width of the index field. Suite 1 does use an RBG-based nonce,
and its one invocation per key is far inside that cap.

## 4. Trust boundaries

`authority_id` is not a trusted endpoint. It MUST be resolved through trusted local
configuration and MUST NOT be dereferenced as an arbitrary URL. URI ownership gives
uniqueness, not trust.

The authority recipient key is distributed outside the object. The deployment remains
responsible for authenticating that key and its mapping to authority identity and
`kid`.

## 5. Metadata and signatures

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

## 6. Failure and release

The opener MUST authenticate the payload under the selected suite before treating it
as complete. A registered streaming suite may release authenticated prefix or selected
segment plaintext only under explicit completion and failure semantics.
