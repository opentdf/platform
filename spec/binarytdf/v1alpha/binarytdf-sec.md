# BinaryTDF-SEC: Security Considerations

| | |
|---|---|
| Document | BinaryTDF-SEC |
| Version | 1 Alpha |
| Source draft | 0.3 |
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

AES-256-GCM security degrades with the volume of data protected under each key and
with the number and size of forgery attempts. RFC 8446 Section 5.5 adopted an
approximately `2^-57` overall AE target using the analysis of Luykx and Paterson.
BinaryTDF adopts `2^-57` as its maximum object-wide confidentiality advantage and
accounts for integrity separately. BinaryTDF-CORE Section 5 lists the references.

RFC 9001 Appendix B.1 applies the tighter multi-user GCM analysis of Hoang, Tessaro,
and Thiruvengadam. For a single user with unique nonces, its dominant confidentiality
term is `2 * (q * l)^2 / 2^128`. Writing `sigma_p` for the total number of 16-byte
plaintext blocks protected under content-encryption key `K_p`, and applying a
conservative hybrid argument across independently derived partition keys, BinaryTDF
uses:

```text
Adv_conf(object) <= 2 * sum(sigma_p^2 for every p) / 2^128
```

Therefore an object meets the `2^-57` target when:

```text
sum(sigma_p^2 for every p) <= 2^70
```

This mode-level bound assumes AES is a secure pseudorandom permutation, HKDF-SHA256
produces pseudorandom partition keys, and every nonce is unique under its key. The
corresponding primitive and KDF advantages are additional negligible terms.

For `v` forgery attempts against messages of at most `l` blocks with a `tau`-bit tag,
integrity is bounded by:

```text
Adv_INT-CTXT <= 2 * v * (l + 1) / 2^tau
```

### 3.1 Object-wide confidentiality budget

For one content-encryption key, the block-square budget implies an absolute ceiling of
`2^35` plaintext blocks, or at most `2^39` bytes (512 GiB). Reaching that ceiling
spends the entire object-wide target on that key, so a multi-partition object needs
substantially smaller partitions. The limit is cumulative over the life of every key
and is independent of how plaintext is divided into segments.

For an object containing `B` plaintext bytes divided into equal `b`-byte partitions,
the dominant term simplifies to approximately:

```text
Adv_conf(object) <= B * b / 2^135
```

At 50 TiB this permits partitions no larger than approximately 5.12 GiB. BinaryTDF
RECOMMENDS partitions of approximately 1 GiB, which yield an object-wide advantage
below `2^-59`. BinaryTDF-STREAM Sections 8.1 and 9.4 define the normative checks in
terms of actual per-invocation block counts.

| Suite | Key bounded by this limit | Effect |
|---:|---|---|
| 1 | payload key | unreachable; Section 3.6 binds first at 68719476704 bytes |
| 2 | payload key | complete object at most 2^35 blocks, BinaryTDF-STREAM Section 8.1 |
| 3 | partition key `K_p` | sum of squared partition block counts at most 2^70 |

A suite 3 payload key performs no AES-GCM encryption. It is only the pseudorandom key
from which each `K_p` is expanded, so this bound does not apply to it.

### 3.2 Segmentation is not rekeying

`sigma_p` counts plaintext blocks however they are divided into segments. Halving the
segment size while retaining the same partition bytes leaves `sigma_p` essentially
unchanged; the only difference is conservative rounding of partial final blocks in
individual invocations.

Smaller segments therefore do not extend the volume one key may protect, and a
segmented suite does not escape the volume bound that constrains a single-message
suite. A segmented suite escapes only the per-invocation limit of Section 3.6, which
is a framing limit on one GCM call. Rekeying is the only mechanism that extends the
volume bound, and in BinaryTDF that mechanism is suite 3 partition-key derivation.

### 3.3 Scale example

Amazon S3 multipart limits advertise a 50 TB object and specify an exact maximum of
50,000 GiB, approximately 48.83 TiB. BinaryTDF's scalable range includes a 50 TiB
logical plaintext so that it also covers that storage limit when encrypted bytes are
mapped across enough physical storage.

A 50 TiB plaintext encrypted under one key has `sigma = 50 * 2^36` blocks and a
confidentiality advantage of approximately `2^-43.7`, well past the target. Merely
using fifty 1 TiB keys would satisfy the former per-key rule but would still give a
conservative object-wide advantage of approximately `2^-49.4`.

At approximately 1 GiB per partition, the same object uses about 51,200 partition
keys. Each protects approximately `2^26` blocks, and:

```text
Adv_conf(object) <= 2 * 51,200 * (2^26)^2 / 2^128 < 2^-59
```

BinaryTDF-STREAM Section 9.5 gives exact wire parameters and block counts. Partition
keys are derived on demand from one payload key and do not add KAOs or CBOR metadata.

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
one AES-GCM message under one payload key. Its per-invocation limit is safely inside
the object-wide confidentiality budget.

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
