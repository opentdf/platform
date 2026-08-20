# NanoTDF-SEC: Security Considerations

| | |
|---|---|
| Document | NanoTDF-SEC |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | None |
| Referenced by | All NanoTDF components |

## 1. Parser limits

Every parser MUST enforce limits before allocation, key derivation, or authority
contact. NanoTDF's length fields are narrow, so most bounds are structural rather than
configurable.

| Input | Required handling |
|---|---|
| Resource Locator body | Length is one byte; the body is at most 255 bytes |
| Embedded policy content | At most 255 bytes, bounded by the Policy section maximum |
| Payload length | Three bytes, at most 16,777,215; a framing bound, not an allocation instruction |
| Ephemeral public key | Length is implied by the curve, never read from the wire |
| Trailing bytes | Rejected; see NanoTDF-PKG §4 |

A decoder MUST NOT allocate directly from a declared length before confirming that the
remaining input can satisfy it. Offset and capacity arithmetic MUST be checked for
overflow.

## 2. Nonce and IV reuse

AES-GCM nonce reuse under one key is catastrophic: it discloses the XOR of two
plaintexts and permits authentication-tag forgery. NanoTDF makes this hazard sharper
than most formats for three reasons.

- The payload IV is only three bytes. A producer MUST NOT encrypt many objects under
  one derived key, and MUST draw each IV from a cryptographically secure random source
  or a per-key counter that cannot repeat.
- The IV value `0x000000` is reserved for the encrypted policy and is never written to
  the wire for that purpose. A payload IV of `0x000000` MUST be rejected.
- Because the encrypted-policy IV is fixed, the key used to encrypt a policy MUST NOT
  be used to encrypt any other policy or payload. Where a distinct policy key is
  required, use Policy Key Access (NanoTDF-KAO §4).

Each object derives its symmetric key from a fresh ephemeral key pair. Reusing an
ephemeral key pair across objects defeats that separation and reintroduces the reuse
hazard.

## 3. Short authentication tags

The Symmetric Cipher Enum admits authentication tags as short as 64 bits
(NanoTDF-ALG §2). A 64-bit tag offers roughly 64 bits of forgery resistance, which is
below contemporary guidance and degrades further as an attacker obtains more
verification attempts against one key.

- A 64-bit tag SHOULD be selected only where the size saving is decisive and the
  deployment bounds the number of forgery attempts.
- A verifier MUST NOT accept a tag shorter than the length implied by the declared
  cipher, and MUST NOT truncate a longer tag to compare a prefix.
- Deployments without a hard size constraint SHOULD use cipher `0x05`, AES-256-GCM
  with a 128-bit tag.

## 4. Elliptic curve requirements

No curve below 256 bits is supported, and the curve registry is closed
(NanoTDF-ALG §1). A parser MUST reject an unlisted curve value rather than substituting
a default.

An implementation MUST validate a received public key as a point on the declared curve
before performing ECDH. Compressed point decoding that does not check curve membership
admits invalid-curve attacks that recover the private key.

The ephemeral private key MUST be generated from a cryptographically secure random
source and MUST NOT be retained after the object is produced.

## 5. Binding and signature semantics

The two binding modes protect different things, and the choice is visible on the wire.

- A 64-bit GMAC binding proves only that the binding was produced by a party holding
  the derived symmetric key. Because the KAS can derive that key, a GMAC binding does
  not attribute the policy to any particular producer.
- An ECDSA binding is verifiable against the ephemeral public key in the header, and
  ties the policy to the holder of the matching ephemeral private key at creation time.

Neither mode authenticates the producer's identity. Only the optional creator signature
(NanoTDF-BND §3) does that, and it does so with a persistent key that the format itself
does not distribute or validate.

Carriage is not endorsement. A valid signature proves that the named key signed the
object; it does not establish that the signer is trusted, that the policy is correct, or
that the key has not been revoked. Trust anchors, certificate handling, and revocation
are deployment concerns.

A signature is optional and can be removed by re-encoding the object with
`HAS_SIGNATURE` cleared. An application that requires provenance MUST reject an object
whose signature is absent rather than treating absence as acceptable.

## 6. Trust boundaries

The KAS Resource Locator is a name, not a trust anchor. Ownership of a URL gives
uniqueness, not authority, and an object may name any locator.

- A client MUST resolve the KAS locator through trusted local configuration — an
  allow-list, a catalog, or a service registry — and MUST NOT dispatch on the literal
  value.
- A validator MUST NOT dereference any locator in an object. Doing so turns every
  malformed or hostile object into an outbound request and leaks the fact and timing of
  validation. See NanoTDF-LOC §3.
- The remote-policy case means policy content may be unavailable, may change between
  two retrievals, and is not authenticated by the object. The binding covers the policy
  body bytes, which for a remote policy are the locator, not the policy it names.

## 7. Offline creation

NanoTDF is designed to be produced without contacting a KAS. That property has
consequences a deployment must accept.

- The producer cannot learn at creation time whether the KAS public key it holds has
  been rotated or revoked. Objects produced against a retired key become
  undecryptable.
- No creation-time audit record exists at the KAS. The first evidence of an object's
  existence is the rewrap request made when it is opened.
- The strength of the object depends entirely on the producer's random source. A weak
  or duplicated ephemeral key compromises the object with no server-side check that
  would detect it.

## 8. Failure handling

Key derivation, binding verification, policy resolution, and authorization failures
SHOULD be reported to the requester as one indistinguishable error class. Distinguishing
them tells an attacker which stage rejected the request and turns the KAS into an oracle
for policy structure and key validity.

Plaintext, derived symmetric keys, and ephemeral private keys MUST NOT be logged or
returned on failure. Implementations SHOULD clear transient key material when practical.

The opener MUST authenticate the payload under the declared cipher before releasing any
plaintext. NanoTDF defines no incremental or streaming release.

## 9. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST SP 800-56A: Key Establishment Using Discrete Logarithm Cryptography](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
