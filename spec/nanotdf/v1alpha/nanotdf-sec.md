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

### 2.1 How three bytes become a GCM nonce

The source specification does not say how the three-byte IV is presented to AES-GCM,
and until this revision no document in this suite said either. NanoTDF-PAY §3 stated
only that the IV is used as the AES-GCM nonce. Three readings are consistent with that
sentence, and they produce different ciphertext for the same key and plaintext:

- the three bytes are the whole nonce, so GCM runs with a 24-bit nonce and derives the
  pre-counter block `J0` through GHASH, as SP 800-38D §7.1 Algorithm 4 step 2 requires
  for any IV whose length is not 96 bits;
- the three bytes are right-aligned in a twelve-byte field zero-padded on the left; or
- the three bytes are left-aligned in a twelve-byte field zero-padded on the right.

Two implementations that chose differently would each produce objects the other could
not open, with no diagnostic beyond an authentication failure.

The two vectors in NanoTDF-EX settle it. Each carries the recipient private key, the
ephemeral public key, the IV, the ciphertext, the tag, and the plaintext, so each
reading can be tested by decryption. Only the first reproduces the recorded plaintext
and the recorded tag; the other two fail authentication and yield unrelated bytes,
under both vectors. NanoTDF-PAY §3 states that reading normatively and NanoTDF-CORE §6
records the correction.

This is an interoperability finding rather than a change of format: it names the one
reading under which the suite's own vectors decrypt. An implementation that padded the
IV to twelve bytes was never conforming, because it could not open either vector.

Two things follow from the nonce being 24 bits rather than 96. The GHASH-derived `J0`
costs one extra GHASH block per operation, which is immaterial at these sizes. More
materially, SP 800-38D §8.2 requires that any IV shorter than 96 bits be built by the
deterministic construction of §8.2.1 — a fixed field identifying the context,
concatenated with an invocation field that increments — and the RBG-based construction
of §8.2.2 is unavailable at this length, because it requires a random field of at
least 96 bits. A randomly drawn 24-bit IV therefore inherits none of the uniqueness
guarantees those two constructions exist to provide. SP 800-38D §5.2.1.1 recommends
that implementations "restrict support to the length of 96 bits, to promote
interoperability, efficiency, and simplicity of design"; NanoTDF trades all three for
nine bytes per object.

### 2.2 A 24-bit nonce space

A three-byte IV admits 16,777,216 values, of which `0x000000` is reserved, leaving
16,777,215 for payloads. Drawing them at random, the probability that some pair of
objects encrypted under one derived key shares an IV is:

| Objects under one derived key | P(at least one IV collision) |
|---:|---:|
| 100 | 0.03% |
| 1,000 | 2.93% |
| 2,048 | 11.75% |
| 4,096 | 39.34% |
| 4,823 | 50.00% |
| 8,192 | 86.47% |
| 16,384 | 99.97% |

The even chance falls at 4,823 objects, and the risk is meaningful well below that
whatever the objects weigh: 4,823 maximum-size objects are 75.4 GiB, and 4,823
kilobyte objects are 4.7 MiB. The volume bound of §4 is far above either figure, which
is why the nonce space and not the volume is NanoTDF's operative limit on the lifetime
of a derived key.

A per-key counter removes the birthday term outright and permits 16,777,215 objects
before exhaustion, and it is also the construction SP 800-38D §8.2 requires at this IV
length. It is the better choice rather than merely an acceptable one
(NanoTDF-PAY §3). SP 800-38D §8.3 separately caps invocations under one key at 2^32
for every IV length except a deterministically constructed 96-bit one; with 2^24
usable IVs, NanoTDF exhausts its nonce space 256 times over before reaching that cap,
so the cap never binds.

None of this bites in normal use. The derived key is
`HKDF(ECDH(ephemeral_private, kas_public))`, so a fresh ephemeral key pair yields a
fresh derived key, and NanoTDF-KAO §2.1 requires one per object. Under that rule each
object is the sole occupant of its own 24-bit nonce space and the table above is
inert. The entire hazard is contingent on a producer reusing an ephemeral key pair.

Version 1 cannot prevent that. Creation is offline, so no authority observes the
second object at production time, and no field declares whether the ephemeral key was
freshly generated. The ephemeral public key is on the wire, however, which gives a
deployment one after-the-fact control: a KAS that records the ephemeral public keys it
has seen can detect reuse across rewrap requests, and SHOULD treat a repeat as an
anomaly rather than a routine request. This is the duplicate monitoring of SP 800-38D
Appendix D applied to the key rather than to the IV. It detects; it does not prevent,
and an opener holding a single object cannot tell at all.

### 2.3 The policy and the payload share one key and one nonce space

For policy types `0x02` and `0x03` without Policy Key Access, the encrypted policy is
protected by the same derived key as the payload, under the fixed IV `0x000000`
(NanoTDF-POL §4). Policy and payload are then two AES-GCM invocations under one key,
and they MUST NOT collide. Reserving `0x000000` for the policy and rejecting it for
the payload is what keeps them apart, and it is the one place in the format where
version 1 defends itself against the narrow nonce space.

That defence is scoped to a single object. Two objects that share a derived key — two
objects produced from the same ephemeral key pair against the same KAS key — both
encrypt their policy under the identical key with the identical nonce. This is not a
birthday risk but a certainty on the first repeat, and it discloses the XOR of the two
policy plaintexts, which for short and highly structured policy bodies is usually
equivalent to disclosing both. Ephemeral key reuse is therefore strictly worse for the
policy than for the payload: the payload still gets a fresh IV and the bound in §2.2,
while the policy gets a guaranteed nonce collision.

## 3. Short authentication tags

The Symmetric Cipher Enum admits authentication tags as short as 64 bits
(NanoTDF-ALG §2). The forgery resistance a tag delivers is not its length. It falls as
the authenticated message grows, and again as an attacker obtains more verification
attempts under one key. Version 1 coupled the two to nothing, so this section
tabulates them.

### 3.1 The integrity bound

For `v` forgery attempts against a message of at most `l` sixteen-byte blocks under a
`tau`-bit tag, from the analysis of Iwata, Ohashi and Minematsu as applied to TLS by
Luykx and Paterson, and the same analysis from which RFC 8446 §5.5 derives the TLS 1.3
record limits:

```text
Adv_INT-CTXT <= 2 * v * (l + 1) / 2^tau
```

The largest NanoTDF ciphertext is 16,777,204 bytes, which is 1,048,576 blocks, or
2^20: the three-byte Length field caps IV, ciphertext, and MAC together at 16,777,215
bytes, and 16,777,204 pairs with the eight-byte tag of cipher `0x00`
(NanoTDF-PAY §2). At the longer tags the ciphertext maximum is a few bytes smaller and
rounds to the same 2^20 blocks. NanoTDF defines no associated data for the payload, so
`l` counts ciphertext blocks alone (NanoTDF-PAY §4).

For one forgery attempt, rounded to a hundredth of a bit:

| Cipher | Tag (bits) | 16 MiB, 2^20 blocks | 1 KiB, 64 blocks | 16 B, 1 block |
|---|---:|---:|---:|---:|
| `0x00` | 64 | 2^-43.00 | 2^-56.98 | 2^-62.00 |
| `0x01` | 96 | 2^-75.00 | 2^-88.98 | 2^-94.00 |
| `0x02` | 104 | 2^-83.00 | 2^-96.98 | 2^-102.00 |
| `0x03` | 112 | 2^-91.00 | 2^-104.98 | 2^-110.00 |
| `0x04` | 120 | 2^-99.00 | 2^-112.98 | 2^-118.00 |
| `0x05` | 128 | 2^-107.00 | 2^-120.98 | 2^-126.00 |

A 64-bit tag over a maximum-size payload is worth about 43 bits, not 64. The message
length costs 21 bits of the 64, and that cost is identical at every tag length; only
the short tag cannot absorb it.

### 3.2 Attempts a tag absorbs

Read the other way, the bound gives the number of forgery attempts a tag absorbs
before the cumulative advantage reaches a chosen target. Taking 2^-32 as the target:

| Cipher | Tag (bits) | Attempts at 2^20 blocks | Attempts at 64 blocks |
|---|---:|---:|---:|
| `0x00` | 64 | 2^11.00 — 2,048 | 2^24.98 |
| `0x01` | 96 | 2^43.00 | 2^56.98 |
| `0x02` | 104 | 2^51.00 | 2^64.98 |
| `0x03` | 112 | 2^59.00 | 2^72.98 |
| `0x04` | 120 | 2^67.00 | 2^80.98 |
| `0x05` | 128 | 2^75.00 | 2^88.98 |

One row in this table is reachable. Two thousand and forty-eight attempts is a few
seconds of work against any service that will verify a tag on demand. Every other row
is beyond any attacker, at any payload size NanoTDF can carry.

### 3.3 What SP 800-38D Appendix C requires

Appendix C of SP 800-38D is not advice. For 32-bit and 64-bit tags it states a
requirement: "For any implementation that supports 32-bit or 64-bit tags, one of the
rows in Table 1 or Table 2, respectively, shall be enforced." Each row pairs a maximum
combined length of ciphertext and AAD in a single packet with a maximum number of
invocations of the authenticated decryption function across all instances of GCM under
that key, and the key must be changed before that number is exceeded. Table 2, for
64-bit tags, is:

| Max ciphertext and AAD in one packet (B) | Max authenticated-decryption invocations per key |
|---:|---:|
| 2^15 — 32,768 | 2^32 |
| 2^17 — 131,072 | 2^29 |
| 2^19 — 524,288 | 2^26 |
| 2^21 — 2,097,152 | 2^23 |
| 2^23 — 8,388,608 | 2^20 |
| 2^25 — 33,554,432 | 2^17 |

A maximum-size NanoTDF payload is 16,777,204 bytes, so the only row that admits it is
the last: at most 2^17, or 131,072, authenticated-decryption invocations under that
derived key. The rows are calibrated to comparable residual risk — spending a full row
budget gives a cumulative advantage of 2^-20 at the first row falling to 2^-25 at the
last — so a deployment buys length with attempts at a fixed exchange rate.

Two further Appendix C items bear directly on cipher `0x00`.

- Item 3 requires that "the substance or meaning of the overall message ... should not
  be lost or compromised by the forgery of a single, arbitrary packet", and states that
  "an individual packet should not carry a .txt or .doc file". A NanoTDF payload is
  exactly one whole item of arbitrary content. Cipher `0x00` therefore falls outside
  the circumstances Appendix C describes as appropriate for a 64-bit tag, for most of
  what NanoTDF is used to protect. The tolerable case Appendix C has in mind — one
  packet of a voice or video stream, where a forged packet costs a fraction of a
  second of audio — has no analogue in a format whose payload is the whole object.
- Item 1 requires that failing packets be discarded silently, that authentication
  errors be logged internally in a way undetectable from side-channel information, and
  that the connection be terminated or the user notified when the error rate exceeds
  normal. §9 below and NanoTDF-KAS §5 already require indistinguishable errors, which
  meets the first half. Version 1 required no counting; §3.5 does.

Independently of tag length, SP 800-38D §5.2.1.1 caps one invocation at 2^39 − 256
bits, 68,719,476,704 bytes. NanoTDF's frame cap is 4,096 times below that, so this
limit is never reached.

### 3.4 The tag is the only integrity mechanism

Tag length matters more in NanoTDF than in a format with a second integrity layer,
because there is no second layer. NanoTDF defines no segmentation, no Merkle layout,
and no per-segment integrity; one payload is one AEAD operation (NanoTDF-PAY §4).
There is no manifest digest, no assertion, and no metadata to cross-check. Undetected
modification of the ciphertext is prevented by the payload tag and by nothing else.

The one fallback is the optional creator signature, which covers the Header and the
Payload — every byte of the object before the Signature section (NanoTDF-BND §3.2).
Where it is present and the verifier requires it, a forged tag alone does not yield an
object that verifies. Where it is absent, and it is absent by default and can be
stripped from a signed object without trace (NanoTDF-BND §3.4), the tag stands alone.

A successful GCM forgery is also not a one-off. Each success leaks information about
the hash subkey `H` and raises the probability that the next targeted forgery
succeeds; SP 800-38D Appendix B notes that `H` may eventually be recovered entirely,
after which authentication assurance for that key is gone.

### 3.5 Requirements and guidance

- A 64-bit tag SHOULD be selected only where the size saving is decisive and the
  deployment bounds the number of forgery attempts.
- A producer SHOULD NOT select cipher `0x00` for a payload whose ciphertext exceeds
  32,768 bytes. That is the shortest row of SP 800-38D Table 2 and the only one leaving
  a workable budget of 2^32 verification invocations; the eight bytes saved against
  cipher `0x05` do not pay for the fourteen bits of forgery resistance given up between
  a kilobyte and 16 MiB.
- A producer SHOULD NOT select cipher `0x00` at all where the payload is a
  self-contained document rather than one packet of a stream, per Appendix C item 3.
- A deployment that permits cipher `0x00` MUST enforce one row of SP 800-38D Table 2.
  Because the applicable row is chosen by the largest payload the deployment produces,
  the practical form of this is a producer-side size cap together with a limit on the
  failed authenticated-decryption attempts performed under one derived key. Both are
  deployment controls: neither changes what a conforming parser accepts, and an opener
  still parses and rejects exactly as NanoTDF-PKG §4 requires.
- An opener or a KAS SHOULD count failed authentication and policy-binding
  verifications per derived key, and SHOULD stop performing them once the count reaches
  the limit of the enforced row (NanoTDF-KAS §5). NanoTDF cannot rekey — the derived
  key is a function of the object — so refusing further verification is the only
  response available where SP 800-38D would call for a new key.
- A verifier MUST NOT accept a tag shorter than the length implied by the declared
  cipher, and MUST NOT truncate a longer tag to compare a prefix.
- Deployments without a hard size constraint SHOULD use cipher `0x05`, AES-256-GCM
  with a 128-bit tag.

### 3.6 The 64-bit GMAC policy binding

When `USE_ECDSA_BINDING` is `0` the policy binding is a 64-bit GMAC tag over
`SHA256(policy body)` (NanoTDF-BND §2). The authenticated message is a fixed 32 bytes,
two blocks, so `l` is 2 and the bound is far kinder than for a payload:

| Forgery attempts against one binding | Adv_INT-CTXT |
|---:|---:|
| 1 | 2^-61.42 |
| 2^20 | 2^-41.42 |
| 2^30 | 2^-31.42 |
| 2^32 | 2^-29.42 |

Reaching 2^-32 takes 715,827,883 attempts, about 2^29.42, against 2^11 for a
maximum-size payload at the same tag length. The short fixed-length message does that
work, and it is why the binding is not simply "a 64-bit tag" in the sense §3.1
describes.

The exposure differs in kind rather than in degree. A payload tag is verified by
whoever already holds the object; a policy binding is verified by the KAS, on demand,
for any header a requester chooses to submit. An attacker who keeps one object's
ephemeral public key, which fixes the derived key, and varies the policy body and the
eight binding bytes has an online forgery oracle whose only limit is how quickly the
KAS answers. NanoTDF-KAS §5 requires the KAS's errors to be indistinguishable, which
denies the attacker any signal about which stage rejected the request, but an
indistinguishable rejection is still a rejection: it constrains what an attempt
reveals, not how many attempts are possible.

Two points sharpen this. The derived key protects the payload as well as the binding,
so the Table 2 row a deployment must enforce is chosen by the payload and not by the
32-byte binding message; a deployment carrying maximum-size payloads is held to 2^17
invocations under that key, and binding verifications count against the same budget.
And by §3.4 a successful forgery leaks hash-subkey material, so attempts against a
binding are not independent trials.

A KAS SHOULD therefore count failed policy-binding verifications per ephemeral public
key, rate-limit them, and stop answering for that key once the count reaches the limit
of the enforced row (NanoTDF-KAS §5). This is a deployment control and requires no
change to the wire format or to what a conforming KAS accepts.

## 4. Key usage volume

The companion bound limits how much plaintext one key may protect. For `sigma` total
sixteen-byte plaintext blocks and `q` encryption invocations under one key:

```text
Adv_IND-CPA <= (sigma + q + 1)^2 / 2^129
```

The sibling suites in this repository draw a single rule from it: a content-encryption
key MUST NOT protect more than 2^40 bytes, one tebibyte, of plaintext. That is the
volume at which the advantage reaches 2^-57, matching the margin RFC 8446 §5.5 targets
for TLS 1.3 record limits. NanoTDF version 1 states no volume bound at all.

One object cannot approach it. A maximum-size object gives `sigma = 1,048,576` and
`q = 1`, or `q = 2` with an encrypted policy, for an advantage of 2^-89 — thirty-two
bits of margin below the figure at 2^40 bytes. Reaching 2^40 bytes takes 65,537
maximum-size objects.

The bound is per key, and NanoTDF's derived key is per ephemeral key pair rather than
per object. A producer that generates a fresh ephemeral key pair for each object, as
NanoTDF-KAO §2.1 requires, accumulates nothing: each object is the whole lifetime of
its key. Only a producer that reuses one ephemeral key pair across objects accumulates
volume, and only such a producer can reach 2^40 bytes.

It would exhaust its nonces long first. By §2.2 the chance of an IV collision under
one derived key passes one half at 4,823 objects, which even at the maximum object
size is 75.4 GiB — a factor of about 13.6 below the volume ceiling, and far below it
at realistic NanoTDF sizes. The volume bound is worth stating because it is the bound
a reader will look for and because version 1 is silent on it, but it is not the
constraint that binds.

- A producer MUST NOT protect more than 2^40 bytes of plaintext under one derived key.
  Following NanoTDF-KAO §2.1 satisfies this automatically: a fresh ephemeral key pair
  per object caps the volume under one derived key at 16,777,204 bytes.

## 5. Elliptic curve requirements

No curve below 256 bits is supported, and the curve registry is closed
(NanoTDF-ALG §1). A parser MUST reject an unlisted curve value rather than substituting
a default.

An implementation MUST validate a received public key as a point on the declared curve
before performing ECDH. Compressed point decoding that does not check curve membership
admits invalid-curve attacks that recover the private key.

The ephemeral private key MUST be generated from a cryptographically secure random
source and MUST NOT be retained after the object is produced.

## 6. Binding and signature semantics

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

## 7. Trust boundaries

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

## 8. Offline creation

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

## 9. Failure handling

Key derivation, binding verification, policy resolution, and authorization failures
SHOULD be reported to the requester as one indistinguishable error class. Distinguishing
them tells an attacker which stage rejected the request and turns the KAS into an oracle
for policy structure and key validity.

Plaintext, derived symmetric keys, and ephemeral private keys MUST NOT be logged or
returned on failure. Implementations SHOULD clear transient key material when practical.

The opener MUST authenticate the payload under the declared cipher before releasing any
plaintext. NanoTDF defines no incremental or streaming release.

## 10. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST SP 800-56A: Key Establishment Using Discrete Logarithm Cryptography](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [Luykx and Paterson 2017: Limits on Authenticated Encryption Use in TLS](https://www.isg.rhul.ac.uk/~kp/TLS-AEbounds.pdf)
- [Iwata, Ohashi, and Minematsu 2012: Breaking and Repairing GCM Security Proofs](https://eprint.iacr.org/2012/438)
