# NanoTDF-KAS: Key Access Service Protocol

| | |
|---|---|
| Document | NanoTDF-KAS |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-LOC, NanoTDF-KAO, NanoTDF-POL, NanoTDF-BND |
| Referenced by | NanoTDF-CORE |

## 1. The KAS reference

The header names one Key Access Service through a Resource Locator (NanoTDF-LOC §1),
placed immediately after the magic-and-version bytes. Exactly one KAS governs an object;
there is no list, no alternative, and no quorum.

The locator is a name, not a trust anchor. A client MUST resolve it through trusted local
configuration and MUST NOT dispatch on the literal value or dereference it during parsing
(NanoTDF-SEC §7).

The KAS public key used to produce the object is not carried in the header and is not
identified by any key identifier. Producer and KAS must therefore agree on which key is
current out of band, and a deployment MUST retain superseded private keys for as long as
objects produced against them need to remain readable (NanoTDF-KAO §3).

## 2. The exchange

The header is the unit sent to the KAS. It is self-delimiting and contains everything the
KAS needs: the ephemeral public key, the policy, the binding, and the configuration bytes
that size them.

The payload never leaves the client. This is the property that makes the exchange
practical for constrained links — the request is bounded by the header size, at most
about a kilobyte, regardless of how large the protected content is.

A conforming KAS performs, in order:

1. Parse the header and enforce parser limits (NanoTDF-SEC §1).
2. Recompute the shared secret by ECDH between its own private key and the ephemeral
   public key from the header, validating that key as a point on the declared curve.
3. Derive the symmetric key through HKDF (NanoTDF-KAO §2).
4. Verify the policy binding (NanoTDF-BND §2).
5. Resolve the policy: read the embedded body, decrypting it if required, or retrieve the
   remote policy named by the locator.
6. Authenticate the requester and evaluate the policy against the requester's attributes.
7. On success, return the derived key to the requester over a confidential channel.

Steps 2 through 4 come before step 6. A KAS MUST NOT evaluate or act on a policy whose
binding it has not verified, because an unverified policy is attacker-controlled.

## 3. Returning the key

The derived key is the payload key. Returning it in the clear would expose the payload to
anyone observing the response, so the response MUST be protected.

- The exchange MUST occur over a channel providing confidentiality, integrity, and server
  authentication. Where the KAS locator names `http`, that channel MUST be supplied by
  the deployment; a plain `http` exchange is not conforming (NanoTDF-LOC §2).
- A KAS SHOULD additionally rewrap the key to a requester-supplied session public key, so
  that the released key is protected end to end rather than only in transit. NanoTDF does
  not define the rewrap encoding; the transport protocol does.
- The requester MUST authenticate to the KAS. NanoTDF defines no authentication mechanism
  and carries no requester identity; this is supplied by the transport.

## 4. Policy resolution

For an embedded policy the KAS has the bytes in hand. For type `0x02` or `0x03` it
decrypts them first, using the payload key or, where Policy Key Access is present, the key
derived from the Policy Key Access structure (NanoTDF-KAO §4).

For a remote policy the KAS retrieves the content named by the locator. Because the
binding covers only the locator bytes, the retrieved content is not authenticated by the
object (NanoTDF-LOC §4). A KAS SHOULD resolve remote policy only through infrastructure
it controls or explicitly trusts, and MUST apply the fetch constraints in NanoTDF-LOC §3.

Failure to retrieve a remote policy MUST result in denial. A KAS MUST NOT release a key
under a default or fallback policy when the named policy is unavailable.

## 5. Failure handling

Header parse failure, curve validation failure, binding verification failure, policy
resolution failure, and authorization denial MUST be reported to the requester as one
indistinguishable error class. Distinguishing them turns the KAS into an oracle for
policy structure, key validity, and object well-formedness (NanoTDF-SEC §9).

A KAS MUST NOT return the derived key, the shared secret, or decrypted policy content on
any failure path, and MUST NOT log them.

Indistinguishable errors limit what a failed request reveals; they do not limit how many
failed requests a party may make. A KAS verifying a 64-bit GMAC policy binding is an
online forgery oracle for that binding, bounded only by its own throughput
(NanoTDF-SEC §3.6). A KAS therefore SHOULD count failed policy-binding verifications per
ephemeral public key, rate-limit them, and stop verifying for that key once the count
reaches the limit its deployment enforces under SP 800-38D Appendix C
(NanoTDF-SEC §3.3). NanoTDF has no rekey: the derived key is a function of the object, so
refusing further verification is the only response available.

A KAS SHOULD also record the ephemeral public keys it has seen. A repeat identifies an
object produced from a reused ephemeral key pair, which is the precondition for both the
nonce-reuse and the volume hazards in NanoTDF-SEC §2.2 and §4, and which NanoTDF-KAO §2.1
forbids. Rewrap is the only point at which a deployment can observe it.

## 6. Auditing

The rewrap request is the first and only point at which the KAS learns an object exists;
creation is offline (NanoTDF-KAO §3). A deployment that requires an audit trail therefore
records access, not creation, and MUST NOT assume that the absence of a record means an
object was never produced.

An audit record SHOULD identify the requester, the resolved policy, and the decision. It
MUST NOT contain the derived key.

## 7. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST SP 800-56A: Key Establishment Using Discrete Logarithm Cryptography](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
