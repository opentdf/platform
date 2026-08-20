# NanoTDF-CORE: Object and End-to-End Processing

| | |
|---|---|
| Document | NanoTDF-CORE |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-ALG, NanoTDF-LOC, NanoTDF-PKG, NanoTDF-KAO, NanoTDF-POL, NanoTDF-BND, NanoTDF-PAY, NanoTDF-KAS |
| Referenced by | NanoTDF-EX |

## 1. Scope

NanoTDF is a compact binary format for protecting one payload under one policy. It exists
because the JSON-based TDF, expressive as it is, is too verbose for environments with
constrained storage or bandwidth. NanoTDF keeps attribute-based access control and
cryptographic policy binding while reducing fixed overhead to under 200 bytes.

Format version 12 defines:

- a three-section binary frame containing one payload;
- a single key access, with the symmetric key derived by ECDH and HKDF rather than
  wrapped;
- one policy, remote or embedded, plaintext or encrypted;
- a policy binding that is either a 64-bit GMAC tag or an ECDSA signature;
- a closed registry of four elliptic curves and six AES-256-GCM tag lengths;
- an optional detachable creator signature; and
- offline creation, requiring no network access at production time.

The core does not define a policy language, segmentation, key splitting, multi-KAS
access, assertions, metadata carriage, or streaming. Objects needing those capabilities
use BaseTDF.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as
described by BCP 14 when written in all capitals.

### 1.1 Terminology

- A producer creates a NanoTDF. An opener decrypts one.
- A Key Access Service, or KAS, holds the private key against which an object was
  produced and decides whether to release the derived key.
- The ephemeral key pair is generated for one object and discarded. Its public half is
  carried in the header.
- The creator key is a persistent identity key used only for the optional signature. It
  is unrelated to the ephemeral key.
- The derived key, or payload key, is the AES-256 key produced by ECDH followed by HKDF.
- ECDH is the elliptic-curve Diffie-Hellman key agreement. HKDF derives a fixed-length
  key from a shared secret.
- AEAD encrypts data and detects changes to the ciphertext. GMAC is the
  authentication-only mode of AES-GCM, used here for the policy binding.
- A compressed point is the X9.62 encoding of an elliptic-curve public key as a parity
  byte followed by the x-coordinate.
- The policy binding cryptographically ties the policy to the payload key.

## 2. Object model

A NanoTDF is immutable. Three sections define what governs release, what is protected,
and who produced it:

```text
+-----------------------+
| Header                |   sent to the KAS
+-----------------------+
| Payload               |   never leaves the client
+-----------------------+
| Signature  (optional) |   detachable provenance
+-----------------------+
```

The Header is self-delimiting and self-sufficient: it can be parsed and transmitted
without the rest of the object. That property is what keeps a rewrap request small
regardless of payload size (NanoTDF-KAS §2).

The Signature is genuinely optional and genuinely detachable. Stripping it and clearing
`HAS_SIGNATURE` yields a well-formed object, and nothing records that it was ever present
(NanoTDF-BND §3.4).

### 2.1 Design assumptions

- Elliptic curve cryptography with ECDH and HKDF derives every key. No RSA, and no
  wrapped key material on the wire.
- No curve below 256 bits is supported, and the curve registry is closed.
- All integers are unsigned and big-endian.
- One object carries one policy and one key access.

### 2.2 Length dependencies

Several fields are sized by other fields rather than by a length prefix. This constrains
parse order, and an implementation that reads the object out of order will not work.

| Field | Sized by |
|---|---|
| Ephemeral public key | Ephemeral ECC Params Enum (ECC and Binding Mode) |
| Policy binding, ECDSA case | Ephemeral ECC Params Enum |
| Policy Key Access ephemeral key | Ephemeral ECC Params Enum |
| Payload MAC | Symmetric Cipher Enum (Symmetric and Payload Config) |
| Creator public key and signature | Signature ECC Mode (Symmetric and Payload Config) |
| Presence of the Signature section | `HAS_SIGNATURE` (Symmetric and Payload Config) |

Both configuration bytes therefore MUST be parsed before the policy, the ephemeral key,
or the payload can be located.

### 2.3 Producer lifecycle

This subsection is non-normative; the referenced component requirements are normative.

1. Generate an ephemeral key pair on the selected curve and derive the symmetric key
   against the KAS public key (NanoTDF-KAO §2).
2. Serialize the policy body — a Resource Locator, or embedded content encrypted under
   the reserved IV where required (NanoTDF-POL §3).
3. Compute the policy binding over those exact bytes (NanoTDF-BND §2).
4. Encrypt the payload under a fresh IV that is not `0x000000` (NanoTDF-PAY §3).
5. Serialize the header and payload per NanoTDF-PKG §2.
6. If a signature is required, sign the serialized header and payload with the persistent
   creator key and append the Signature section (NanoTDF-BND §3).

Step 2 completes before step 3 because the binding is computed over the serialized policy
body bytes. Step 5 completes before step 6 because the signature covers those bytes.

## 3. Opening procedure

A conforming opener performs:

1. Frame validation per NanoTDF-PKG §4: magic, version, section bounds, reserved IV, and
   absence of trailing bytes.
2. Curve and cipher validation against the registries in NanoTDF-ALG §1 and §2, rejecting
   unlisted values.
3. Creator signature verification, if present and if the application requires provenance
   (NanoTDF-BND §3.3).
4. A key request to the KAS named in the header, sending the header (NanoTDF-KAS §2).
5. Policy binding verification against the returned key (NanoTDF-BND §2.3).
6. Payload authentication under the declared cipher, before any plaintext is released
   (NanoTDF-PAY §5).

An opener that holds the KAS private key itself performs step 4 locally, deriving the key
per NanoTDF-KAO §2 rather than making a request.

## 4. Size characteristics

The minimum object is 67 bytes: a 53-byte header and a 14-byte payload with empty
plaintext. Realistic objects are larger, dominated by the two Resource Locators and the
policy binding.

The second worked example in NanoTDF-EX carries a 15-byte KAS hostname, a 29-byte remote
policy locator, an ECDSA binding, and a 128-bit tag, for 173 bytes of overhead — which is
the basis of the format's sub-200-byte claim. The first example, with a signature
attached, costs 253 bytes.

## 5. Conformance

At minimum, interoperability tests SHOULD cover:

- byte-identical production and parsing of both vectors in NanoTDF-EX across
  implementations;
- rejection of a version below 12 and of an unrecognized magic number;
- rejection of a payload IV of `0x000000`;
- rejection of unlisted curve, cipher, and policy-type values;
- rejection of a non-zero reserved field in the ECC and Binding Mode byte;
- rejection of trailing bytes with and without a signature;
- both binding modes, GMAC and ECDSA, including an object whose Signature ECC Mode names
  a different curve than its Ephemeral ECC Params Enum;
- all four curves and all six cipher settings, checking derived field lengths;
- signature present, signature absent, and signature stripped from a signed object;
- all four policy types, including Policy Key Access;
- a policy body modified by one byte, which must fail binding verification;
- a ciphertext modified by one byte, which must fail payload authentication; and
- KAS denial, malformed header, and unresolvable remote policy, which must be
  indistinguishable to the requester.

Cross-language vectors SHOULD include the complete object, the header bytes as sent to
the KAS, the policy body bytes, the ephemeral and creator key pairs, the HKDF salt, the
derived key, and the expected failure class.

## 6. Deviations from the source specification

This suite reorganizes the nanotdf version 1 specification without changing its wire
format. Where the source is internally inconsistent, incomplete, or in error, this suite
states the corrected value and records the correction here. Every deviation below is
editorial or clarifying; none alters the bytes an implementation produces.

| # | Source | Issue | Resolution |
|---|---|---|---|
| 1 | §3.3.1.3.2 | Describes the Ephemeral ECC Params Enum as a "7-bit length enum" while the same section's table gives it 3 bits with 4 unused | 3 bits at indices 2–0, with 4 reserved bits at 6–3, per NanoTDF-PKG §3.3. Both worked examples confirm the 3-bit reading. |
| 2 | §3.4.2.3.2.3.2 | Gives the Policy Key Access ephemeral public key as 33–133 bytes | 33–67 bytes, the compressed-point range used everywhere else in the format (NanoTDF-ALG §1). |
| 3 | §3.4.2.3.2.3 | Gives Policy Key Access a total of 36–136 bytes, which its own sub-table contradicts | 36–324 bytes: a 3–257 byte Resource Locator plus a 33–67 byte compressed key (NanoTDF-KAO §4). |
| 4 | §3.3.1 | Gives the Policy section as 3–257 bytes, omitting the type enum and the binding | 12–714 bytes (NanoTDF-POL §2). |
| 5 | §3.3 | Gives the Header as 43–584 bytes | 53–1,043 bytes, following from the corrected Policy range (NanoTDF-PKG §2). |
| 6 | §3.3 | Gives the Signature as 97–133 bytes; the maximum is `67 + 132` for `secp521r1` | 97–199 bytes (NanoTDF-BND §3.1). |
| 7 | §3.4.2.4 | Does not state which curve sizes an ECDSA policy binding, though two curve fields exist | The Ephemeral ECC Params Enum, not the Signature ECC Mode (NanoTDF-BND §2.2). |
| 8 | §3.3.1.2 | Cross-reference to the Resource Locator definition is an unresolved placeholder, `[section X.X.X.X]()` | Resolved to NanoTDF-LOC §1. |
| 9 | §3.4.2 | Subsection numbering skips §3.4.2.2 | Renumbered contiguously in NanoTDF-POL. |
| 10 | §3.4.1.1.1 | Describes the Shared Resource Directory protocol `0xff` as experimental but defines no resolution procedure or failure behaviour | Non-normative for version 1; rejected unless the deployment opts in out of band (NanoTDF-LOC §2.1). |
| 11 | §6.1.6 | The parsing breakdown omits the three-byte payload Length field and nests Payload and Signature beneath the Header heading | Corrected in NanoTDF-EX: Length is shown, and the three sections are siblings. |

One figure that looks wrong is correct and has been preserved. The Payload range of
14–16,777,218 bytes reconciles: the three-byte Length field caps the IV, ciphertext, and
MAC together at 16,777,215, and the stated 16,777,204-byte ciphertext maximum pairs with
the 8-byte minimum MAC. Adding the two independent maxima overshoots because they cannot
co-occur (NanoTDF-PAY §2).

## 7. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms](https://www.rfc-editor.org/rfc/rfc6090)
- [RFC 6637: ECC in OpenPGP](https://www.rfc-editor.org/rfc/rfc6637)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [FIPS 180-4: Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [FIPS 197: AES](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
