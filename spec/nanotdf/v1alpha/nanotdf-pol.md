# NanoTDF-POL: Policy Object

| | |
|---|---|
| Document | NanoTDF-POL |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-ALG, NanoTDF-LOC, NanoTDF-PKG, NanoTDF-KAO |
| Referenced by | NanoTDF-BND, NanoTDF-KAS, NanoTDF-CORE, NanoTDF-EX |

## 1. Scope

A NanoTDF carries exactly one policy. This document defines the policy object's
structure and its four body types; the cryptographic binding that ties the policy to the
payload is defined in NanoTDF-BND.

NanoTDF does not define a policy *language*. The policy body is an opaque byte string
whose interpretation belongs to the KAS and the deployment. A conforming parser reads its
length and preserves its bytes; it does not parse its contents.

## 2. Structure

| Field | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Type Enum | 1 | 1 |
| Body | 3 | 581 |
| Binding | 8 | 132 |
| **Total** | **12** | **714** |

The Binding length follows the binding method selected by `USE_ECDSA_BINDING`
(NanoTDF-PKG §3.3): 8 bytes for a 64-bit GMAC tag, or 64 to 132 bytes for an ECDSA
signature sized by the ephemeral curve.

## 3. Type enumeration

| Value | Body |
|---|---|
| `0x00` | Remote Policy |
| `0x01` | Embedded Policy, plaintext |
| `0x02` | Embedded Policy, encrypted |
| `0x03` | Embedded Policy, encrypted, with Policy Key Access |

Values outside this table are unreserved and MUST be rejected.

### 3.1 Remote policy

The body is a Resource Locator (NanoTDF-LOC §1) naming where the policy may be
retrieved. This is the smallest option and the one used by both worked examples in
NanoTDF-EX.

The binding covers the locator bytes, not the policy those bytes name. A party who
controls the resolution of that locator can change the effective policy without
invalidating the binding, so remote policy SHOULD be used only where the resolver is as
trusted as the KAS (NanoTDF-LOC §4).

### 3.2 Embedded policy

Types `0x01` through `0x03` carry the policy in the object.

| Field | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Content Length | 2 | 2 |
| Plaintext or Ciphertext | 1 | 255 |
| Policy Key Access (type `0x03` only) | 36 | 324 |

Content Length is the length of the plaintext or ciphertext that follows. It is a
two-byte field, but the policy content is limited to 255 bytes, so the high byte is zero
for every legal value. A parser MUST reject a Content Length that exceeds 255 or that
overruns the remaining input.

Policy Key Access is present if and only if the type is `0x03`. Its structure and
key-derivation rules are defined in NanoTDF-KAO §4.

## 4. Policy encryption

For types `0x02` and `0x03` the policy content is encrypted with the cipher selected in
the Symmetric and Payload Config byte (NanoTDF-ALG §2) — the same cipher used for the
payload.

There is no IV field. To save three bytes, the encrypted policy always uses the reserved
IV `0x000000`, which is why a payload IV of `0x000000` is invalid (NanoTDF-PKG §4).

This makes key separation mandatory rather than advisory:

- The key used to encrypt a policy MUST NOT be used to encrypt any payload, and MUST NOT
  be used for any other policy. A fixed IV under a reused key repeats a nonce, which is
  catastrophic for AES-GCM (NanoTDF-SEC §2).
- Where a policy must be encrypted to a different party than the payload, use type
  `0x03` and derive a separate policy key through Policy Key Access.

The Content Length for an encrypted policy is the length of the ciphertext including its
authentication tag.

## 5. Choosing a policy type

| Type | Size cost | Policy visible to holder | Policy fixed at creation |
|---|---|---|---|
| `0x00` Remote | Smallest | No | No |
| `0x01` Embedded plaintext | Content plus 2 | Yes | Yes |
| `0x02` Embedded encrypted | Content plus 2 | No | Yes |
| `0x03` Embedded encrypted with PKA | Content plus 38 or more | No | Yes |

An embedded plaintext policy is readable by anyone holding the object. Where attribute
values are themselves sensitive — a compartment name, a project code — type `0x01`
discloses them to every party that touches the object, including those who cannot decrypt
the payload.

An embedded policy is immutable once written, because its bytes are covered by the
binding. Changing it requires producing a new object.

## 6. Parsing requirements

- The exact policy body bytes are a cryptographic input to the binding. A decoder MUST
  retain them as received and MUST NOT re-serialize, canonicalize, or normalize them
  (NanoTDF-BND §2).
- A decoder MUST verify the binding before acting on the policy, and a KAS MUST verify it
  before evaluating the policy (NanoTDF-KAS §2).
- A decoder MUST NOT dereference a remote policy locator during parsing or validation
  (NanoTDF-LOC §3).
- An unlisted type value, a zero Content Length, or a Policy Key Access structure present
  under a type other than `0x03` MUST be rejected.

## 7. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
