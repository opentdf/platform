# NanoTDF-PKG: Binary Packaging Profile

| | |
|---|---|
| Document | NanoTDF-PKG |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-ALG, NanoTDF-LOC |
| Referenced by | NanoTDF-KAO, NanoTDF-POL, NanoTDF-BND, NanoTDF-PAY, NanoTDF-CORE, NanoTDF-EX |

## 1. Scope

This document defines the physical serialization of one NanoTDF object. It owns the
magic number, the version field, section ordering, the two bitfield configuration bytes,
length fields, and outer parsing rules. The logical meaning of each section is defined by
the component documents: NanoTDF-POL for the policy, NanoTDF-BND for the binding and
signature, NanoTDF-KAO for the ephemeral key, and NanoTDF-PAY for the payload.

All integers are unsigned and big-endian. Bit indices run from 7, the most significant
bit, down to 0.

Several field lengths are not on the wire. The ephemeral public key, the signature, and
an ECDSA policy binding are all sized by a curve selected in a configuration byte, so
those bytes MUST be parsed before the fields they govern can be located.

## 2. Object structure

A NanoTDF is three sections. The Signature is present if and only if `HAS_SIGNATURE` is
set in the Symmetric and Payload Config byte.

| Section | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Header | 53 | 1,043 |
| Payload | 14 | 16,777,218 |
| Signature (optional) | 97 | 199 |
| **Object** | **67** | **16,778,460** |

```text
+-------------------------------------------------------+
| Header                                                |
|   +-----------------------------------------------+   |
|   | Magic Number + Version           3 bytes      |   |
|   | KAS Resource Locator             3 - 257      |   |
|   | ECC and Binding Mode             1            |   |
|   | Symmetric and Payload Config     1            |   |
|   | Policy                           12 - 714     |   |
|   | Ephemeral Public Key             33 - 67      |   |
|   +-----------------------------------------------+   |
+-------------------------------------------------------+
| Payload                                               |
|   +-----------------------------------------------+   |
|   | Length                           3 bytes      |   |
|   | IV                               3            |   |
|   | Ciphertext                       0 - 16777204 |   |
|   | Payload MAC                      8 - 32       |   |
|   +-----------------------------------------------+   |
+-------------------------------------------------------+
| Signature      present iff HAS_SIGNATURE              |
|   +-----------------------------------------------+   |
|   | Creator Public Key               33 - 67      |   |
|   | Signature (r || s)               64 - 132     |   |
|   +-----------------------------------------------+   |
+-------------------------------------------------------+
```

The maxima above assume the largest legal value of every field independently. Some
combinations cannot co-occur: the 16,777,204-byte ciphertext maximum pairs with the
8-byte minimum MAC, because the three-byte Length field caps IV, ciphertext, and MAC
together at 16,777,215 bytes.

The Header is the unit transmitted to a KAS. It is self-delimiting: nothing in the
Payload or Signature is required to parse it.

## 3. Header

### 3.1 Magic Number and Version

Three bytes carry an 18-bit magic number followed by a 6-bit version. The `x` bits below
are the version:

```text
0100 1100 0011 0001 01xx xxxx
```

The version count starts at 12. Every version below 12 is invalid by construction, and a
parser MUST reject one. Version 12 is the first and, at the time of writing, only defined
version; this suite refers to it as format version 12.

Format version 12 serializes as `4c 31 4c`, which is ASCII `L1L` and base64 `TDFM`. Those
three bytes are also the input to the HKDF salt in NanoTDF-ALG §3, so a version change
domain-separates every derived key.

A parser MUST reject an object whose first three bytes do not match a supported magic
number and version.

### 3.2 KAS Resource Locator

A Resource Locator naming the Key Access Service for this object, encoded per
NanoTDF-LOC §1. Its semantics are defined in NanoTDF-KAS §1.

### 3.3 ECC and Binding Mode

One byte selecting the ephemeral curve and the policy binding strategy.

```text
 bit   7   6   5   4   3   2   1   0
     +---+---+---+---+---+---+---+---+
     | E |     UNUSED    |   CURVE   |
     +---+---+---+---+---+---+---+---+
       |         |             |
       |         |             +-- Ephemeral ECC Params Enum (3 bits, 2..0)
       |         +-- reserved (4 bits, 6..3)
       +-- USE_ECDSA_BINDING (1 bit, 7)
```

| Field | Bits | Width |
|---|---|---:|
| `USE_ECDSA_BINDING` | 7 | 1 |
| Reserved | 6–3 | 4 |
| Ephemeral ECC Params Enum | 2–0 | 3 |

`USE_ECDSA_BINDING` selects the policy binding method: `0` for a 64-bit GMAC tag, `1` for
an ECDSA signature. See NanoTDF-BND §2.

The Ephemeral ECC Params Enum selects the curve from the registry in NanoTDF-ALG §1. It
governs the length of the ephemeral public key in §3.5, the length of the Policy Key
Access ephemeral key, and — when `USE_ECDSA_BINDING` is set — the length of the policy
binding.

The reserved bits MUST be zero when written. A parser SHOULD reject a non-zero reserved
field rather than ignoring it, so that a later version can assign meaning to those bits
without ambiguity.

### 3.4 Symmetric and Payload Config

One byte selecting the symmetric cipher and describing the optional signature. The
selected cipher applies to both the payload and, where the policy is encrypted, the
policy.

```text
 bit   7   6   5   4   3   2   1   0
     +---+---+---+---+---+---+---+---+
     | S | SIG CURVE |    CIPHER     |
     +---+---+---+---+---+---+---+---+
       |       |             |
       |       |             +-- Symmetric Cipher Enum (4 bits, 3..0)
       |       +-- Signature ECC Mode (3 bits, 6..4)
       +-- HAS_SIGNATURE (1 bit, 7)
```

| Field | Bits | Width |
|---|---|---:|
| `HAS_SIGNATURE` | 7 | 1 |
| Signature ECC Mode | 6–4 | 3 |
| Symmetric Cipher Enum | 3–0 | 4 |

`HAS_SIGNATURE` is `1` when a Signature section follows the payload and `0` otherwise.

The Signature ECC Mode selects the curve of the creator signature from the registry in
NanoTDF-ALG §1, and therefore the length of the Signature section. It has no meaning when
`HAS_SIGNATURE` is `0`, and a parser MUST NOT reject an object because an unused
Signature ECC Mode names a curve it would not otherwise accept.

The Signature ECC Mode is independent of the Ephemeral ECC Params Enum. In particular, it
does **not** size an ECDSA policy binding; that follows the ephemeral curve
(NanoTDF-BND §2).

The Symmetric Cipher Enum selects the cipher and tag length from the registry in
NanoTDF-ALG §2, and therefore the length of the Payload MAC.

### 3.5 Policy

The Policy object, encoded per NanoTDF-POL §2. Its length depends on the policy type, the
body, and the binding method selected in §3.3.

### 3.6 Ephemeral Public Key

The producer's ephemeral public key as an X9.62 compressed point, 33 to 67 bytes
according to the curve selected in §3.3. Its use is defined in NanoTDF-KAO §2.

## 4. Parsing

A decoder MUST reject an object when:

- the magic number is unrecognized, or the version is unsupported or below 12;
- a Resource Locator declares a body length of zero, or one exceeding remaining input;
- a declared section exceeds the remaining input;
- offset or capacity arithmetic overflows;
- the payload Length field does not accommodate the IV, the MAC implied by the cipher,
  and a non-negative ciphertext length;
- the payload IV is `0x000000`, which is reserved for the encrypted policy
  (NanoTDF-SEC §2); or
- bytes remain after the payload when `HAS_SIGNATURE` is `0`, or after the signature
  when it is `1`.

Parser limits from NanoTDF-SEC §1 apply before allocation, key derivation, or KAS
contact.

The exact policy body bytes are a cryptographic input to the binding. A decoder MUST
retain them as received and MUST NOT re-serialize them (NanoTDF-BND §2).

## 5. Versioning and conformance

Changing section ordering, a length encoding, a bitfield layout, the meaning of an
existing security-bearing field, or a cryptographic input construction requires a new
format version, and therefore new magic-and-version bytes and a new HKDF salt.

Adding a value to the curve or cipher registry does not require a new format version,
because both are read from an enumerated field whose unlisted values are already rejected.

NanoTDF-CORE §5 defines suite-wide conformance coverage.

## 6. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 4648: Base16 and Base64 Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
