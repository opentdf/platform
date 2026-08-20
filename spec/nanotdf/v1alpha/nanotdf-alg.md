# NanoTDF-ALG: Algorithm Registry and Encodings

| | |
|---|---|
| Document | NanoTDF-ALG |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC |
| Referenced by | NanoTDF-PKG, NanoTDF-KAO, NanoTDF-POL, NanoTDF-BND, NanoTDF-PAY, NanoTDF-CORE |

## 1. Elliptic curve registry

NanoTDF does not permit arbitrary curve parameters. The registry is closed, and the
same enumeration is used by the Ephemeral ECC Params field and the Signature ECC Mode
field (NanoTDF-PKG §3).

| Value | Curve | Compressed public key (B) | ECDSA `r \|\| s` (B) |
|---|---|---:|---:|
| `0x00` | `secp256r1` | 33 | 64 |
| `0x01` | `secp384r1` | 49 | 96 |
| `0x02` | `secp521r1` | 67 | 132 |
| `0x03` | `secp256k1` | 33 | 64 |

The key and signature lengths are derived, not carried on the wire. A parser locates the
ephemeral public key and the signature by the curve alone, so the field selecting the
curve MUST be parsed first.

Values outside this table are unreserved. A parser MUST reject an unlisted value rather
than falling back to a default. No curve below 256 bits is supported.

## 2. Symmetric cipher registry

One cipher selection governs both the payload and, when the policy is encrypted, the
policy. Every entry is AES-256-GCM; the entries differ only in authentication tag
length.

| Value | Cipher | Tag (bits) | Tag (B) |
|---|---|---:|---:|
| `0x00` | AES-256-GCM | 64 | 8 |
| `0x01` | AES-256-GCM | 96 | 12 |
| `0x02` | AES-256-GCM | 104 | 13 |
| `0x03` | AES-256-GCM | 112 | 14 |
| `0x04` | AES-256-GCM | 120 | 15 |
| `0x05` | AES-256-GCM | 128 | 16 |

This table may be extended in a future point release. Values outside it are unreserved
and MUST be rejected.

Because the key length is fixed at 256 bits across every entry, the HKDF output length
in §3 is 32 bytes for all currently registered ciphers. The short-tag hazard is discussed
in NanoTDF-SEC §3.

## 3. Key derivation

An ECDH exchange yields a shared secret whose length is a property of the curve, not of
the symmetric algorithm. NanoTDF decouples the two with HKDF.

| Parameter | Value |
|---|---|
| Function | HKDF (RFC 5869) |
| Hash | SHA-256 |
| Input keying material | The ECDH shared secret |
| Output length | The key length of the selected cipher; 32 bytes for every registered value |
| `salt` | `SHA256(MAGIC_NUMBER \|\| VERSION)` |
| `info` | Empty |

The salt is a fixed, non-random value tied to the magic number and version, so it is a
constant per format version rather than a per-object input. For format version 12, the
three magic-and-version bytes are `4c 31 4c` and the salt is:

```text
3de3ca1e50cf62d8b6aba603a96fca6761387a7ac86c3d3afe85ae2d1812edfc
```

A future format version changes the magic-and-version bytes and therefore changes the
salt, which domain-separates derived keys across versions.

## 4. Public key encoding

Elliptic curve public keys are encoded as X9.62 compressed points: a single leading byte
of `0x02` or `0x03` indicating the parity of the y-coordinate, followed by the
big-endian x-coordinate padded to the curve's field size.

Compressed encoding is used everywhere a public key appears — the header ephemeral key,
the Policy Key Access ephemeral key, and the creator signature's public key. Uncompressed
and hybrid encodings are not permitted.

A decoder MUST verify that the recovered point lies on the declared curve before using
it (NanoTDF-SEC §4).

## 5. ECDSA signature encoding

ECDSA signatures are the big-endian encodings of `r` and `s` concatenated, each padded
to the curve's field size. DER is not used, and there is no length prefix: the total
length follows from the curve.

For example, `r = 1` and `s = 2` over `secp256k1` encode as the following 64 bytes. Line
breaks and spaces are added for readability only.

```text
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02
```

A verifier MUST reject a signature whose length does not match the curve exactly.

## 6. Integer and byte-order conventions

All multi-byte integers in NanoTDF are unsigned and big-endian. `||` denotes byte
concatenation. Bit indices within a single-byte bitfield are numbered from 7, the most
significant bit, down to 0.

## 7. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms](https://www.rfc-editor.org/rfc/rfc6090)
- [RFC 6637: ECC in OpenPGP](https://www.rfc-editor.org/rfc/rfc6637)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [FIPS 197: AES](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
