# NanoTDF-PAY: Payload Carriage

| | |
|---|---|
| Document | NanoTDF-PAY |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-ALG, NanoTDF-PKG, NanoTDF-KAO |
| Referenced by | NanoTDF-CORE, NanoTDF-EX |

## 1. Scope

This document defines the Payload section: how the ciphertext is framed, which IV and
authentication tag accompany it, and when plaintext may be released. The key that
protects it is derived in NanoTDF-KAO §2 and the cipher is selected in NanoTDF-ALG §2.

## 2. Structure

| Field | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Length | 3 | 3 |
| IV | 3 | 3 |
| Ciphertext | 0 | 16,777,204 |
| Payload MAC | 8 | 32 |
| **Total** | **14** | **16,777,218** |

Length is a three-byte unsigned integer giving the combined size of the IV, ciphertext,
and MAC that follow. It does not include itself.

Because Length caps those three fields together at 16,777,215 bytes, the ciphertext
maximum above pairs with the 8-byte minimum MAC. With a 16-byte MAC the largest
ciphertext is 16,777,196 bytes. In general:

```text
ciphertext length = Length - 3 - MAC length
```

The MAC length is not on the wire. It is implied by the Symmetric Cipher Enum
(NanoTDF-ALG §2), so that byte MUST be parsed before the payload can be split into its
parts.

A zero-length ciphertext is legal. It yields a 14-byte payload section carrying an
authenticated empty plaintext.

## 3. IV

The IV is three bytes, used as the AES-GCM nonce for the payload.

- An IV MUST NOT repeat under one derived key. NanoTDF-SEC §2 explains why a three-byte
  nonce space makes this a practical rather than theoretical constraint: a producer MUST
  NOT encrypt many objects under one derived key.
- The value `0x000000` is reserved for the encrypted policy (NanoTDF-POL §4) and MUST NOT
  be used for a payload. A parser MUST reject a payload IV of `0x000000`.
- An IV SHOULD be drawn from a cryptographically secure random source. A per-key counter
  is acceptable where the producer can guarantee it cannot repeat or roll over.

Because each object derives a fresh key from a fresh ephemeral key pair, the IV space is
scoped to one object in normal use. Reusing an ephemeral key pair across objects collapses
that scoping and reintroduces the reuse hazard.

## 4. Ciphertext and MAC

The ciphertext is the AES-256-GCM encryption of the plaintext under the derived key and
the IV above. The Payload MAC is the GCM authentication tag, truncated to the length
implied by the cipher selection.

NanoTDF defines no associated data for the payload. The header is not authenticated by
the payload tag; a modification to the KAS locator or the configuration bytes is detected
only because it changes the derived key or the parse, and an object-wide integrity
guarantee exists only when a creator signature is present (NanoTDF-BND §3).

There is no segmentation, no per-segment integrity, and no Merkle layout. One payload is
one AEAD operation.

## 5. Release of plaintext

The opener MUST verify the authentication tag over the complete ciphertext before
releasing any plaintext. NanoTDF defines no incremental, prefix, or streaming release: a
payload is authenticated whole or not at all.

On authentication failure the opener MUST discard the plaintext, MUST NOT return partial
output, and MUST report failure in the same error class as key derivation and
authorization failure (NanoTDF-SEC §8).

A verifier MUST NOT accept a tag shorter than the length implied by the declared cipher,
and MUST NOT compare a prefix of a longer tag (NanoTDF-SEC §3).

## 6. Size characteristics

The payload adds a fixed 14 bytes to the plaintext at the smallest cipher setting: three
for Length, three for the IV, and eight for the MAC. Selecting a 128-bit tag raises that
to 22 bytes.

The three-byte Length field caps a single NanoTDF payload at just under 16 MiB. A larger
payload requires a different format; NanoTDF is designed for the case where the object
must stay small, and BaseTDF covers large and streamed payloads.

## 7. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [FIPS 197: AES](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
