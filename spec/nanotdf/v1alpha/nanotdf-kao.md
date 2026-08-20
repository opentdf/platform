# NanoTDF-KAO: Key Access and Derivation

| | |
|---|---|
| Document | NanoTDF-KAO |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-ALG, NanoTDF-PKG |
| Referenced by | NanoTDF-POL, NanoTDF-BND, NanoTDF-PAY, NanoTDF-KAS, NanoTDF-CORE |

## 1. Scope

This document defines how a NanoTDF object's symmetric key comes into existence. Unlike
formats that wrap a randomly generated content key, NanoTDF carries no wrapped key at
all: the key is *derived* on both sides from an ECDH exchange between the producer's
ephemeral key pair and the KAS key pair. The saving is the whole wrapped-key structure,
which is why the format's fixed overhead can stay under 200 bytes.

The consequence is that the header carries one public key and nothing else. There is no
key identifier, no algorithm negotiation, and no support for more than one key access
per object.

## 2. Ephemeral key agreement

At creation, the producer generates a fresh ephemeral key pair on the curve selected by
the Ephemeral ECC Params Enum (NanoTDF-PKG §3.3), and holds the KAS public key obtained
out of band.

```text
producer:  shared_secret = ECDH(ephemeral_private, kas_public)
KAS:       shared_secret = ECDH(kas_private, ephemeral_public)
```

Both parties reach the same shared secret. The producer writes only `ephemeral_public`,
as a compressed point, into the header, and discards `ephemeral_private`.

The symmetric key follows from the shared secret through HKDF, with the parameters fixed
in NanoTDF-ALG §3:

```text
symmetric_key = HKDF(
    ikm  = shared_secret,
    salt = SHA256(MAGIC_NUMBER || VERSION),
    info = "",
    len  = key length of the selected cipher)
```

For every currently registered cipher the output is 32 bytes, because all of them are
AES-256-GCM.

The derived key protects the payload (NanoTDF-PAY §3), and — unless Policy Key Access is
in use — an encrypted policy and a GMAC policy binding as well (NanoTDF-POL §4,
NanoTDF-BND §2).

### 2.1 Requirements

- The producer MUST generate the ephemeral key pair from a cryptographically secure
  random source, MUST NOT reuse it across objects, and MUST discard the private key once
  the object is written.
- A party performing ECDH MUST validate the received public key as a point on the
  declared curve before use (NanoTDF-SEC §4).
- Both parties MUST use the curve named in the header. The curve is not negotiated, and
  a receiver MUST NOT substitute another.

## 3. Offline creation

Creating an object requires only the KAS public key, so production needs no network
access. The producer cannot discover at creation time that the KAS key has rotated, and
an object produced against a retired key cannot be opened. Deployments SHOULD publish key
rotation schedules and SHOULD retain superseded KAS private keys for as long as objects
produced against them must remain readable.

## 4. Policy Key Access

By default the policy and the payload are protected by the same derived key. Policy Key
Access is an optional structure, carried inside an embedded policy body, that lets the
policy be encrypted to a *different* key than the payload.

| Field | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Resource Locator | 3 | 257 |
| Ephemeral Public Key | 33 | 67 |
| **Total** | **36** | **324** |

The Resource Locator names the remote public key to be combined with the accompanying
ephemeral public key. The ephemeral public key is a compressed point whose length follows
the same Ephemeral ECC Params Enum as the header key (NanoTDF-PKG §3.3); it is a
*second, independent* ephemeral key pair, not a copy of the header's.

The policy key is derived exactly as in §2, substituting this ephemeral key and the key
named by the locator.

Policy Key Access is present only when the policy type is `0x03` (NanoTDF-POL §2). It is
worth its size mainly when the payload is encrypted to a KAS hardware security module: it
lets a policy be evaluated by a party that cannot decrypt the payload.

### 4.1 Requirements

- The policy key derived here MUST NOT be used to encrypt the payload, and MUST NOT be
  reused for another object's policy. The encrypted-policy IV is the fixed value
  `0x000000`, so reuse of the key repeats an IV under one key (NanoTDF-SEC §2).
- A client MUST resolve the Resource Locator through trusted local configuration and MUST
  NOT dereference it during validation (NanoTDF-LOC §3).
- When Policy Key Access is present and the policy binding is a GMAC tag, the binding is
  computed under the *payload* key, not the policy key (NanoTDF-BND §2). The binding
  exists to tie the policy to the payload; computing it under the policy key would break
  that tie.

## 5. Limits

NanoTDF version 1 supports exactly one key access. There is no key splitting, no
multi-KAS access, no key identifier, and no algorithm agility beyond the curve and cipher
enumerations. An object that must be released by more than one authority is outside this
format's scope.

## 6. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms](https://www.rfc-editor.org/rfc/rfc6090)
- [NIST SP 800-56A: Key Establishment Using Discrete Logarithm Cryptography](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
