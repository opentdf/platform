# NanoTDF-BND: Policy Binding and Creator Signature

| | |
|---|---|
| Document | NanoTDF-BND |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC, NanoTDF-ALG, NanoTDF-PKG, NanoTDF-KAO, NanoTDF-POL |
| Referenced by | NanoTDF-KAS, NanoTDF-CORE, NanoTDF-EX |

## 1. Scope

NanoTDF has two cryptographic bindings, and they answer different questions.

| Mechanism | Question answered | Required |
|---|---|---|
| Policy binding | Is this policy the one the producer attached to this payload? | Always |
| Creator signature | Which persistent identity produced this object? | Optional |

The policy binding lives inside the Policy section and is verified by the KAS before it
releases a key. The creator signature is a separate trailing section and is verified by
the consumer, if at all. This document owns both.

## 2. Policy binding

### 2.1 Construction

```text
PB = the exact policy body bytes as serialized
BM = the binding method, ECDSA or GMAC
BS = BM(SHA256(PB))
```

The input is a SHA-256 digest over the policy body bytes only. The type enum and the
binding itself are excluded, as are all other header fields.

`PB` is the body as it appears on the wire. A verifier MUST use the bytes it received and
MUST NOT re-serialize the policy to recompute them (NanoTDF-POL §6).

### 2.2 Method selection and length

`USE_ECDSA_BINDING`, bit 7 of the ECC and Binding Mode byte (NanoTDF-PKG §3.3), selects
the method.

| `USE_ECDSA_BINDING` | Method | Length (B) | Key |
|---|---|---:|---|
| `0` | 64-bit GMAC tag, AES-256-GCM | 8 | Derived symmetric key |
| `1` | ECDSA signature, `r \|\| s` | 64 – 132 | Ephemeral private key |

For the ECDSA case the signature length follows the **Ephemeral ECC Params Enum** in the
ECC and Binding Mode byte — the curve of the header's ephemeral key. It does **not**
follow the Signature ECC Mode, which sizes the creator signature only. The source
specification leaves this implicit; this suite states it normatively because the two
fields can name different curves in the same object.

For the GMAC case the key is the symmetric key derived in NanoTDF-KAO §2 — the payload
key. This holds even when Policy Key Access supplies a separate policy key: the binding
exists to tie the policy to *this payload*, and computing it under the policy key would
sever that tie.

### 2.3 Verification

A KAS MUST verify the policy binding before evaluating the policy or releasing a key. A
consumer that receives a key MUST verify the binding before acting on the policy.

Verification failure MUST be reported in the same indistinguishable error class as key
derivation and authorization failure (NanoTDF-SEC §8).

### 2.4 What the binding does not do

- It does not authenticate the producer. A GMAC binding is computable by anyone holding
  the derived key, which includes the KAS. An ECDSA binding is verifiable against an
  ephemeral key that exists only for this object and is tied to no identity.
- For a remote policy it covers the locator, not the policy content (NanoTDF-LOC §4).
- It does not cover the payload ciphertext, the KAS locator, or the configuration bytes.
  Integrity of the payload comes from the AEAD tag (NanoTDF-PAY §4); integrity of the
  whole object comes only from the creator signature.

## 3. Creator signature

### 3.1 Presence and structure

The Signature section is present if and only if `HAS_SIGNATURE`, bit 7 of the Symmetric
and Payload Config byte, is set (NanoTDF-PKG §3.4).

| Field | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Creator Public Key | 33 | 67 |
| Signature (`r \|\| s`) | 64 | 132 |
| **Total** | **97** | **199** |

Both lengths follow the Signature ECC Mode, bits 6–4 of the Symmetric and Payload Config
byte, resolved through the curve registry in NanoTDF-ALG §1. The public key is a
compressed point; the signature is fixed-width big-endian `r || s`, not DER
(NanoTDF-ALG §5).

### 3.2 Coverage and key

The signature covers the Header and the Payload — every byte of the object preceding the
Signature section.

The signing key is a **persistent** key belonging to an individual, entity, or device
that produces NanoTDFs. It is distinct from the ephemeral key in the header, which exists
only for one object and carries no identity. Including the creator's public key in the
section makes the signature self-contained: a verifier needs no directory lookup to check
the mathematics.

### 3.3 Verification

A verifier MUST decode the creator public key as a point on the curve named by the
Signature ECC Mode, reject a signature whose length does not match that curve exactly,
and verify over the exact received header and payload bytes.

### 3.4 What the signature does not do

Carriage is not endorsement. A valid signature proves that the holder of the named
private key signed these bytes. It does not establish that:

- the signer is authorized to produce objects under this policy;
- the policy is correct or the attributes truthful;
- the key has not been revoked, or was valid at the time of signing — there is no
  timestamp in the object; or
- the key belongs to the identity a consumer expects. Binding the key to an identity is a
  deployment concern, handled by a certificate, a directory, or pinned trust
  configuration outside the format.

The signature is also removable: re-encoding the object with `HAS_SIGNATURE` cleared and
the section stripped yields a well-formed, openable NanoTDF. Nothing else in the object
records that a signature was ever present. An application requiring provenance MUST
reject an unsigned object rather than treating absence as acceptable (NanoTDF-SEC §5).

## 4. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [FIPS 180-4: Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
