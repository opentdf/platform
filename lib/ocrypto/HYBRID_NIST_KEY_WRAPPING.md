# NIST EC + ML-KEM Hybrid Key Wrapping

## Overview

This document describes the hybrid post-quantum key wrapping scheme used in TDF (Trusted Data Format) that combines classical elliptic curve cryptography (ECDH) with post-quantum lattice-based cryptography (ML-KEM) to protect data encryption keys (split keys).

The wire format and combiner conform to [draft-ietf-lamps-pq-composite-kem-14](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/14/). The composite KEM is wrapped in standard X.509 SubjectPublicKeyInfo (SPKI) for public keys and PKCS#8 (RFC 5958 OneAsymmetricKey) for private keys, with the AlgorithmIdentifier OID selecting the scheme.

Two variants are supported. Hybrid security is bounded by the stronger of the two underlying primitives against each adversary class, so the post-quantum strength is set by ML-KEM and the classical strength is set by ECDH.

| Variant | Classical (ECDH) | Post-quantum (ML-KEM) | AlgorithmIdentifier OID |
|---------|------------------|-----------------------|-------------------------|
| P-256 + ML-KEM-768 | NIST Category 1 | NIST Category 3 | `1.3.6.1.5.5.7.6.59` (`id-MLKEM768-ECDH-P256`) |
| P-384 + ML-KEM-1024 | NIST Category 3 | NIST Category 5 | `1.3.6.1.5.5.7.6.63` (`id-MLKEM1024-ECDH-P384`) |

References:
- draft-ietf-lamps-pq-composite-kem-14 (composite KEM construction, OIDs, combiner): https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/14/
- NIST PQC Call for Proposals §4.A.5 (category definitions): https://csrc.nist.gov/csrc/media/projects/post-quantum-cryptography/documents/call-for-proposals-final-dec-2016.pdf
- FIPS 203 (ML-KEM-768 = Cat 3, ML-KEM-1024 = Cat 5): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- NIST SP 800-57 Part 1 Rev. 5 Table 2 (P-256 = 128-bit ≈ Cat 1, P-384 = 192-bit ≈ Cat 3): https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf
- RFC 5280 §4.1 (SubjectPublicKeyInfo): https://datatracker.ietf.org/doc/html/rfc5280
- RFC 5958 (PKCS#8 / OneAsymmetricKey): https://datatracker.ietf.org/doc/html/rfc5958
- RFC 5915 (ECPrivateKey DER): https://datatracker.ietf.org/doc/html/rfc5915

Core implementation: `lib/ocrypto/hybrid_nist.go`. Shared SPKI/PKCS#8 helpers and OID constants: `lib/ocrypto/pq_asn1.go`, `lib/ocrypto/pq_oids.go`.

## Key Format

### Combined Public Key

The KAS (Key Access Server) hosts a combined public key in PEM format. The PEM uses the standard `PUBLIC KEY` block type. Inside the SPKI envelope, the raw key bytes are a concatenation of the ML-KEM and EC public keys, in that order (draft-14 §3.2):

```
SubjectPublicKeyInfo {
    AlgorithmIdentifier { oid = <variant OID>, parameters ABSENT },
    BIT STRING [ mlkemPublicKey || ecPublicKey (uncompressed SEC1 point) ]
}
```

| Variant | ML-KEM Public Key Size | EC Public Key Size | Raw Concat Size |
|---------|-----------------------|-------------------|-----------------|
| P-256 + ML-KEM-768 | 1184 bytes | 65 bytes | 1249 bytes |
| P-384 + ML-KEM-1024 | 1568 bytes | 97 bytes | 1665 bytes |

The EC half is an uncompressed SEC1 point (leading `0x04` tag). The PEM block type is the standard `PUBLIC KEY` for both variants; routing is by the OID inside the AlgorithmIdentifier.

### Combined Private Key

The KAS holds a combined private key in PEM format using the standard `PRIVATE KEY` block type. Inside the PKCS#8 / OneAsymmetricKey envelope, the raw key bytes are a concatenation of the ML-KEM seed and the EC private key encoded as RFC 5915 `ECPrivateKey` DER, in that order (draft-14 §3.3):

```
OneAsymmetricKey {
    version = v1,
    AlgorithmIdentifier { oid = <variant OID>, parameters ABSENT },
    OCTET STRING [ mlkemSeed (64 bytes) || ECPrivateKey DER (RFC 5915) ]
}
```

The ML-KEM portion is stored in the 64-byte seed form (`d || z`) defined by FIPS 203 §7.1, not the expanded ~2400/3168-byte decapsulation key. The seed is what `crypto/mlkem` (Go 1.25) emits via `Bytes()` and consumes via `NewDecapsulationKey768` / `NewDecapsulationKey1024`. The constant `mlkemSeedSize = 64` in `hybrid_nist.go` enforces this layout.

The EC half is a full RFC 5915 `ECPrivateKey` DER blob (not the bare scalar), produced by `x509.MarshalECPrivateKey`. Its length varies slightly with the curve and ASN.1 lengths but is bounded; size validation lives in the parser.

| Variant | ML-KEM Seed | EC Private Key (RFC 5915 DER, approx.) |
|---------|-------------|----------------------------------------|
| P-256 + ML-KEM-768 | 64 bytes | ~121 bytes |
| P-384 + ML-KEM-1024 | 64 bytes | ~167 bytes |

### How the Client Obtains the Public Key

The client obtains the combined public key from KAS in one of two ways:

1. **Fetched at runtime (autoconfigure)**: The SDK calls the KAS `PublicKey` gRPC endpoint, specifying the hybrid algorithm. KAS returns the SPKI PEM. The response is cached for 5 minutes.
2. **Provided manually**: The caller supplies the public key PEM via `WithKasInformation(...)` when configuring the SDK.

In both cases, dispatch happens by parsing the SPKI envelope and matching the AlgorithmIdentifier OID against the known hybrid OIDs (`asym_encryption.go`). The PEM block type alone is not authoritative.

## Wrap (Encrypt the Split Key)

Function: `hybridNISTWrapDEK` (`hybrid_nist.go`).

This is performed on the **client side** during TDF encryption.

### Step 1 - Parse the Public Key

The SPKI PEM is decoded via `parseHybridSPKI`. The returned OID selects the variant; the raw bytes are split at the ML-KEM public key size boundary:

```
mlkemPubBytes = publicKeyRaw[:mlkemPubSize]      // 1184 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024
ecPubBytes    = publicKeyRaw[mlkemPubSize:]      // 65 bytes for P-256, 97 bytes for P-384
```

### Step 2 - ECDH (Classical Key Agreement)

An ephemeral EC key pair is generated on the same curve as the KAS static key:

1. Generate ephemeral EC key pair: `ephemeral_private, ephemeral_public`
2. Compute ECDH shared secret: `tradSS = ECDH(ephemeral_private, KAS_ec_public)`
3. Retain `tradCT = ephemeral_public` (uncompressed SEC1 point) for inclusion in the output and the combiner

The ephemeral key provides forward secrecy — even if the KAS static key is later compromised, past wrapped keys remain protected.

### Step 3 - ML-KEM Encapsulate (Post-Quantum KEM)

ML-KEM is a KEM, not a key exchange. Encapsulation takes only the public key and produces two outputs:

```
(mlkemSS, mlkemCT) = ML-KEM.Encapsulate(KAS_mlkem_public)
```

- `mlkemSS` (32 bytes): shared secret known to the encapsulator
- `mlkemCT` (1088 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024): opaque ciphertext that only the ML-KEM private key holder can decapsulate to recover the same shared secret

No ephemeral ML-KEM key pair is generated by the client. The ciphertext itself serves as the "ephemeral" artifact sent to KAS.

### Step 4 - Combine Secrets (draft-14 §4.3)

Per draft-14, the wrapping key is derived directly from a SHA3-256 hash that binds both shared secrets together with the traditional ciphertext, the traditional static public key, and a domain-separation Label:

```
wrapKey = SHA3-256( mlkemSS || tradSS || tradCT || tradPK || Label )
```

Where:

- `mlkemSS` is the ML-KEM-768/1024 shared secret (32 bytes)
- `tradSS` is the ECDH shared secret (32 bytes for P-256, 48 bytes for P-384)
- `tradCT` is the ephemeral EC public key sent on the wire (uncompressed SEC1 point)
- `tradPK` is the KAS static EC public key (uncompressed SEC1 point)
- `Label` is the ASCII string `"MLKEM768-P256"` or `"MLKEM1024-P384"` (per draft-14 §6)

The 32-byte SHA3-256 digest is used directly as the AES-256 wrapping key. **No HKDF, no salt, no `info` parameter.** The Label is the only domain separator; including `tradCT` and `tradPK` gives the combiner identity binding (an attacker cannot substitute either without changing the wrap key).

The Label constants live in `lib/ocrypto/pq_oids.go` (`labelMLKEM768P256`, `labelMLKEM1024P384`). The combiner is exercised by the conformance tests in `hybrid_conformance_test.go`.

### Step 5 - AES-GCM Encrypt the Split Key

The split key (the actual data encryption key shard) is encrypted using AES-256-GCM with the SHA3-256-derived `wrapKey`:

```
encryptedDEK = AES-256-GCM.Encrypt(key=wrapKey, plaintext=splitKey)
```

The output format is:

```
[ nonce (12 bytes) | ciphertext | authentication tag (16 bytes) ]
```

The nonce is randomly generated. The authentication tag provides integrity verification.

### Step 6 - Package as ASN.1 DER

The ML-KEM ciphertext, ephemeral EC public key, and encrypted DEK are packaged into an ASN.1 DER structure:

```asn1
HybridNISTWrappedKey ::= SEQUENCE {
    hybridCiphertext  [0] OCTET STRING,    -- mlkemCT || ephemeralECPub
    encryptedDEK      [1] OCTET STRING     -- AES-GCM nonce + ciphertext + tag
}
```

Where `hybridCiphertext` is laid out per draft-14 §3.4:

```
[ ML-KEM ciphertext (1088 or 1568 bytes) | ephemeral EC public key (65 or 97 bytes) ]
```

| Variant | ML-KEM Ciphertext | Ephemeral EC Pub | hybridCiphertext Size |
|---------|-------------------|------------------|----------------------|
| P-256 + ML-KEM-768 | 1088 bytes | 65 bytes | 1153 bytes |
| P-384 + ML-KEM-1024 | 1568 bytes | 97 bytes | 1665 bytes |

This DER blob is then base64-encoded and stored as the `wrappedKey` field in the TDF manifest's Key Access Object, with `keyType` set to `"hybrid-wrapped"`.

The `HybridNISTWrappedKey` envelope is a TDF-level container for the DEK wrap and is **not** specified by the IETF draft; the draft covers only the KEM (combined public key, combined private key, hybrid ciphertext, combined shared secret).

## Unwrap (Decrypt the Split Key)

Function: `hybridNISTUnwrapDEK` (`hybrid_nist.go`).

This is performed on the **KAS server side** when a client sends a rewrap request. KAS holds the combined private key on disk, loaded at startup.

### Step 1 - Parse the ASN.1 DER

The base64-decoded DER blob is unmarshalled:

```
ASN.1 Unmarshal -> HybridNISTWrappedKey {
    hybridCiphertext: [ mlkemCT | ephemeralECPub ]
    encryptedDEK:     [ nonce | ciphertext | tag ]
}
```

### Step 2 - Split the Hybrid Ciphertext

The `hybridCiphertext` is split at the known ML-KEM ciphertext size boundary:

```
mlkemCT        = hybridCiphertext[:mlkemCtSize]   // 1088 or 1568 bytes
ephemeralECPub = hybridCiphertext[mlkemCtSize:]   // 65 or 97 bytes
```

### Step 3 - Parse the Private Key

The combined private key is decoded via `parseHybridPKCS8`. The returned OID is checked against the dispatcher's expectation; the raw bytes are split at the ML-KEM seed size boundary:

```
mlkemSeed     = privateKeyRaw[:mlkemSeedSize]    // 64 bytes
ecPrivDER     = privateKeyRaw[mlkemSeedSize:]    // RFC 5915 ECPrivateKey DER
```

The ML-KEM decapsulation key is reconstructed from the seed via `mlkem.NewDecapsulationKey768` / `NewDecapsulationKey1024`. The EC private key is recovered via `x509.ParseECPrivateKey(ecPrivDER)`.

### Step 4 - ECDH (Reconstruct Classical Shared Secret)

KAS uses its static EC private key with the client's ephemeral EC public key:

```
tradSS = ECDH(KAS_ec_private, ephemeralECPub)
```

This produces the same `tradSS` that the client computed in Wrap Step 2, because `ECDH(a, g^b) == ECDH(b, g^a)`.

### Step 5 - ML-KEM Decapsulate (Reconstruct Post-Quantum Shared Secret)

KAS uses its ML-KEM private key to decapsulate the ciphertext:

```
mlkemSS = ML-KEM.Decapsulate(KAS_mlkem_private, mlkemCT)
```

Decapsulation recovers the same 32-byte shared secret the client obtained during encapsulation.

### Step 6 - Combine Secrets

Identical to Wrap Step 4:

```
wrapKey = SHA3-256( mlkemSS || tradSS || tradCT || tradPK || Label )
```

Both sides derive the same `wrapKey` because both sides have the same `mlkemSS`, `tradSS`, `tradCT` (sent on the wire), `tradPK` (KAS static public key, derived from the private key), and `Label` (constant per variant).

### Step 7 - AES-GCM Decrypt the Split Key

```
splitKey = AES-256-GCM.Decrypt(key=wrapKey, ciphertext=encryptedDEK)
```

The AES-GCM decryption verifies the authentication tag. If the tag does not match (indicating tampering or a wrong key), decryption fails.

KAS now has the original split key. It enforces policy checks, and if the requesting client is authorized, returns the split key (protected by the session transport layer).

## Security Properties

### Hybrid Security Guarantee

The `wrapKey` is derived from both ECDH and ML-KEM shared secrets. An attacker must break **both** to recover the wrap key:

- If a quantum computer breaks ECDH (recovers `tradSS` from the ephemeral public key), ML-KEM still protects `mlkemSS` under the SHA3-256 mix
- If a classical vulnerability is found in ML-KEM (recovers `mlkemSS` from the ciphertext), ECDH still protects `tradSS`

### Forward Secrecy

- The ephemeral EC key pair is generated fresh for each wrap operation, providing forward secrecy on the classical side
- ML-KEM encapsulation generates fresh randomness for each operation, providing forward secrecy on the post-quantum side

### Identity Binding in the Combiner

The draft-14 combiner mixes both ciphertexts and the traditional static public key into the SHA3-256 input, plus a fixed Label for domain separation. Concretely the combiner inputs are:

- `mlkemSS`, `tradSS` — the two shared secrets
- `tradCT` — the ephemeral EC public key sent on the wire
- `tradPK` — the KAS static EC public key
- `Label` — `"MLKEM768-P256"` or `"MLKEM1024-P384"`

This means:

- The ephemeral EC public key is bound into the wrap key — an attacker cannot substitute a different `tradCT` without changing `wrapKey`.
- The KAS static EC public key is bound in — committing the wrap key to the intended recipient.
- A constant Label provides domain separation between schemes.

The static ML-KEM public key and the ML-KEM ciphertext are **not** in the combiner input. Draft-14 §4.3 takes the position that ML-KEM's IND-CCA2 already binds the ciphertext to its shared secret, so adding the ciphertext to the combiner does not strengthen the security argument.

## Comparison with Other Key Wrapping Schemes in TDF

| Aspect | RSA (`wrapped`) | EC (`ec-wrapped`) | NIST Hybrid (`hybrid-wrapped`) | X-Wing (`hybrid-wrapped`) |
|--------|-----------------|-------------------|-------------------------------|--------------------------|
| Classical | RSA-2048 | ECDH (P-256/384/521) | ECDH (P-256/384) | X25519 |
| Post-Quantum | None | None | ML-KEM-768/1024 | ML-KEM-768 |
| Combiner | N/A | HKDF only | SHA3-256 with Label + tradCT + tradPK (draft-14 §4.3) | SHA3-256 (X-Wing spec, inside circl) |
| Output Format | Base64(RSA ciphertext) | Base64(AES-GCM ciphertext) | Base64(ASN.1 DER) | Base64(ASN.1 DER) |
| Ephemeral Key | None | EC ephemeral | EC ephemeral + ML-KEM ciphertext | X-Wing ciphertext (contains both) |
| Identity Binding | N/A | No | Yes (`tradCT`, `tradPK`, `Label` in combiner) | Yes (public keys mixed into SHA3-256) |
| Public Key PEM | `PUBLIC KEY` (SPKI, stdlib OID) | `PUBLIC KEY` (SPKI, stdlib OID) | `PUBLIC KEY` (SPKI, draft-14 OID) | `PUBLIC KEY` (SPKI, draft-10 OID) |

## Manifest Example

A Key Access Object in the TDF manifest for hybrid wrapping:

```json
{
  "type": "hybrid-wrapped",
  "url": "https://kas.example.com",
  "kid": "hybrid-key-1",
  "sid": "split-1",
  "wrappedKey": "<base64 of ASN.1 DER { hybridCiphertext, encryptedDEK }>",
  "policyBinding": {
    "alg": "HS256",
    "hash": "<HMAC-SHA256 of split_key || policy>"
  }
}
```

Note: Unlike `ec-wrapped`, the `ephemeralPublicKey` field is **not** used in the manifest for hybrid wrapping. The ephemeral EC public key is embedded inside the `wrappedKey` ASN.1 structure alongside the ML-KEM ciphertext.
