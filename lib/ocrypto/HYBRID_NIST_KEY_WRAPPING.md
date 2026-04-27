# NIST EC + ML-KEM Hybrid Key Wrapping

## Overview

This document describes the hybrid post-quantum key wrapping scheme used in TDF (Trusted Data Format) that combines classical elliptic curve cryptography (ECDH) with post-quantum lattice-based cryptography (ML-KEM) to protect data encryption keys (split keys).

Two variants are supported. Hybrid security is bounded by the stronger of the two underlying primitives against each adversary class, so the post-quantum strength is set by ML-KEM and the classical strength is set by ECDH.

| Variant | Classical (ECDH) | Post-quantum (ML-KEM) |
|---------|------------------|-----------------------|
| P-256 + ML-KEM-768 | NIST Category 1 | NIST Category 3 |
| P-384 + ML-KEM-1024 | NIST Category 3 | NIST Category 5 |

References:
- NIST PQC Call for Proposals §4.A.5 (category definitions): https://csrc.nist.gov/csrc/media/projects/post-quantum-cryptography/documents/call-for-proposals-final-dec-2016.pdf
- FIPS 203 (ML-KEM-768 = Cat 3, ML-KEM-1024 = Cat 5): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- NIST SP 800-57 Part 1 Rev. 5 Table 2 (P-256 = 128-bit ≈ Cat 1, P-384 = 192-bit ≈ Cat 3): https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf

Core implementation: `lib/ocrypto/hybrid_nist.go`

## Key Format

### Combined Public Key

The KAS (Key Access Server) hosts a combined public key in PEM format. The raw bytes inside the PEM are a simple concatenation of the EC and ML-KEM public keys:

```
[ EC Public Key (uncompressed point) | ML-KEM Public Key ]
```

| Variant | EC Public Key Size | ML-KEM Public Key Size | Combined Size | PEM Block Type |
|---------|-------------------|----------------------|---------------|----------------|
| P-256 + ML-KEM-768 | 65 bytes | 1184 bytes | 1249 bytes | `SECP256R1 MLKEM768 PUBLIC KEY` |
| P-384 + ML-KEM-1024 | 97 bytes | 1568 bytes | 1665 bytes | `SECP384R1 MLKEM1024 PUBLIC KEY` |

### Combined Private Key

The KAS holds a combined private key, also a concatenation:

```
[ EC Private Key (raw scalar) | ML-KEM Private Key ]
```

The ML-KEM portion is stored in the 64-byte seed form (`d || z`) defined by FIPS 203 §7.1, not the expanded ~2400/3168-byte decapsulation key. The seed is what `crypto/mlkem` (Go 1.25) emits via `Bytes()` and consumes via `NewDecapsulationKey768` / `NewDecapsulationKey1024`. The constant `mlkemSeedSize = 64` in `hybrid_nist.go` and the size checks in `decodeSizedPEMBlock` enforce this layout.

| Variant | EC Private Key Size | ML-KEM Seed Size | Combined Size | PEM Block Type |
|---------|--------------------|------------------|---------------|----------------|
| P-256 + ML-KEM-768 | 32 bytes | 64 bytes | 96 bytes | `SECP256R1 MLKEM768 PRIVATE KEY` |
| P-384 + ML-KEM-1024 | 48 bytes | 64 bytes | 112 bytes | `SECP384R1 MLKEM1024 PRIVATE KEY` |

### How the Client Obtains the Public Key

The client obtains the combined public key from KAS in one of two ways:

1. **Fetched at runtime (autoconfigure)**: The SDK calls the KAS `PublicKey` gRPC endpoint, specifying the hybrid algorithm. KAS returns the combined PEM. The response is cached for 5 minutes.
2. **Provided manually**: The caller supplies the public key PEM via `WithKasInformation(...)` when configuring the SDK.

## Wrap (Encrypt the Split Key)

Function: `hybridNISTWrapDEK` (`hybrid_nist.go`, line 339)

This is performed on the **client side** during TDF encryption.

### Step 1 - Split the Public Key

The combined public key bytes are split at the known EC public key size boundary:

```
ecPubBytes    = publicKeyRaw[:ecPubSize]      // 65 bytes for P-256, 97 bytes for P-384
mlkemPubBytes = publicKeyRaw[ecPubSize:]      // 1184 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024
```

### Step 2 - ECDH (Classical Key Agreement)

An ephemeral EC key pair is generated on the same curve as the KAS static key:

1. Generate ephemeral EC key pair: `ephemeral_private, ephemeral_public`
2. Compute ECDH shared secret: `ecdhSecret = ECDH(ephemeral_private, KAS_ec_public)`
3. Retain `ephemeral_public` bytes for inclusion in the output

This is a standard elliptic curve Diffie-Hellman operation. The ephemeral key provides forward secrecy - even if the KAS static key is later compromised, past wrapped keys remain protected.

### Step 3 - ML-KEM Encapsulate (Post-Quantum KEM)

ML-KEM (Module Lattice-based Key Encapsulation Mechanism, formerly known as Kyber) is a KEM, not a key exchange. The encapsulation operation takes only the public key and produces two outputs:

```
(mlkemSecret, mlkemCiphertext) = ML-KEM.Encapsulate(KAS_mlkem_public)
```

- `mlkemSecret` (32 bytes): A shared secret known to the encapsulator
- `mlkemCiphertext` (1088 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024): An opaque ciphertext that only the ML-KEM private key holder can decapsulate to recover the same shared secret

Internally, `EncapsulateTo`:
1. Generates random coins (entropy)
2. Uses the ML-KEM public key (a matrix over a polynomial ring) to encrypt those random coins into the ciphertext
3. Derives the shared secret from both the random coins and the ciphertext

No ephemeral ML-KEM key pair is generated by the client. The ciphertext itself serves as the "ephemeral" artifact sent to KAS.

### Step 4 - Combine Secrets

The two shared secrets from the classical and post-quantum operations are concatenated:

```
combinedSecret = ecdhSecret || mlkemSecret
```

This is a simple byte concatenation. The security property is that an attacker must break **both** ECDH and ML-KEM to recover the combined secret. If quantum computers break ECDH but ML-KEM remains secure, the combined secret is still protected (and vice versa).

### Step 5 - Key Derivation (HKDF)

A 32-byte AES-256 wrapping key is derived from the combined secret using HKDF-SHA256:

```
wrapKey = HKDF-SHA256(
    IKM:  combinedSecret,          // ecdhSecret || mlkemSecret
    salt: SHA256("TDF"),           // 32-byte fixed salt
    info: <optional>               // empty by default
) -> 32 bytes
```

Function: `deriveHybridNISTWrapKey` (`hybrid_nist.go`, line 479)

The salt is a hardcoded SHA-256 digest of the ASCII string `"TDF"`, shared across all TDF key wrapping schemes.

### Step 6 - AES-GCM Encrypt the Split Key

The split key (the actual data encryption key shard) is encrypted using AES-256-GCM:

```
encryptedDEK = AES-256-GCM.Encrypt(key=wrapKey, plaintext=splitKey)
```

The output format is:

```
[ nonce (12 bytes) | ciphertext | authentication tag (16 bytes) ]
```

The nonce is randomly generated. The authentication tag provides integrity verification.

### Step 7 - Package as ASN.1 DER

The ephemeral EC public key, ML-KEM ciphertext, and encrypted DEK are packaged into an ASN.1 DER structure:

```asn1
HybridNISTWrappedKey ::= SEQUENCE {
    hybridCiphertext  [0] OCTET STRING,    -- ephemeralECPub || mlkemCiphertext
    encryptedDEK      [1] OCTET STRING     -- AES-GCM nonce + ciphertext + tag
}
```

Where `hybridCiphertext` is:

```
[ ephemeral EC public key (65 or 97 bytes) | ML-KEM ciphertext (1088 or 1568 bytes) ]
```

| Variant | Ephemeral EC Pub | ML-KEM Ciphertext | hybridCiphertext Size |
|---------|-----------------|-------------------|----------------------|
| P-256 + ML-KEM-768 | 65 bytes | 1088 bytes | 1153 bytes |
| P-384 + ML-KEM-1024 | 97 bytes | 1568 bytes | 1665 bytes |

This DER blob is then base64-encoded and stored as the `wrappedKey` field in the TDF manifest's Key Access Object, with `keyType` set to `"hybrid-wrapped"`.

## Unwrap (Decrypt the Split Key)

Function: `hybridNISTUnwrapDEK` (`hybrid_nist.go`, line 406)

This is performed on the **KAS server side** when a client sends a rewrap request. KAS holds the combined private key on disk, loaded at startup.

### Step 1 - Parse the ASN.1 DER

The base64-decoded DER blob is unmarshalled:

```
ASN.1 Unmarshal -> HybridNISTWrappedKey {
    hybridCiphertext: [ephemeralECPub | mlkemCiphertext]
    encryptedDEK:     [nonce | ciphertext | tag]
}
```

### Step 2 - Split the Hybrid Ciphertext

The `hybridCiphertext` is split at the known EC public key size boundary:

```
ephemeralECPub = hybridCiphertext[:ecPubSize]       // 65 or 97 bytes
mlkemCiphertext = hybridCiphertext[ecPubSize:]      // 1088 or 1568 bytes
```

### Step 3 - Split the Private Key

The combined private key is split at the known EC private key size boundary:

```
ecPrivBytes    = privateKeyRaw[:ecPrivSize]          // 32 or 48 bytes
mlkemPrivBytes = privateKeyRaw[ecPrivSize:]          // 2400 or 3168 bytes
```

### Step 4 - ECDH (Reconstruct Classical Shared Secret)

KAS uses its static EC private key with the client's ephemeral EC public key:

```
ecdhSecret = ECDH(KAS_ec_private, ephemeral_ec_public)
```

This produces the same `ecdhSecret` that the client computed in Wrap Step 2, because `ECDH(a, g^b) == ECDH(b, g^a)`.

### Step 5 - ML-KEM Decapsulate (Reconstruct Post-Quantum Shared Secret)

KAS uses its ML-KEM private key to decapsulate the ciphertext:

```
mlkemSecret = ML-KEM.Decapsulate(KAS_mlkem_private, mlkemCiphertext)
```

The ML-KEM private key contains the secret trapdoor in the lattice structure. Decapsulation recovers the random coins from the ciphertext and derives the same 32-byte shared secret that the client obtained during encapsulation.

### Step 6 - Combine Secrets

Identical to Wrap Step 4:

```
combinedSecret = ecdhSecret || mlkemSecret
```

### Step 7 - Key Derivation (HKDF)

Identical to Wrap Step 5:

```
wrapKey = HKDF-SHA256(
    IKM:  combinedSecret,
    salt: SHA256("TDF"),
    info: <optional>
) -> 32 bytes
```

Both sides derive the same `wrapKey` because both sides have the same `ecdhSecret` and `mlkemSecret`.

### Step 8 - AES-GCM Decrypt the Split Key

```
splitKey = AES-256-GCM.Decrypt(key=wrapKey, ciphertext=encryptedDEK)
```

The AES-GCM decryption verifies the authentication tag. If the tag does not match (indicating tampering or a wrong key), decryption fails.

KAS now has the original split key. It enforces policy checks, and if the requesting client is authorized, returns the split key (protected by the session transport layer).

## Security Properties

### Hybrid Security Guarantee

The combined secret is derived from both ECDH and ML-KEM. An attacker must break **both** to recover the wrap key:

- If a quantum computer breaks ECDH (recovers `ecdhSecret` from the ephemeral public key), ML-KEM still protects the combined secret
- If a classical vulnerability is found in ML-KEM (recovers `mlkemSecret` from the ciphertext), ECDH still protects the combined secret

### Forward Secrecy

- The ephemeral EC key pair is generated fresh for each wrap operation, providing forward secrecy on the classical side
- ML-KEM encapsulation generates fresh randomness for each operation, providing forward secrecy on the post-quantum side

### What is NOT in the Combiner

Unlike the X-Wing KEM (which uses SHA3-256 and mixes in public keys, ciphertexts, and a domain label), this NIST hybrid implementation:

- Does **not** mix the ephemeral EC public key into the KDF
- Does **not** mix the ML-KEM ciphertext into the KDF
- Does **not** mix the static public keys into the KDF
- Does **not** use a domain separation label in the HKDF info

The two raw shared secrets are simply concatenated and passed through HKDF. This is a common and accepted pattern for hybrid KEM composition, though it provides less identity binding than the X-Wing combiner approach.

## Comparison with Other Key Wrapping Schemes in TDF

| Aspect | RSA (`wrapped`) | EC (`ec-wrapped`) | NIST Hybrid (`hybrid-wrapped`) | X-Wing (`hybrid-wrapped`) |
|--------|-----------------|-------------------|-------------------------------|--------------------------|
| Classical | RSA-2048 | ECDH (P-256/384/521) | ECDH (P-256/384) | X25519 |
| Post-Quantum | None | None | ML-KEM-768/1024 | ML-KEM-768 |
| Combiner | N/A | HKDF only | Concatenation + HKDF | SHA3-256 (spec-defined, inside circl library) + HKDF |
| Output Format | Base64(RSA ciphertext) | Base64(AES-GCM ciphertext) | Base64(ASN.1 DER) | Base64(ASN.1 DER) |
| Ephemeral Key | None | EC ephemeral | EC ephemeral + ML-KEM ciphertext | X-Wing ciphertext (contains both) |
| Identity Binding | N/A | No | No | Yes (public keys mixed into SHA3-256) |

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
