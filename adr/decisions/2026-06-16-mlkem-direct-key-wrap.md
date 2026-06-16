---
status: proposed
date: 2026-06-16
tags:
 - cryptography
 - mlkem
 - kas
 - hsm
 - fips
---
# ML-KEM-wrapped KAOs use the Decaps shared secret directly as the AES-GCM wrap key (no HKDF)

## Context and Problem Statement

PR [opentdf/platform#3537](https://github.com/opentdf/platform/pull/3537) introduces a pure ML-KEM-768 / ML-KEM-1024 wrapping scheme for KAOs (key-access objects) — wire type `mlkem-wrapped`. The first draft of that PR derived the AES-256-GCM wrap key from the ML-KEM Decaps output via HKDF-SHA256 over a fixed `"TDF"` salt, mirroring the existing hybrid PQ/T (`hybrid-wrapped`) path.

The intended downstream consumer is an HSM-backed KAS provider: specifically Thales Luna T-Series with firmware 7.15.1 in strict-FIPS mode. On that HSM, `CKM_ML_KEM_KEY_DECAP` can only materialize its 32-byte shared secret as a sensitive, non-extractable AES key object (`CKK_AES`). The HSM refuses to emit the Decaps result as `CKK_GENERIC_SECRET`, returning `CKR_ATTRIBUTE_TYPE_INVALID`, which means we cannot:

* run `CKM_SHA256_HMAC` over the shared secret (so no HKDF-on-HSM), nor
* extract the shared secret to run HKDF off-HSM (`CKA_EXTRACTABLE=false`).

Any KDF in the unwrap chain therefore blocks HSM-backed KAS providers on this firmware.

## Decision Drivers

* Must support HSM-backed KAS providers (Thales Luna T-Series 7.15.1 in strict-FIPS mode) without an HSM firmware change, vendor RFE, or unsafe key extraction.
* Must remain FIPS-compliant.
* Must not change the on-wire envelope format (the wire format is the same ASN.1 DER `MLKEMWrappedKey { MLKEMCiphertext, EncryptedDEK }` — only the internal key-derivation step is removed).
* Must not regress security relative to the HKDF-using draft.
* Must not bleed into the hybrid PQ/T (`hybrid-wrapped`) wrap path, where HKDF is load-bearing as the combiner for the two shared-secret halves.

## Considered Options

1. Use the ML-KEM Decaps output directly as the AES-256-GCM wrap key for `mlkem-wrapped`.
2. Keep HKDF-SHA256 over `(sharedSecret, salt, info)` and require vendor firmware support for `CKM_GENERIC_SECRET_KEY_GEN` from Decaps.
3. Keep HKDF and require KAS operators to mark the ML-KEM private key as software-only (no HSM) when used with this wire format.

## Decision Outcome

Chosen option: **(1) Use the ML-KEM Decaps shared secret directly as the AES-256-GCM wrap key.**

The 32-byte Decaps output is fed straight into AES-256-GCM with a fresh random nonce; the AES-GCM ciphertext + tag are stored as `EncryptedDEK` inside the existing ASN.1 envelope. The `salt` / `info` parameters that flow into the unified `kemEncryptor` / `kemDecryptor` are ignored by the ML-KEM adapter (they remain meaningful for the X-Wing and NIST EC + ML-KEM hybrid adapters, which still derive their AES key via HKDF as the combiner).

### Wire format

Unchanged. The envelope is still:

```asn1
MLKEMWrappedKey ::= SEQUENCE {
    mlkemCiphertext  [0] IMPLICIT OCTET STRING,
    encryptedDEK     [1] IMPLICIT OCTET STRING
}
```

`encryptedDEK` is now `AES-256-GCM(K = mlkemSharedSecret, nonce = random12B, AAD = none, plaintext = DEK)` with the standard 12-byte nonce prefix + 16-byte tag layout produced by `ocrypto.AesGcm.Encrypt`. No HKDF; no `salt`; no `info`.

### FIPS 203 justification

FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard) specifies the Decaps output `K` as a uniformly random 32-byte shared secret produced by hashing through the spec's internal G/H/J SHA-3 family functions:

* §7.3 *ML-KEM.Decaps*: "Output: shared secret key K ∈ B^{32}".
* §6.3 *ML-KEM.Decaps* (the variant exposing the implicit-rejection branch) likewise emits a 32-byte K, including in the failure path where K is derived pseudorandomly from `(z, c)` using J — preserving indistinguishability from a real success.

Because K is already a 32-byte uniformly random string by construction, an additional HKDF expansion would not increase its entropy or change its distribution — at best, HKDF would re-mix uniformly-random input bits into a different uniformly-random 32-byte output. It is not load-bearing.

ML-KEM also produces a fresh K per encapsulation by construction (encapsulation samples fresh randomness `m` and packs it through K-PKE encrypt, so every wrap operation produces an independent K). The per-call key-isolation property HKDF is conventionally used to provide is therefore already present in the input.

### Cryptographic argument

The properties we need for a DEK-wrap key are:

1. **Uniform 32-byte distribution.** ML-KEM `Decaps` outputs a 32-byte K drawn from the SHA-3 family applied to fresh per-encapsulation randomness; FIPS 203 specifies this directly.
2. **Per-wrap independence.** Encapsulation samples a fresh 32-byte `m` per call, so K is independent across wraps by construction; no domain separation tag is required to keep wraps from colliding.
3. **Authenticated wrap.** AES-256-GCM provides confidentiality and integrity for the wrapped DEK; a wrong-key unwrap fails at the GCM tag-check stage. FIPS 203 §6.3's implicit-rejection design means a wrong-key Decaps still returns a 32-byte K, but that K is pseudorandom and uncorrelated with the encryptor's K, so the AES-GCM tag verification fails.

Skipping HKDF therefore neither lowers the wrap key's entropy nor weakens the unwrap-failure behaviour observed by the caller. The only thing HKDF would have added is a fixed-string domain-separation tag (`info`); since the `mlkem-wrapped` wire type is itself a domain-separation tag, there is no cross-protocol collision risk to defend against.

### Code shape

* `lib/ocrypto/kem.go`: the `kem` interface gains a `wrapKey(sharedSecret, salt, info []byte) ([]byte, error)` method. `mlkemKEM.wrapKey` returns the shared secret verbatim; `xwingKEM.wrapKey` and `nistHybridKEM.wrapKey` both delegate to the existing `hkdfWrapKey` (renamed from `deriveKEMWrapKey`). The `wrapDEKWithKEM` / `unwrapDEKWithKEM` helpers ask the adapter for the key.
* `lib/ocrypto/mlkem.go`: the `MLKEM{768,1024}{Wrap,Unwrap}DEK` entry points pass `nil, nil` for salt/info so the ignore-semantics are obvious at the call site.
* `lib/ocrypto/hybrid_common.go`: `defaultTDFSalt()` is retained — it is still the default HKDF salt for the X-Wing and NIST hybrid adapters and for ECIES (`FromPublicPEMWithSalt`).

### Consequences

* **Good**, because HSM-backed KAS providers (Thales Luna T-Series 7.15.1 in strict-FIPS mode) can now perform `mlkem-wrapped` unwrap end-to-end without ever extracting the Decaps shared secret. The 32-byte K stays on-HSM as a `CKK_AES`, sensitive, non-extractable object and is used directly by `CKM_AES_GCM`.
* **Good**, because the wire format does not change: the ASN.1 envelope is byte-identical, and only the internal key derivation is removed.
* **Good**, because the unified `kem` interface keeps the wrap/unwrap path single-source; the per-scheme key-derivation policy is the only thing that diverges, and it is captured in one method on the adapter.
* **Neutral**, because the `salt` and `info` parameters threaded through the unified encryptor / decryptor constructors still exist (they are needed for X-Wing and NIST hybrid). They are silently ignored for ML-KEM. The `TestMLKEMSaltInfoIgnored` test pins this behaviour so it cannot regress.
* **Bad**, because any wire-format artifact produced by the HKDF-using draft of PR #3537 is no longer decryptable. This is acceptable: PR #3537 is not merged and the HKDF-using artifacts existed only in the PR branch and its test fixtures.

### Migration

* PR #3537 is not merged. Any `mlkem-wrapped` envelopes that were produced by intermediate versions of that branch are no longer decryptable after this change.
* The hybrid PQ/T (`hybrid-wrapped`) wrap path is **unchanged**. Both X-Wing and NIST EC + ML-KEM continue to use HKDF-SHA256 over the combined `(EC || ML-KEM)` shared secret, because the KDF is the combiner and is load-bearing for those schemes.

### Out of scope

* Maintaining an HKDF-using variant of `mlkem-wrapped` for non-HSM consumers. There is no consumer that requires HKDF — software KAS implementations can use the Decaps output directly with no measurable difference in behaviour or security, and the KDF only adds compute cost on the unwrap path. A second wire variant would split the ecosystem with no upside.
* Generalising direct-shared-secret wrapping to the hybrid PQ/T schemes. For X-Wing and NIST EC + ML-KEM the AES wrap key must be derived from `(ecdhSecret || mlkemSecret)` via a KDF, because (a) the combined input is 64+ bytes (not 32), and (b) HKDF is the combiner that turns the two halves into a single uniformly-random key. Removing HKDF there would reduce security, not just compute.

## Validation

* `TestMLKEMSharedSecretIsAESWrapKey` (lib/ocrypto/mlkem_test.go) extracts the AES-GCM ciphertext from an `mlkem-wrapped` envelope and opens it using `AES-256-GCM(K = sharedSecret)` directly, asserting the recovered plaintext matches the original DEK. This pins the no-KDF contract from both directions (encrypt-side and decrypt-side).
* `TestMLKEMSaltInfoIgnored` (lib/ocrypto/mlkem_test.go) wraps with one `(salt, info)` pair and unwraps with a different pair (and again with `nil, nil`); both must succeed, proving salt/info are no-ops for ML-KEM.
* The existing `TestMLKEM{768,1024}WrapUnwrapRoundTrip`, `TestMLKEM{768,1024}WrapUnwrapWrongKeyFails`, and `TestMLKEM{768,1024}WrapDEKFormats` tests continue to pass.

## More Information

* FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
* OpenTDF platform PR #3537 (ML-KEM-768 / ML-KEM-1024 post-quantum encryption support): https://github.com/opentdf/platform/pull/3537
* Related: `lib/ocrypto/HYBRID_NIST_KEY_WRAPPING.md` (hybrid PQ/T variant, which retains HKDF as the combiner).
