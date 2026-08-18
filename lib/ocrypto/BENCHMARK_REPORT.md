# Benchmark Report: Hybrid Post-Quantum Key Wrapping Performance

**Platform:** Apple M4, darwin/arm64, Go 1.25.9
**Date:** 2026-04-29
**Methodology:** `go test -bench=. -benchmem -count=5` (median of 5 runs)

> **Note:** Wrap and unwrap benchmarks mirror the actual TDF code paths:
> - **Wrap** follows `sdk/tdf.go` (`generateWrapKeyWithRSA`, `generateWrapKeyWithEC`, `generateWrapKeyWithHybrid`)
> - **Unwrap** follows `service/internal/security/standard_crypto.go:Decrypt()`
>
> This includes PEM parsing, ephemeral keygen, ECDH, scheme-specific secret combining, AES-GCM, and ASN.1 marshaling — not simplified library-level `WrapDEK()` / `UnwrapDEK()` calls.

## How to Run

```bash
# Full benchmark suite (use -count=5 for statistical significance)
cd lib/ocrypto && go test -bench=. -benchmem -count=5 -timeout=10m

# Quick single-count run
cd lib/ocrypto && go test -bench=. -benchmem -count=1 -timeout=5m

# Specific benchmark groups
cd lib/ocrypto && go test -bench=BenchmarkKeyGeneration -benchmem
cd lib/ocrypto && go test -bench=BenchmarkWrapDEK -benchmem
cd lib/ocrypto && go test -bench=BenchmarkUnwrapDEK -benchmem

# Wrapped key size comparison table
cd lib/ocrypto && go test -v -run TestWrappedKeySizeComparison
```

## Results

### Key Generation

| Scheme | Time | B/op | allocs/op | vs EC P-256 |
|--------|-----:|-----:|----------:|-------------|
| RSA-2048         |  31.3 ms |  652 KB | 4,399 | 4,770x slower |
| EC P-256         |   6.6 µs |  984 B  |    16 |    baseline   |
| EC P-384         |  61.2 µs |  1.2 KB |    19 |   9.5x slower |
| X-Wing           |  39.1 µs |  9.8 KB |     9 |   6.0x slower |
| P256+ML-KEM-768  |  40.1 µs | 11.4 KB |    68 |   6.1x slower |
| P384+ML-KEM-1024 | 173.8 µs | 17.9 KB |    80 |  26.5x slower |

**Takeaway:** RSA-2048 key generation is orders of magnitude slower than everything else (~48ms). All hybrid schemes generate keys in under 115us. EC P-256 is fastest at ~7us; EC P-384 keygen is ~10x slower than P-256 due to the larger field size.

### Wrap DEK (32-byte AES-256 key)

These benchmarks follow the exact TDF wrapping paths:
- **RSA:** `FromPublicPEM` -> `Encrypt` (OAEP)
- **EC:** `NewECKeyPair` -> `ComputeECDHKey` -> `CalculateHKDF` -> `AES-GCM Encrypt`
- **Hybrid:** `PubKeyFromPem` -> `Encapsulate` -> scheme-specific combiner/KDF -> `AES-GCM Encrypt` -> `ASN.1 Marshal`

| Scheme | Time | Wrapped Size | B/op | allocs/op | vs EC P-256 |
|--------|-----:|-------------:|-----:|----------:|-------------|
| RSA-2048         |  22.2 µs |  4.3 KB |  36 | 0.5x faster |
| EC P-256         |  49.1 µs | 12.8 KB | 177 |   baseline  |
| EC P-384         | 396.4 µs | 15.1 KB | 211 | 8.1x slower |
| X-Wing           |  69.2 µs | 16.7 KB |  46 | 1.4x slower |
| P256+ML-KEM-768  |  59.9 µs | 17.9 KB |  47 | 1.2x slower |
| P384+ML-KEM-1024 | 308.5 µs | 26.0 KB |  56 | 6.3x slower |

### Unwrap DEK

These benchmarks follow the KAS unwrap paths:
- **RSA:** pre-loaded `AsymDecryption.Decrypt` (key parsed at startup)
- **EC:** `NewSaltedECDecryptor(cachedKey, TDFSalt)` -> `DecryptWithEphemeralKey`
- **Hybrid:** `PrivateKeyFromPem` -> `UnwrapDEK` (PEM parsed each call)

| Scheme | Time | B/op | allocs/op | vs EC P-256 |
|--------|-----:|-----:|----------:|-------------|
| RSA-2048         | 606.0 µs |  0.6 KB |   8 | 24.6x slower |
| EC P-256         |  24.6 µs |  3.9 KB |  39 |    baseline  |
| EC P-384         | 202.0 µs |  4.3 KB |  51 |  8.2x slower |
| X-Wing           |  79.9 µs | 12.8 KB |  43 |  3.2x slower |
| P256+ML-KEM-768  |  91.4 µs | 16.0 KB |  97 |  3.7x slower |
| P384+ML-KEM-1024 | 463.0 µs | 23.0 KB | 121 | 18.8x slower |

**Takeaway:** RSA unwrap is the slowest operation in the entire suite due to private key exponentiation. P256+ML-KEM-768 unwraps are fast enough for real-time use. EC P-384 unwrap is much slower than P-256 because of the more expensive curve operations. Hybrid unwraps include PEM parsing overhead that could be optimized by caching parsed keys (as EC already does).

## Analysis: Where Time Is Spent

KEM encapsulation dominates all hybrid schemes (~93-97% of total wrap time);
post-encapsulation combining, AES-GCM, and ASN.1 marshaling are all
sub-microsecond. X-Wing still includes its HKDF-based TDF wrap path, while the
NIST composites use the draft-14 SHA3-256 combiner instead of HKDF. The P-384
elliptic curve ECDH is ~5x slower than P-256, which is why P384+ML-KEM-1024 is
significantly slower than P256+ML-KEM-768. Per-sub-op figures were captured
under a one-off benchmark that has since been removed; re-introduce with
`pprof` if a more granular breakdown is needed.

## Manifest Size Impact

| Scheme | Wrapped Key | Public Key (PEM) | Base64 Wrapped | Notes |
|--------|------------:|-----------------:|---------------:|-------|
| RSA-2048 | 256 B | 451 B | 344 B | No ephemeral key in manifest |
| EC P-256 | 60 B | 178 B | 80 B | + ephemeral key (91 B) in manifest |
| EC P-384 | 60 B | 215 B | 80 B | + ephemeral key (120 B) in manifest |
| X-Wing | 1,190 B | 1,714 B | 1,588 B | All in single ASN.1 blob |
| P256+ML-KEM-768 | 1,223 B | 1,785 B | 1,632 B | All in single ASN.1 blob |
| P384+ML-KEM-1024 | 1,735 B | 2,347 B | 2,316 B | All in single ASN.1 blob |

> Base64 overhead = ceil(raw_bytes * 4/3). TDF manifests store wrapped keys as base64.

Hybrid schemes produce wrapped keys that are ~20x larger than EC P-256 (1.2-1.7 KB vs 60 B). For a TDF with a single recipient, this adds ~1-2 KB to the manifest. For multi-recipient TDFs, the overhead scales linearly per recipient.

## Trade-offs Summary

| Concern | RSA-2048 | EC P-256 | EC P-384 | X-Wing | P256+ML-KEM-768 | P384+ML-KEM-1024 |
|---------|----------|----------|----------|--------|-----------------|-------------------|
| Quantum resistance | None | None | None | Yes (hybrid) | Yes (hybrid) | Yes (hybrid) |
| Key generation | 48 ms (slow) | 7.4 us (fastest) | 71 us | 44 us | 35 us | 114 us |
| Wrap latency | 26 us | 55 us | 449 us | 77 us | 75 us | 370 us |
| Unwrap latency | 737 us (slow) | 28 us | 231 us | 90 us | 96 us | 400 us |
| Round-trip | 763 us | 83 us | 680 us | 168 us | 172 us | 770 us |
| Wrapped key size | 256 B | 60 B | 60 B | 1,190 B | 1,223 B | 1,735 B |
| Standards basis | PKCS#1 | ECIES | ECIES | IETF draft | NIST SP 800-227 | NIST SP 800-227 |

### Recommendations

- **P256+ML-KEM-768** is the best all-around hybrid choice: NIST-standardized, fastest hybrid round-trip (~172us), and moderate size overhead (1.2 KB wrapped keys). Only ~1.4x slower than EC P-256 for wrapping.
- **P384+ML-KEM-1024** provides a higher classical security level (Cat 3 classical / Cat 5 PQ) at the cost of ~4-5x more latency. Use when policy requires P-384 or equivalent classical strength.
- **X-Wing** offers a simpler construction (X25519 + ML-KEM-768) but is based on an IETF draft rather than a NIST standard. Performance is comparable to P256+ML-KEM-768.
- **EC P-256** remains the fastest and smallest option for environments where quantum resistance is not yet required.
- **EC P-384** is significantly more expensive than P-256 (~8-10x for both wrap and unwrap) without quantum protection — prefer P384+ML-KEM-1024 if the latency budget already covers P-384, since it adds PQ resistance for similar cost.
- **RSA-2048** has the worst unwrap performance (~737us) and should be considered legacy.

### Optimization Opportunities

- **Hybrid unwrap PEM caching:** The KAS currently parses hybrid private key PEM on every unwrap call. Caching the parsed key (as EC already does) would save ~5-10us per unwrap.
