# Benchmark Report: Hybrid Post-Quantum Key Wrapping Performance

**Platform:** Apple M4, darwin/arm64, Go 1.25.8
**Date:** 2026-04-15
**Methodology:** `go test -bench=. -benchmem -count=3` (median of 3 runs)

> **Note:** Wrap and unwrap benchmarks mirror the actual TDF code paths:
> - **Wrap** follows `sdk/tdf.go` (`generateWrapKeyWithRSA`, `generateWrapKeyWithEC`, `generateWrapKeyWithHybrid`)
> - **Unwrap** follows `service/internal/security/standard_crypto.go:Decrypt()`
>
> This includes PEM parsing, ephemeral keygen, ECDH, HKDF, AES-GCM, and ASN.1 marshaling — not simplified library-level `WrapDEK()` / `UnwrapDEK()` calls.

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
cd lib/ocrypto && go test -bench=BenchmarkHybridSubOps -benchmem

# Wrapped key size comparison table
cd lib/ocrypto && go test -v -run TestWrappedKeySizeComparison
```

## Results

### Key Generation

| Scheme | Time | B/op | allocs/op | vs EC P-256 |
|--------|-----:|-----:|----------:|-------------|
| RSA-2048 | 48.2 ms | 671 KB | 6,101 | ~6,500x slower |
| EC P-256 | 7.4 us | 984 B | 16 | baseline |
| X-Wing | 44.1 us | 9.8 KB | 9 | ~6x slower |
| P256+ML-KEM-768 | 35.3 us | 16.6 KB | 16 | ~5x slower |
| P384+ML-KEM-1024 | 114.8 us | 23.9 KB | 19 | ~15x slower |

**Takeaway:** RSA-2048 key generation is orders of magnitude slower than everything else (~48ms). All hybrid schemes generate keys in under 115us. EC P-256 is fastest at ~7.4us.

### Wrap DEK (32-byte AES-256 key)

These benchmarks follow the exact TDF wrapping paths:
- **RSA:** `FromPublicPEM` -> `Encrypt` (OAEP)
- **EC:** `NewECKeyPair` -> `ComputeECDHKey` -> `CalculateHKDF` -> `AES-GCM Encrypt`
- **Hybrid:** `PubKeyFromPem` -> `Encapsulate` -> `CalculateHKDF` -> `AES-GCM Encrypt` -> `ASN.1 Marshal`

| Scheme | Time | Wrapped Size | B/op | allocs/op | vs EC P-256 |
|--------|-----:|-------------:|-----:|----------:|-------------|
| RSA-2048 | 25.6 us | 256 B | 4.1 KB | 33 | 0.5x (faster) |
| EC P-256 | 55.0 us | 60 B | 12.0 KB | 158 | baseline |
| X-Wing | 77.1 us | 1,190 B | 16.4 KB | 42 | ~1.4x slower |
| P256+ML-KEM-768 | 67.6 us | 1,223 B | 18.7 KB | 58 | ~1.2x slower |
| P384+ML-KEM-1024 | 356.3 us | 1,735 B | 27.0 KB | 67 | ~6.5x slower |

**Takeaway:** P256+ML-KEM-768 wrapping (~68us) is only ~1.2x slower than EC P-256 (~55us) — the ephemeral EC keygen + ECDH in the EC path narrows the gap significantly. RSA wrap is fastest since it's just OAEP padding. P384+ML-KEM-1024 is noticeably slower (~356us) due to the P-384 ECDH cost.

### Unwrap DEK

These benchmarks follow the KAS unwrap paths:
- **RSA:** pre-loaded `AsymDecryption.Decrypt` (key parsed at startup)
- **EC:** `NewSaltedECDecryptor(cachedKey, TDFSalt)` -> `DecryptWithEphemeralKey`
- **Hybrid:** `PrivateKeyFromPem` -> `UnwrapDEK` (PEM parsed each call)

| Scheme | Time | B/op | allocs/op | vs EC P-256 |
|--------|-----:|-----:|----------:|-------------|
| RSA-2048 | 705.0 us | 560 B | 8 | ~25x slower |
| EC P-256 | 28.0 us | 4.1 KB | 40 | baseline |
| X-Wing | 90.0 us | 12.4 KB | 37 | ~3.2x slower |
| P256+ML-KEM-768 | 78.0 us | 22.0 KB | 50 | ~2.8x slower |
| P384+ML-KEM-1024 | 365.2 us | 30.7 KB | 59 | ~13x slower |

**Takeaway:** RSA unwrap is the slowest operation in the entire suite (~705us) due to private key exponentiation. P256+ML-KEM-768 unwraps in ~78us — fast enough for real-time use. Hybrid unwraps include PEM parsing overhead that could be optimized by caching parsed keys (as EC already does).

### Wrap + Unwrap Round-Trip Summary

| Scheme | Wrap + Unwrap | Quantum Safe? |
|--------|-------------:|:-------------:|
| RSA-2048 | 731 us | No |
| EC P-256 | 83 us | No |
| X-Wing | 167 us | Yes |
| P256+ML-KEM-768 | 146 us | Yes |
| P384+ML-KEM-1024 | 722 us | Yes |

## Analysis: Where Time Is Spent

The `BenchmarkHybridSubOps` benchmarks break down hybrid wrap operations into their constituent parts:

### X-Wing Sub-Operations

| Operation | Time | % of Wrap |
|-----------|-----:|----------:|
| Encapsulate (X25519 + ML-KEM-768) | 71.9 us | 93.3% |
| HKDF key derivation | 0.53 us | 0.7% |
| AES-GCM encrypt (32B DEK) | 0.39 us | 0.5% |
| ASN.1 marshal | 0.57 us | 0.7% |
| PEM parsing + overhead | ~3.7 us | 4.8% |

### P256+ML-KEM-768 Sub-Operations

| Operation | Time | % of Wrap |
|-----------|-----:|----------:|
| Encapsulate (ECDH P-256 + ML-KEM-768) | 63.6 us | 94.1% |
| HKDF key derivation | 0.53 us | 0.8% |
| AES-GCM encrypt (32B DEK) | 0.40 us | 0.6% |
| ASN.1 marshal | 0.55 us | 0.8% |
| PEM parsing + overhead | ~2.5 us | 3.7% |

### P384+ML-KEM-1024 Sub-Operations

| Operation | Time | % of Wrap |
|-----------|-----:|----------:|
| Encapsulate (ECDH P-384 + ML-KEM-1024) | 344.8 us | 96.8% |
| HKDF key derivation | 0.53 us | 0.1% |
| AES-GCM encrypt (32B DEK) | 0.40 us | 0.1% |
| ASN.1 marshal | 0.61 us | 0.2% |
| PEM parsing + overhead | ~10.0 us | 2.8% |

**Conclusion:** KEM encapsulation dominates all hybrid schemes at 93-97% of total time. HKDF, AES-GCM, and ASN.1 marshaling are all sub-microsecond and negligible. The P-384 elliptic curve ECDH is ~5x slower than P-256, which is why P384+ML-KEM-1024 is significantly slower than P256+ML-KEM-768.

## Manifest Size Impact

| Scheme | Wrapped Key | Public Key (PEM) | Base64 Wrapped | Notes |
|--------|------------:|-----------------:|---------------:|-------|
| RSA-2048 | 256 B | 451 B | 344 B | No ephemeral key in manifest |
| EC P-256 | 60 B | 178 B | 80 B | + ephemeral key (91 B) in manifest |
| X-Wing | 1,190 B | 1,714 B | 1,588 B | All in single ASN.1 blob |
| P256+ML-KEM-768 | 1,223 B | 1,785 B | 1,632 B | All in single ASN.1 blob |
| P384+ML-KEM-1024 | 1,735 B | 2,347 B | 2,316 B | All in single ASN.1 blob |

> Base64 overhead = ceil(raw_bytes * 4/3). TDF manifests store wrapped keys as base64.

Hybrid schemes produce wrapped keys that are ~20x larger than EC P-256 (1.2-1.7 KB vs 60 B). For a TDF with a single recipient, this adds ~1-2 KB to the manifest. For multi-recipient TDFs, the overhead scales linearly per recipient.

## Trade-offs Summary

| Concern | RSA-2048 | EC P-256 | X-Wing | P256+ML-KEM-768 | P384+ML-KEM-1024 |
|---------|----------|----------|--------|-----------------|-------------------|
| Quantum resistance | None | None | Yes (hybrid) | Yes (hybrid) | Yes (hybrid) |
| Key generation | 48 ms (slow) | 7.4 us (fastest) | 44 us | 35 us | 115 us |
| Wrap latency | 26 us | 55 us | 77 us | 68 us | 356 us |
| Unwrap latency | 705 us (slow) | 28 us | 90 us | 78 us | 365 us |
| Round-trip | 731 us | 83 us | 167 us | 146 us | 722 us |
| Wrapped key size | 256 B | 60 B | 1,190 B | 1,223 B | 1,735 B |
| Standards basis | PKCS#1 | ECIES | IETF draft | NIST SP 800-227 | NIST SP 800-227 |

### Recommendations

- **P256+ML-KEM-768** is the best all-around hybrid choice: NIST-standardized, fastest hybrid round-trip (146us), and moderate size overhead (1.2 KB wrapped keys). Only 1.2x slower than EC P-256 for wrapping.
- **P384+ML-KEM-1024** provides a higher classical security level (192-bit vs 128-bit) at the cost of ~5x more latency. Use when policy requires P-384 or equivalent classical strength.
- **X-Wing** offers a simpler construction (X25519 + ML-KEM-768) but is based on an IETF draft rather than a NIST standard. Performance is comparable to P256+ML-KEM-768.
- **EC P-256** remains the fastest and smallest option for environments where quantum resistance is not yet required.
- **RSA-2048** has the worst unwrap performance (705us) and should be considered legacy.

### Optimization Opportunities

- **Hybrid unwrap PEM caching:** The KAS currently parses hybrid private key PEM on every unwrap call. Caching the parsed key (as EC already does) would save ~5-10us per unwrap.
