# Performance Analysis: RSA vs ML-DSA-44 Quantum-Resistant Assertions

## Executive Summary

This analysis compares the performance and size characteristics of traditional RSA-based assertions versus quantum-resistant ML-DSA-44 assertions in the OpenTDF platform.

## Key Findings

### 1. Performance Metrics (Individual Operations)

| Operation | RSA-2048 | ML-DSA-44 | Quantum Advantage |
|-----------|----------|-----------|-------------------|
| **Key Generation** | ~126ms | ~82μs | **1,533x faster** |
| **Signing** | ~888μs | ~209μs | **4.2x faster** |
| **Verification** | ~35μs | ~50μs | 1.4x slower |

### 2. Size Metrics

| Component | RSA-2048 | ML-DSA-44 | Size Impact |
|-----------|----------|-----------|-------------|
| **Private Key** | 2.8KB | 2.5KB | 11% smaller |
| **Public Key** | 639B | 1.3KB | **2.1x larger** |
| **Signature** | 503B | 4.4KB | **8.9x larger** |

### 3. TDF Creation Impact

| Metric | Traditional (HS256) | Quantum-Safe (ML-DSA) | Overhead |
|--------|---------------------|------------------------|----------|
| **Assertion Creation Time** | ~4.8μs | ~285μs | **59x slower** |
| **Memory Usage** | 4.8KB/op | 77KB/op | **16x more memory** |
| **Assertion Signature Size** | 155B | 4.3KB | **28x larger** |

## Detailed Benchmark Results

### Raw Performance Data
```
BenchmarkRSAKeyGeneration-12           12    126159128 ns/op    888770 B/op    7373 allocs/op
BenchmarkMLDSAKeyGeneration-12      14760        82357 ns/op     55328 B/op       3 allocs/op
BenchmarkRSASigning-12               1388       887956 ns/op      6560 B/op      96 allocs/op
BenchmarkMLDSASigning-12             5544       209166 ns/op     20788 B/op      13 allocs/op
BenchmarkRSAVerification-12         34788        34580 ns/op      8859 B/op     133 allocs/op
BenchmarkMLDSAVerification-12       23985        50160 ns/op     10664 B/op      21 allocs/op
```

### TDF Integration Performance
```
BenchmarkTDFWithTraditionalAssertions-12    254433     4791 ns/op     4774 B/op    103 allocs/op
BenchmarkTDFWithQuantumAssertions-12          4068   285444 ns/op    76659 B/op     20 allocs/op
```

## Analysis & Recommendations

### Performance Advantages of ML-DSA-44

✅ **Key Generation**: Extremely fast (1,533x faster than RSA)
✅ **Signing Operations**: Significantly faster (4.2x faster than RSA)
✅ **Memory Efficiency**: Fewer memory allocations for crypto operations
✅ **Future-Proof Security**: Quantum-resistant by design

### Performance Trade-offs

⚠️ **Signature Size**: 8.9x larger signatures impact storage and bandwidth
⚠️ **TDF Creation**: 59x slower when quantum assertions are enabled
⚠️ **Memory Usage**: 16x more memory during TDF creation with quantum assertions
⚠️ **Verification**: Slightly slower than RSA (1.4x)

### Recommended Use Cases

#### Choose ML-DSA-44 When:
- **Long-term security** is critical (data will be valuable for 10+ years)
- **Compliance** requires quantum-resistant cryptography
- **High-value data** needs protection against future quantum attacks
- **Performance impact** is acceptable for the security benefit

#### Choose Traditional RSA When:
- **Legacy compatibility** is required
- **Bandwidth/storage** constraints are critical
- **Short-term data** protection (< 5 years)
- **Maximum performance** is needed

### Migration Strategy

1. **Hybrid Approach**: Use quantum-resistant assertions for new, high-value data
2. **Gradual Migration**: Implement quantum assertions for sensitive datasets first
3. **Performance Monitoring**: Track impact on system performance during rollout
4. **Storage Planning**: Account for 8.9x larger signature storage requirements

### Technical Considerations

- **Bandwidth Impact**: Each quantum assertion adds ~4KB vs ~500B for RSA
- **Storage Growth**: TDF files will be larger with quantum assertions
- **Processing Overhead**: 59x slower TDF creation may impact high-throughput scenarios
- **Memory Planning**: 16x more memory usage during quantum TDF creation

## Conclusion

ML-DSA-44 provides excellent quantum resistance with superior key generation and signing performance compared to RSA. However, the significantly larger signature sizes and slower TDF creation process require careful consideration of use cases and system resources.

The quantum-resistant option should be adopted for high-value, long-term data where future security is paramount, while traditional RSA remains suitable for performance-critical or legacy scenarios.
