# OpenTDF SDK Examples

This directory contains example code demonstrating how to use the OpenTDF SDK with quantum-resistant assertions.

## Basic Usage Example

The `basic-usage/` directory contains a simple example showing how to create a TDF with quantum-resistant assertions:

```bash
cd basic-usage
go run basic_quantum_usage.go
```

## Performance Demo

The `performance-demo/` directory contains an interactive demonstration that compares performance metrics between traditional and quantum-resistant cryptography:

```bash
cd performance-demo  
go run demo_quantum_performance.go
```

This demo shows:
- Key generation speed comparison
- Signing performance differences
- Size overhead analysis
- Real-world usage recommendations

## Features Demonstrated

- **Quantum-Resistant Assertions**: Using ML-DSA-44 for future-proof security
- **Performance Analysis**: Detailed metrics comparing RSA vs ML-DSA
- **Integration**: How to enable quantum assertions in existing TDF workflows
- **Best Practices**: When to use quantum-resistant vs traditional cryptography

## Requirements

- Go 1.21 or later
- OpenTDF platform (for full functionality)
- Access to appropriate dependencies

## Security Note

These examples demonstrate quantum-resistant cryptography using ML-DSA-44 (FIPS-204), providing protection against both classical and quantum computing attacks.
