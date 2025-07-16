# Quantum-Resistant Assertions in OpenTDF

This document describes the quantum-resistant assertion feature added to the OpenTDF SDK, which provides protection against quantum computer attacks using ML-DSA (FIPS-204) signatures.

## Overview

The OpenTDF platform now supports quantum-resistant assertions using the ML-DSA-44 (Module Lattice Digital Signature Algorithm) standardized in FIPS-204. This feature ensures that TDF assertions remain secure even against future quantum computing attacks.

## Usage

To enable quantum-resistant assertions when creating a TDF, use the `WithQuantumResistantAssertions()` option:

```go
tdfObject, err := sdk.CreateTDF(writer, reader,
    sdk.WithQuantumResistantAssertions(), // Enable quantum-resistant signatures
    sdk.WithSystemMetadataAssertion(),    // Add system metadata with quantum-safe signatures
    sdk.WithDataAttributes("https://example.com/attr/classification/sensitive"),
)
```

## How It Works

When `WithQuantumResistantAssertions()` is enabled:

1. **System Metadata Assertions**: Default system metadata assertions are signed using ML-DSA-44 instead of traditional HMAC-SHA256
2. **Custom Assertions**: If no signing key is provided for custom assertions, ML-DSA-44 keys are automatically generated
3. **Backward Compatibility**: Traditional RSA/HMAC signatures are still supported for assertions that explicitly provide signing keys

## API Functions

### `WithQuantumResistantAssertions() TDFOption`
Enables quantum-resistant assertions for TDF creation.

### `GenerateMLDSAKeyPair() (AssertionKey, error)`
Generates a new ML-DSA-44 key pair for manual assertion signing.

### `GetQuantumSafeSystemMetadataAssertionConfig() (AssertionConfig, error)`
Creates a system metadata assertion configuration with ML-DSA-44 signatures.

## Algorithm Details

- **Algorithm**: ML-DSA-44 (FIPS-204)
- **Security Level**: NIST Level 2 (equivalent to AES-128)
- **Key Size**: 1,312 bytes (private), 1,312 bytes (public)
- **Signature Size**: 2,420 bytes
- **Performance**: Optimized for balance between security and speed

## Migration Guide

### For New Applications
Simply add `WithQuantumResistantAssertions()` to your TDF creation options.

### For Existing Applications
1. Add the quantum-resistant option to enable post-quantum security
2. Existing TDFs with traditional signatures can still be verified
3. New TDFs will use quantum-resistant signatures automatically

## Example

See `examples/quantum_assertions_example.go` for a complete working example.

## Security Considerations

- ML-DSA-44 provides protection against both classical and quantum attacks
- Signatures are larger than traditional schemes but provide future-proof security
- The implementation uses the Cloudflare CIRCL library, which follows FIPS-204 standards
- All cryptographic operations use secure random number generation

## Testing

Run the quantum assertion tests:

```bash
cd sdk
go test -v -run TestQuantum
```

This will verify:
- Key generation functionality
- Signing and verification processes
- Integration with TDF creation
- Backward compatibility
