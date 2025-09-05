# Custom Assertion Providers for OpenTDF SDK

## Status
Implemented

## Context

The OpenTDF SDK previously only supported assertion signing and validation using predefined symmetric or asymmetric keys. This limitation prevented integration with external signing mechanisms such as:

- Hardware security modules (HSMs)
- Smart cards (CAC/PIV)
- Cloud-based key management services
- X.509 certificate-based signing

Additionally, the otdfctl tool (on a feature branch) had diverged from the SDK by implementing a different assertion binding approach, creating interoperability issues.

## Decision

We have implemented **custom assertion provider interfaces** that allow developers to supply their own signing and validation implementations while maintaining full backward compatibility with existing code.

### Key Design Principles

1. **Pluggable Architecture**: Developers can pass custom providers to the SDK
2. **Backward Compatible**: When no custom provider is supplied, SDK uses existing DEK-based logic
3. **Single Binding Style**: All tools use the same assertion binding approach (`assertionHash` + `assertionSig`)
4. **Flexible Verification**: Support both DEK-based and X.509-based verification methods

### Architecture

```
                 Assertion Providers
                         │
            ┌────────────┴────────────┐
            │                         │
     Signing Provider          Validation Provider
            │                         │
    ┌───────┴───────┐        ┌───────┴───────┐
    │               │        │               │
 Default         X.509    Default         X.509
 (DEK)     (Certificate)   (DEK)     (Certificate)
    │               │        │               │
 Built-in      External   Built-in      External
```

### Interfaces

#### AssertionSigningProvider

```go
type AssertionSigningProvider interface {
    // Sign creates a JWS signature for the given assertion
    Sign(ctx context.Context, assertion *Assertion, 
         assertionHash, assertionSig string) (signature string, err error)
    
    // GetSigningKeyReference returns a reference for the signing key
    GetSigningKeyReference() string
    
    // GetAlgorithm returns the signing algorithm (e.g., "RS256", "ES256")
    GetAlgorithm() string
}
```

#### AssertionValidationProvider

```go
type AssertionValidationProvider interface {
    // Validate verifies the assertion signature
    Validate(ctx context.Context, assertion Assertion) (hash, sig string, err error)
    
    // IsTrusted checks if the signing entity is trusted
    IsTrusted(ctx context.Context, assertion Assertion) error
    
    // GetTrustedAuthorities returns list of trusted authorities
    GetTrustedAuthorities() []string
}
```

### Usage

#### Creating TDFs with Custom Signing

```go
// X.509 certificate signing (e.g., for PIV/CAC cards)
provider := sdk.NewX509SigningProvider(privateKey, certChain)
client.CreateTDF(output, input, 
    sdk.WithAssertionSigningProvider(provider),
    sdk.WithAssertions(assertionConfigs))

// Default behavior (unchanged)
client.CreateTDF(output, input, sdk.WithAssertions(assertionConfigs))
```

#### Reading TDFs with Custom Validation

```go
// X.509 certificate validation
provider := sdk.NewX509ValidationProvider(options)
client.LoadTDF(file,
    sdk.WithReaderAssertionValidationProvider(provider))

// Default behavior (unchanged)
client.LoadTDF(file) // Uses DEK-based validation
```

## Implementation

### Completed Work

1. **Core Interfaces** (`sdk/assertion_provider.go`)
   - `AssertionSigningProvider` interface
   - `AssertionValidationProvider` interface
   - Supporting types and options

2. **Built-in Implementations**
   - `DefaultSigningProvider/DefaultValidationProvider` - Existing DEK-based behavior
   - `X509SigningProvider/X509ValidationProvider` - X.509 certificate support
   - `PKCS11Provider` - Template for hardware token integration

3. **SDK Integration**
   - `WithAssertionSigningProvider()` - Configure custom signing for TDF creation
   - `WithReaderAssertionValidationProvider()` - Configure custom validation for TDF reading
   - Automatic fallback to default providers when none specified

4. **Unified Binding Style**
   - All implementations use `assertionHash` and `assertionSig` claims
   - otdfctl updated to match SDK approach (completed 2025-01-04)
   - Full interoperability between all tools

### Example: Command Line Usage

```bash
# Decrypt TDF with X.509 assertion validation (e.g., from otdfctl)
./examples-cli decrypt --x509-verify signed.tdf

# Standard decryption (DEK-based validation)
./examples-cli decrypt signed.tdf
```

## Consequences

### Positive

- ✅ **Extensibility**: Support for any signing mechanism (HSM, cloud KMS, hardware tokens)
- ✅ **Backward Compatibility**: Existing code continues to work without changes
- ✅ **Interoperability**: All OpenTDF tools create compatible TDFs
- ✅ **Security**: X.509 support enables certificate-based identity and non-repudiation
- ✅ **Simplicity**: Single binding style reduces complexity

### Negative

- ❌ **Migration Required**: Developers using custom keys must implement providers
- ❌ **API Surface**: New interfaces to learn and maintain

### Neutral

- ↔️ **Performance**: Negligible impact - provider pattern adds minimal overhead
- ↔️ **Documentation**: Requires examples for common integration scenarios

## Security Considerations

1. **Key Management**: Custom providers are responsible for secure key handling
2. **Certificate Validation**: X.509 providers should verify certificate chains and revocation
3. **Trust Models**: Different providers may implement different trust policies
4. **Audit**: Providers should log signing operations for compliance

## Acceptance Criteria Verification

✅ **SDK exposes interface for custom signing implementation**
- `AssertionSigningProvider` interface defined and integrated

✅ **SDK exposes interface for custom assertion validation**
- `AssertionValidationProvider` interface defined and integrated

✅ **Defaults to existing logic when no custom providers supplied**
- SDK uses `DefaultSigningProvider/DefaultValidationProvider` automatically

✅ **Documentation explains implementation and usage**
- This ADR plus `CUSTOM_ASSERTION_PROVIDERS.md` guide

## Migration Guide

### For Existing Applications
No changes required. The SDK maintains full backward compatibility.

### For Hardware Token Integration
1. Implement `AssertionSigningProvider` using your PKCS#11 library
2. Pass provider via `WithAssertionSigningProvider()`
3. For validation, use `X509ValidationProvider` or implement custom

### For Cloud KMS Integration
1. Implement `AssertionSigningProvider` using your KMS SDK
2. Handle key references and permissions in your provider
3. Pass provider to SDK when creating TDFs

## Future Work

1. **Provider Registry**: Allow registration of providers by name/type
2. **Caching**: Add caching support for validation providers
3. **Batch Operations**: Optimize providers for bulk signing/validation
4. **Standard Providers**: Build providers for common KMS services (AWS, Azure, GCP)

## Decision Record

- **Date**: 2025-01-04  
- **Authors**: Platform SDK Team
- **Stakeholders**: Security Team, otdfctl Team, Enterprise Customers
- **Supersedes**: Initial assertion binding divergence
- **Related PRs**: 
  - SDK custom providers implementation
  - otdfctl alignment to SDK binding style

## References

- [OpenTDF Specification](https://github.com/opentdf/spec)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [X.509 Certificate Standard](https://www.itu.int/rec/T-REC-X.509)
- [PIV Card Specification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)