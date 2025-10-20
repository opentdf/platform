# Custom Assertion Providers for OpenTDF SDK

- **Status**: implemented

## Context and Problem Statement

The OpenTDF SDK needs to support custom assertion signing and validation mechanisms to enable integration with hardware security modules, smart cards, and cloud key management services. Currently, the SDK only supports DEK-based (Data Encryption Key) assertion signing, which prevents integration with:

- Personal Identity Verification (PIV) cards
- Common Access Card (CAC)
- Hardware security modules (HSMs)
- Cloud-based key management services (KMS like AWS KMS, Azure Key Vault, Google Cloud KMS)
- Custom cryptographic implementations

**Problem**: How can we allow developers to provide their own signing and validation logic while maintaining compatibility with existing DEK-based assertion handling and ensuring security?

**Key constraints**:
- Must not break existing TDFs or SDK behavior
- Must maintain cryptographic security guarantees
- Must support cross-SDK interoperability (Java, JavaScript, Go)
- Must be simple enough for developers to implement custom providers

## Decision Drivers

- **Hardware Security Requirements**: Enterprise customers require PIV/CAC card support for government and regulated environments
- **Cloud-Native Architecture**: Modern deployments need cloud KMS integration (AWS, Azure, GCP)
- **Security Compliance**: Organizations need hardware-backed key operations that never expose private keys
- **Developer Experience**: Must be easy to implement custom providers without deep cryptographic expertise
- **Backward Compatibility**: Cannot break existing TDF files or SDK implementations
- **Cross-SDK Interoperability**: Must work with Java and JavaScript SDKs
- **Performance**: Minimal overhead for assertion verification in high-throughput scenarios

## Considered Options

1. **Single Unified Provider Interface** - One interface handling both signing and validation
2. **Binder/Validator Pattern** - Separate interfaces for signing (binder) and validation (validator)
3. **Factory-Based Approach** - Central factory creating providers based on configuration
4. **Plugin Architecture** - Dynamic loading of assertion providers from external modules

## Decision Outcome

**Chosen option**: "Binder/Validator Pattern" (Option 2)

We implement separate `AssertionBinder` (for signing) and `AssertionValidator` (for verification) interfaces with regex-based pattern matching for validator dispatch.

### Key Design Elements

**Interfaces**:
```go
type AssertionBinder interface {
    Bind(ctx context.Context, manifest Manifest) (Assertion, error)
}

type AssertionValidator interface {
    Verify(ctx context.Context, assertion Assertion, reader Reader) error
    Validate(ctx context.Context, assertion Assertion, reader Reader) error
}
```

**Architecture**:
```
                 Assertion System
                         │
            ┌────────────┴────────────┐
            │                         │
      Binders (Signing)          Validators (Verification)
            │                         │
    ┌───────┴───────┐        ┌───────┴───────┐
    │               │        │               │
  Key-Based    Custom     Key-Based    Custom
  (RSA/EC)     (HSM/KMS)  (RSA/EC)     (HSM/KMS)
    │               │        │               │
 Built-in      External   Built-in      External
```

**Usage**:
```go
// Create TDF with custom binder
privateKey := sdk.AssertionKey{Alg: sdk.AssertionKeyAlgRS256, Key: rsaPrivateKey}
keyBinder := sdk.NewKeyAssertionBinder(privateKey)
client.CreateTDF(output, input,
    sdk.WithDataAttributes("attr/Classification/value/Secret"),
    sdk.WithAssertionBinder(keyBinder))

// Read TDF with custom validator
publicKeys := sdk.AssertionVerificationKeys{
    Keys: map[string]sdk.AssertionKey{
        sdk.KeyAssertionID: {Alg: sdk.AssertionKeyAlgRS256, Key: rsaPublicKey},
    },
}
keyValidator := sdk.NewKeyAssertionValidator(publicKeys)
pattern := regexp.MustCompile("^" + sdk.KeyAssertionID)
tdfreader, _ := client.LoadTDF(file,
    sdk.WithAssertionValidator(pattern, keyValidator))
```

### Rationale

**Why not Option 1 (Unified Provider)?**
- Coupling signing and validation logic together makes implementations more complex
- Many use cases only need validation (e.g., verifying signatures from external systems)
- Single interface would need 4+ methods, increasing implementation burden

**Why not Option 3 (Factory-Based)?**
- Adds indirection without clear benefit
- Makes it harder to test and mock providers
- Less flexible for runtime provider selection

**Why not Option 4 (Plugin Architecture)?**
- Over-engineered for the problem
- Adds deployment complexity
- Security concerns with dynamic code loading
- Most providers can be implemented as regular Go packages

**Why Option 2 (Binder/Validator) works best**:
- **Simplicity**: Single-method interfaces are easy to implement
- **Separation of Concerns**: Verify (crypto) vs Validate (policy) are distinct operations
- **Flexibility**: Regex-based validator dispatch enables mixed assertion types in one TDF
- **Efficiency**: Direct registration avoids factory overhead
- **Security**: Clear boundary between cryptographic verification and trust decisions

## Consequences

### Positive

- ✅ **Extensibility**: Supports any signing mechanism (HSM, cloud KMS, hardware tokens)
- ✅ **Simplicity**: Single-method interfaces are straightforward to implement
- ✅ **Flexibility**: Pattern-based dispatch supports mixed assertion types in one TDF
- ✅ **Efficiency**: Post-creation assertion binding without full decryption/re-encryption cycles
- ✅ **Security**: Cryptographic verification is independent from trust policy evaluation
- ✅ **Testability**: Easy to mock and test individual components
- ✅ **Backward Compatible**: Existing DEK-based assertions continue to work unchanged

### Negative

- ❌ **Learning Curve**: Developers must understand when to use binders vs validators
- ❌ **Pattern Matching**: Regex-based validator dispatch requires careful pattern design
- ❌ **Documentation Burden**: Need comprehensive examples for common scenarios (PIV/CAC, HSM, KMS)
- ❌ **Validation Complexity**: Two-phase validation (Verify + Validate) may be confusing initially

### Neutral

- ↔️ **Performance**: Minimal overhead from pattern matching and interface dispatch
- ↔️ **API Surface**: Adds 2 new interfaces and 4 new option functions to SDK

## Pros and Cons of the Options

### Option 1: Single Unified Provider Interface

**Pros**:
- Single interface to implement
- Simpler conceptual model

**Cons**:
- Forces all providers to implement both signing and validation
- Harder to compose different signing/validation strategies
- Less flexible for read-only or write-only scenarios
- Larger interface increases implementation burden

### Option 2: Binder/Validator Pattern (CHOSEN)

**Pros**:
- Clear separation between signing and validation
- Single-method interfaces are easy to implement
- Flexible pattern-based dispatch
- Independent implementation of crypto vs policy checks

**Cons**:
- Two interfaces to understand
- Regex pattern matching requires careful design

### Option 3: Factory-Based Approach

**Pros**:
- Centralized provider creation
- Could support configuration-based instantiation

**Cons**:
- Adds indirection layer
- Less flexible for runtime selection
- Harder to test
- Doesn't solve core problem better than Option 2

### Option 4: Plugin Architecture

**Pros**:
- Maximum flexibility for third-party providers
- Could support dynamic provider loading

**Cons**:
- Over-engineered for this use case
- Security concerns with dynamic code loading
- Deployment complexity
- Most providers can be standard Go packages

## More Information

### Cryptographic Binding Mechanism

Assertions are cryptographically bound to the TDF payload by signing the manifest's **root signature** along with the assertion hash:

```go
// During TDF creation (in AssertionBinder.Bind):
assertionHash := assertion.GetHash()
rootSignature := manifest.RootSignature.Signature  // Already base64-encoded
assertion.Sign(assertionHash, rootSignature, signingKey)

// During TDF verification (in AssertionValidator.Verify):
verifiedHash, verifiedSig := assertion.Verify(verificationKey)
if manifest.RootSignature.Signature != verifiedSig {
    return errors.New("signature mismatch")
}
```

**Why root signature as binding target?**
1. **No Runtime Computation**: Stored directly in manifest, no need to recompute aggregate hashes
2. **Comprehensive Coverage**: HMAC over aggregate hash of all payload segments
3. **Simple Verification**: Direct string comparison

### Verification Modes

The SDK supports three verification modes for different security/compatibility trade-offs:

| Mode                   | Unknown Assertions | Missing Keys | Missing Binding | Verification Failure |
|------------------------|--------------------|--------------|-----------------|----------------------|
| **PermissiveMode**     | Skip + warn        | Skip + warn  | **FAIL**        | Log + continue       |
| **FailFast (default)** | Skip + warn        | **FAIL**     | **FAIL**        | **FAIL**             |
| **StrictMode**         | **FAIL**           | **FAIL**     | **FAIL**        | **FAIL**             |

**Recommendation**: Use `FailFast` for production (default), `PermissiveMode` only for development/testing, `StrictMode` for high-security environments.

### Cross-SDK Compatibility

Supports two assertion binding formats:

**Format v2 (Current - Go SDK)**:
```
assertionSig = rootSignature
```
- More secure, direct binding to manifest root signature

**Format v1 (Legacy - Java/JS SDKs)**:
```
assertionSig = base64(aggregateHash + assertionHash)
```
- Maintained for backward compatibility with older Java/JS SDK versions
- No schema claim in JWT (legacy format)

Both `SystemMetadataAssertionProvider` and `KeyAssertionValidator` auto-detect format version.

### Security Considerations

1. **Mandatory Bindings**: All assertions MUST have cryptographic bindings. Assertions without explicit signing keys are auto-signed with the DEK.
2. **Key Management**: Custom binders must handle private keys securely (PIV/CAC/HSM never expose key material).
3. **Certificate Validation**: Validators should verify X.509 certificate chains, expiration, and revocation status.
4. **Verification Mode Security**: Validators respect configured mode to prevent bypasses. A critical security fix (2025-10-17) ensures validators fail securely when no keys are configured instead of silently skipping verification.
5. **Binding Integrity**: Root signature binding ensures assertions cannot be moved between TDFs or tampered with.

### Implementation Guide

**Custom Binder (Signing)**:
1. Implement `AssertionBinder.Bind(ctx, manifest) (Assertion, error)`
2. Create assertion with appropriate ID, scope, and statement
3. Generate cryptographic signature over manifest
4. Return complete assertion with binding
5. Register via `sdk.WithAssertionBinder(binder)`

**Custom Validator (Verification)**:
1. Implement `AssertionValidator.Schema()` to return expected schema URI
2. Implement `AssertionValidator.Verify()` for cryptographic checks:
   - Validate `assertion.Statement.Schema` matches expected schema BEFORE processing
   - Verify JWT signature and extract `assertionHash`, `assertionSig` claims
   - Verify assertion hash and manifest binding
3. Implement `AssertionValidator.Validate()` for policy/trust checks
4. Define regex pattern matching target assertion IDs
5. Register via `sdk.WithAssertionValidator(pattern, validator)`

**Example: PIV/CAC Card (PKCS#11)**:
- Connect to card via PKCS#11 library
- Reference signing certificate by slot/label
- Private key never leaves the card
- Call card's signing operation in `Bind()`
- Return assertion with X.509-based signature

**Example: Cloud KMS**:
- Authenticate to KMS service
- Reference key by identifier (ARN/URI)
- Call KMS Sign API in `Bind()`
- Handle key versioning and rotation

### Future Enhancements

1. **Caching**: Validator result caching for improved performance
2. **Batch Operations**: Optimized bulk signing/validation patterns
3. **Standard Implementations**: Reference implementations for PIV/CAC, HSM, cloud KMS
4. **PKCS#11 Library**: Production-ready PIV/CAC/HSM integration library
5. **X.509 PKI**: Full certificate chain validation and revocation checking (OCSP/CRL)

## Links

- [OpenTDF Specification](https://github.com/opentdf/spec)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [X.509 Certificate Standard](https://www.itu.int/rec/T-REC-X.509)
- [PIV Card Specification (NIST SP 800-73-4)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)
- [PR #2687 - Implementation](https://github.com/opentdf/platform/pull/2687)
- [MADR Template](https://adr.github.io/madr/)
