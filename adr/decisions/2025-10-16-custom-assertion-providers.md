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

We implement separate `AssertionBinder` (for signing) and `AssertionValidator` (for verification) interfaces with exact string matching for validator dispatch.

### Key Design Elements

**Interfaces**:
```go
type AssertionBinder interface {
    // Bind creates and signs an assertion, binding it to the manifest.
    // Use ShouldUseHexEncoding(m) for format compatibility.
    Bind(ctx context.Context, manifest Manifest) (Assertion, error)
}

type AssertionValidator interface {
    Schema() string  // Returns schema URI or "*" for wildcard
    Verify(ctx context.Context, assertion Assertion, reader Reader) error    // Crypto check
    Validate(ctx context.Context, assertion Assertion, reader Reader) error  // Policy check
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

**Registration**:
- Binders: `sdk.WithAssertionBinder(binder)`
- Validators: `sdk.WithAssertionValidator(schema, validator)` using exact schema string matching (the `schema` parameter must exactly match the value returned by the validator's `Schema()` method)

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
- **Flexibility**: Schema-based validator dispatch enables mixed assertion types in one TDF
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
- ❌ **Schema Matching**: Validator schema strings must exactly match registration keys
- ❌ **Documentation Burden**: Need comprehensive examples for common scenarios (PIV/CAC, HSM, KMS)
- ❌ **Validation Complexity**: Two-phase validation (Verify + Validate) may be confusing initially

### Neutral

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
- Flexible schema-based dispatch
- Independent implementation of crypto vs policy checks

**Cons**:
- Two interfaces to understand
- Schema strings must exactly match between registration and validator implementation

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

**Standard Format**: `base64(aggregateHash + assertionHash)`

- Binds assertions to all payload segments via aggregateHash
- Cross-SDK compatible (Java, JS, Go)
- `ShouldUseHexEncoding(manifest)` determines legacy (hex) vs modern (raw bytes) encoding
- SDK provides `ComputeAssertionSignature()` helper for consistent implementation

### Verification Modes

The SDK supports three verification modes for different security/compatibility trade-offs:

| Mode                   | Unknown Assertions | Missing Keys | Missing Binding | Verification Failure | DEK Fallback |
|------------------------|--------------------|--------------|-----------------|----------------------|--------------|
| **PermissiveMode**     | Skip + warn        | Skip + warn  | **FAIL**        | Log + continue       | Attempted    |
| **FailFast (default)** | Skip + warn        | **FAIL**     | **FAIL**        | **FAIL**             | Attempted    |
| **StrictMode**         | **FAIL**           | **FAIL**     | **FAIL**        | **FAIL**             | Attempted    |

**DEK Fallback Logic**: When no schema-specific validator exists and no explicit verification keys provided:
1. Attempt verification with DEK (payload key)
2. If JWT verification fails (wrong key) → Treat as unknown assertion (skip per mode)
3. If JWT succeeds but hash/binding fails → **FAIL** (tampering detected)
4. If verification succeeds → Assertion validated with DEK

This enables forward compatibility (new assertion types are skipped) while detecting tampering (DEK-signed assertions are validated).

**Recommendation**: Use `FailFast` for production (default), `PermissiveMode` only for development/testing, `StrictMode` for high-security environments.

### Security Considerations

1. **Mandatory Bindings**: All assertions MUST have cryptographic bindings - unsigned assertions are rejected immediately
2. **Key Management**: Private keys should remain in HSM/PIV/CAC and never be exposed
3. **Fail-Secure Validation**: Validators fail securely when keys are missing (not silently skip)
4. **Binding Integrity**: Assertion signature format binds to all payload segments via aggregateHash
5. **TDFVersion Spoofing**: `ShouldUseHexEncoding()` checks unprotected `TDFVersion` field - use ONLY for format detection, NOT security decisions. Always verify cryptographic bindings regardless of version.
6. **DEK Fallback Validation**: Assertions without schema-specific validators attempt DEK verification as fallback, enabling tampering detection while maintaining forward compatibility

### Implementation Requirements

**Custom Binders/Validators must**:
- Use `ShouldUseHexEncoding(manifest)` and `ComputeAssertionSignature()` for cross-SDK compatibility
- Compute `aggregateHash` from manifest segments during binding/verification (not pre-store)
- Verify cryptographic bindings in `Verify()`, enforce policy in `Validate()`

## Links

- [OpenTDF Specification](https://github.com/opentdf/spec)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [X.509 Certificate Standard](https://www.itu.int/rec/T-REC-X.509)
- [PIV Card Specification (NIST SP 800-73-4)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)
- [PR #2687 - Implementation](https://github.com/opentdf/platform/pull/2687)
- [MADR Template](https://adr.github.io/madr/)
