# Custom Assertion Providers for OpenTDF SDK

## Status
Implemented

## Context

The OpenTDF SDK needs to support custom assertion signing and validation mechanisms to enable integration with:

- Personal Identity Verification (PIV) cards
- Common Access Card (CAC)
- Hardware security modules (HSMs)
- Cloud-based key management services (KMS)
- Custom cryptographic implementations

The SDK must allow developers to provide their own signing and validation logic while maintaining compatibility with existing DEK-based assertion handling.

## Decision

Implement a **binder/validator pattern** that enables custom assertion signing and validation through simple interfaces.

### Key Design Principles

1. **Pluggable Architecture**: Developers provide custom binders and validators
2. **Clear Separation**: Distinct interfaces for signing (`AssertionBinder`) and validation (`AssertionValidator`)
3. **Pattern-Based Dispatch**: Validators are selected via regex matching on assertion IDs
4. **Cryptographic Independence**: Separates cryptographic verification from policy validation
5. **Efficient Mutation**: Support post-creation assertion binding without full re-encryption

### Architecture

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

### Interfaces

#### AssertionBinder (for Creating Assertions)

```go
type AssertionBinder interface {
    // Bind creates and signs an assertion based on the TDF manifest
    Bind(ctx context.Context, manifest Manifest) (Assertion, error)
}
```

#### AssertionValidator (for Verifying Assertions)

```go
type AssertionValidator interface {
    // Verify checks the assertion's cryptographic binding
    Verify(ctx context.Context, assertion Assertion, reader Reader) error

    // Validate checks the assertion's policy and trust requirements
    Validate(ctx context.Context, assertion Assertion, reader Reader) error
}
```

### Usage

#### Creating TDFs with Custom Assertion Binders

```go
// Key-based assertion signing (RSA/EC)
privateKey := sdk.AssertionKey{
    Alg: sdk.AssertionKeyAlgRS256,
    Key: rsaPrivateKey,
}
keyBinder := sdk.NewKeyAssertionBinder(privateKey)

client.CreateTDF(output, input,
    sdk.WithDataAttributes("https://example.com/attr/Classification/value/Secret"),
    sdk.WithAssertionBinder(keyBinder))

// Custom binder (e.g., "Magic Word" for simple scenarios)
magicWordBinder := NewMagicWordAssertionProvider("swordfish")
client.CreateTDF(output, input,
    sdk.WithDataAttributes("https://example.com/attr/Classification/value/Secret"),
    sdk.WithAssertionBinder(magicWordBinder))

// Default behavior with system metadata assertion
client.CreateTDF(output, input,
    sdk.WithDataAttributes("https://example.com/attr/Classification/value/Secret"),
    sdk.WithSystemMetadataAssertion())
```

#### Reading TDFs with Custom Assertion Validators

```go
// Key-based assertion validation
publicKeys := sdk.AssertionVerificationKeys{
    Keys: map[string]sdk.AssertionKey{
        sdk.KeyAssertionID: {
            Alg: sdk.AssertionKeyAlgRS256,
            Key: rsaPublicKey,
        },
    },
}
keyValidator := sdk.NewKeyAssertionValidator(publicKeys)
keyPattern := regexp.MustCompile("^" + sdk.KeyAssertionID)

tdfreader, err := client.LoadTDF(file,
    sdk.WithAssertionValidator(keyPattern, keyValidator),
    sdk.WithDisableAssertionVerification(false))

// Custom validator (e.g., "Magic Word")
magicWordValidator := NewMagicWordAssertionProvider("swordfish")
magicWordPattern := regexp.MustCompile("^magic-word$")

tdfreader, err := client.LoadTDF(file,
    sdk.WithAssertionValidator(magicWordPattern, magicWordValidator),
    sdk.WithDisableAssertionVerification(false))
```

## Design Rationale

### Why Binder/Validator Pattern

**Simplicity**: Single-method interfaces (`Bind()` for signing, `Verify()`/`Validate()` for validation) are easier to implement than multi-method provider interfaces.

**Flexibility**: Regex-based validator dispatch enables different validation strategies for different assertion types within the same TDF.

**Separation of Concerns**:
- `Verify()` handles cryptographic binding validation
- `Validate()` handles policy and trust evaluation
- Clear distinction between "is the signature valid?" vs "do we trust the signer?"

**Efficiency**: Direct registration avoids factory indirection. `AppendAssertion()` enables adding assertions to existing TDFs without full decryption/re-encryption cycles.

## Consequences

### Positive

- ✅ **Extensibility**: Supports any signing mechanism (HSM, cloud KMS, hardware tokens)
- ✅ **Simplicity**: Single-method interfaces are straightforward to implement
- ✅ **Flexibility**: Pattern-based dispatch supports mixed assertion types in one TDF
- ✅ **Efficiency**: Post-creation assertion binding without full re-encryption
- ✅ **Security**: Cryptographic verification is independent from trust policy

### Negative

- ❌ **Learning Curve**: Developers must understand when to use binders vs validators
- ❌ **Pattern Matching**: Regex-based validator dispatch requires careful pattern design

### Neutral

- ↔️ **Performance**: Minimal overhead from pattern matching and interface dispatch

## Cryptographic Binding Mechanism

### Binding Target: Manifest Root Signature

Assertions are cryptographically bound to the TDF payload by signing the manifest's **root signature** along with the assertion hash. The root signature is chosen as the binding target because:

1. **No Runtime Computation**: Root signature is stored directly in the manifest, avoiding the need to recompute aggregate hashes from segments during verification
2. **Comprehensive Coverage**: Root signature is an HMAC over the aggregate hash of all payload segments, providing complete integrity coverage
3. **Simple Verification**: Direct string comparison against manifest value

### Encoding Convention

The root signature in the manifest is **base64-encoded**. The assertion binding mechanism maintains this encoding:

- **During `Assertion.Sign()`**: The root signature parameter is already base64-encoded (from `manifest.RootSignature.Signature`), so it's stored directly in the JWT without additional encoding
- **During `Assertion.Verify()`**: The signature is extracted from the JWT and compared directly against `manifest.RootSignature.Signature` (both are base64-encoded strings)

**Important**: Custom binders that implement cryptographic binding should follow this convention to ensure compatibility.

### Example Binding Flow

```go
// During TDF creation (in AssertionBinder.Bind):
assertionHash := assertion.GetHash()
rootSignature := manifest.RootSignature.Signature  // Already base64-encoded
assertion.Sign(assertionHash, rootSignature, signingKey)

// During TDF verification (in AssertionValidator.Verify):
verifiedHash, verifiedSig := assertion.Verify(verificationKey)
if manifest.RootSignature.Signature != verifiedSig {  // Both base64-encoded
    return errors.New("signature mismatch")
}
```

## Security Considerations

1. **Key Management**: Custom binders must handle private keys securely (PIV/CAC/HSM never expose key material)
2. **Certificate Validation**: Validators should verify X.509 certificate chains, expiration, and revocation status
3. **Trust Models**: The `Validate()` method enables policy-based trust decisions beyond cryptographic verification
4. **Audit Logging**: Binders and validators should log operations for compliance and debugging
5. **Pattern Safety**: Regex patterns must be carefully designed to avoid unintended validator selection
6. **Binding Integrity**: The root signature binding ensures assertions cannot be moved between TDFs or added/removed without detection
7. **Mandatory Bindings**: All assertions MUST have cryptographic bindings. Assertions without explicit signing keys are automatically signed with the DEK (payload key) to maintain security while supporting backward compatibility
8. **Verification Mode Security**: Validators respect the configured verification mode to prevent security bypasses (see Verification Modes section below)

## Cross-SDK Compatibility

The Go SDK supports two assertion binding formats to maintain interoperability with Java and JavaScript SDKs:

### Format v2 (Current - Go SDK)
```
assertionSig = rootSignature
```
- Used by Go SDK for newly created TDFs
- More secure binding directly to manifest root signature
- No need to reconstruct aggregate hash during verification

### Format v1 (Legacy - Java/JS SDKs)
```
assertionSig = base64(aggregateHash + assertionHash)
```
- Used by older Java and JavaScript SDK versions
- Supported for backward compatibility when reading TDFs
- Less secure but maintained for cross-SDK interoperability

### Auto-Detection
Both `SystemMetadataAssertionProvider` and `KeyAssertionValidator` implement automatic format detection:

1. First attempt to verify using v2 format (root signature comparison)
2. If v2 fails, fall back to v1 legacy verification
3. Log format detection for observability

This ensures:
- ✅ Go SDK can read TDFs created by Java/JS SDKs (v1 format)
- ✅ Java/JS SDKs can read TDFs created by Go SDK with explicit keys (v2 format)
- ✅ Tamper detection works correctly in both formats
- ✅ No breaking changes for existing TDF consumers

### DEK Auto-Signing

Assertions without explicit signing keys are automatically signed with the DEK (payload key) during TDF creation:

```go
// In sdk/tdf.go during CreateTDF:
// 1. Binders create assertions (may be unsigned if no explicit key)
for _, binder := range assertionRegistry.binders {
    boundAssertion := binder.Bind(ctx, manifest)
    boundAssertions = append(boundAssertions, boundAssertion)
}

// 2. Auto-sign any unsigned assertions with DEK
dekKey := AssertionKey{Alg: AssertionKeyAlgHS256, Key: payloadKey[:]}
for i := range boundAssertions {
    if boundAssertions[i].Binding.IsEmpty() {
        assertionHash := boundAssertions[i].GetHash()
        boundAssertions[i].Sign(assertionHash, manifest.RootSignature.Signature, dekKey)
    }
}
```

This ensures all assertions have mandatory cryptographic bindings while maintaining backward compatibility with test fixtures and SDKs that don't provide explicit keys.

## Verification Modes

The SDK supports three verification modes that control how assertion validation errors are handled. This provides flexibility for different security requirements and deployment scenarios.

### Mode Comparison Matrix

| Scenario | PermissiveMode | FailFast (Default) | StrictMode |
|----------|---------------|-------------------|------------|
| **Unknown assertion** | Skip + warn | Skip + warn | **FAIL** |
| **Missing verification keys** | Skip + warn | **FAIL** | **FAIL** |
| **Missing binding** | **FAIL** | **FAIL** | **FAIL** |
| **Tampered binding** | **FAIL** | **FAIL** | **FAIL** |
| **Verification failure** | Log + continue | **FAIL** | **FAIL** |
| **Validation failure** | Log + continue | **FAIL** | **FAIL** |

### Mode Selection Guidelines

**PermissiveMode**:
- Use Case: Development, testing, forward compatibility testing
- Security Level: Low - May allow tampered assertions
- Compatibility: Highest - Works with partial configurations
- **WARNING**: Never use in production with sensitive data

**FailFast (Default)**:
- Use Case: Production deployments with known assertion types
- Security Level: High - Detects tampering, prevents key bypass
- Compatibility: Good - Forward compatible with unknown assertions
- **Recommended**: Best balance for most production scenarios

**StrictMode**:
- Use Case: High-security, regulated environments, controlled TDF formats
- Security Level: Maximum - Every assertion must be explicitly validated
- Compatibility: Lowest - Breaks on unknown assertions
- **Recommended**: Environments where all TDF formats are controlled

### Security Fix (2025-10-17)

A critical security vulnerability was identified and fixed where validators would skip verification when no keys were configured, rather than failing securely. The fix ensures:

1. **FailFast and StrictMode**: Validators with empty key sets now fail with an error instead of silently skipping
2. **PermissiveMode**: Maintains backward compatibility by logging warnings but continuing
3. **Attack Prevention**: Prevents bypass attacks where adversaries use unconfigured key IDs

Implementation details:
- Added `verificationMode` field to all validators
- Added `SetVerificationMode()` method for mode propagation
- SDK automatically propagates mode to all registered validators during TDF reading

### Usage Example

```go
// Production: Fail-secure with balanced compatibility (default)
reader, _ := client.LoadTDF(file,
    sdk.WithAssertionValidator(pattern, validator),
    sdk.WithAssertionVerificationMode(sdk.FailFast))

// Development: Best-effort validation with warnings
reader, _ := client.LoadTDF(file,
    sdk.WithAssertionValidator(pattern, validator),
    sdk.WithAssertionVerificationMode(sdk.PermissiveMode))

// High-security: Zero tolerance for unknowns
reader, _ := client.LoadTDF(file,
    sdk.WithAssertionValidator(pattern, validator),
    sdk.WithAssertionVerificationMode(sdk.StrictMode))
```

## Acceptance Criteria

✅ **Pluggable signing and validation**
- Custom implementations via `AssertionBinder` and `AssertionValidator` interfaces

✅ **Clean API design**
- Direct binder/validator interfaces without intermediate abstractions

✅ **Flexible dispatch**
- Regex-based pattern matching enables selective validation by assertion type

✅ **Efficient assertion management**
- Post-creation binding via `AppendAssertion()` without full re-encryption

## Implementation Guide

### Custom Binder (Signing)

1. Implement `AssertionBinder.Bind(ctx, manifest) (Assertion, error)`
2. Create assertion with appropriate ID, scope, and statement
3. Generate cryptographic signature over manifest
4. Return complete assertion with binding
5. Register via `sdk.WithAssertionBinder(binder)`

### Custom Validator (Verification)

1. Implement `AssertionValidator.Verify(ctx, assertion, reader) error` for cryptographic checks
2. Implement `AssertionValidator.Validate(ctx, assertion, reader) error` for policy/trust checks
3. Define regex pattern matching target assertion IDs
4. Register via `sdk.WithAssertionValidator(pattern, validator)`

### PIV/CAC Card (PKCS#11)

Implement `AssertionBinder` that:
- Connects to PIV/CAC card via PKCS#11 library
- References signing certificate by slot/label
- Private key never leaves the card
- Calls card's signing operation in `Bind()`
- Returns assertion with X.509-based signature

### HSM (PKCS#11)

Implement `AssertionBinder` that:
- Connects to HSM via PKCS#11 library
- References key by label/ID without exposing private key material
- Calls HSM signing operation in `Bind()`
- Returns assertion with signature from hardware

### Cloud KMS

Implement `AssertionBinder` that:
- Authenticates to cloud KMS service
- References key by identifier (ARN/URI/resource ID)
- Calls KMS Sign API in `Bind()`
- Handles key versioning and rotation

## Future Considerations

1. **Caching**: Validator result caching for improved performance
2. **Batch Operations**: Optimized bulk signing/validation patterns
3. **Standard Implementations**: Reference implementations for PIV/CAC, HSM, and cloud KMS providers
4. **PKCS#11 Library**: Production-ready PIV/CAC/HSM integration library
5. **X.509 PKI**: Full certificate chain validation and revocation checking (OCSP/CRL)

## Decision Record

- **Date**: 2025-10-16
- **Authors**: Platform SDK Team
- **Stakeholders**: Security Team, Enterprise Customers requiring PIV/CAC/HSM/KMS integration

## References

- [OpenTDF Specification](https://github.com/opentdf/spec)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [X.509 Certificate Standard](https://www.itu.int/rec/T-REC-X.509)
- [PIV Card Specification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)
