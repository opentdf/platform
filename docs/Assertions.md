# Assertions

This document describes the format of assertions in OpenTDF to ensure interoperability between different tools and implementations.

For troubleshooting assertion issues, see [Assertions-Troubleshooting.md](./Assertions-Troubleshooting.md).

## Assertion Structure

Assertions follow the OpenTDF specification and contain the following fields:

```json
{
  "id": "assertion-identifier",
  "type": "handling",
  "scope": "tdo",
  "appliesToState": "encrypted",
  "statement": {
    "format": "value",
    "schema": "urn:example:schema",
    "value": "assertion-specific-data"
  },
  "binding": {
    "method": "jws",
    "signature": "base64-encoded-signature"
  }
}
```

## Key-Based Assertions

Key-based assertions use asymmetric cryptography (RSA or ECDSA) for signing.

### Assertion ID Format

```
<algorithm>-<key-fingerprint>
```

Example: `RS256-a1b2c3d4e5f6...`

### Signature Method

The `binding.method` is set to `jws` (JSON Web Signature).

### Signature Format

The signature is a JWS Compact Serialization containing:

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "assertionHash": "<sha256-hash-of-assertion-statement>",
  "assertionSig": "<signature-over-manifest>",
  "assertionSchema": "<schema-uri-from-statement>"
}
```

**Security Note**: The `assertionSchema` claim (added in v2) cryptographically binds the schema to the assertion, preventing schema substitution attacks where an attacker modifies `statement.schema` to route the assertion to a different validator.

**Signature:** RSA-SHA256 signature over `<header>.<payload>`

### Complete Binding Example

```
binding.signature = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhc3NlcnRpb25IYXNoIjoiYWJjZGVmLi4uIiwiYXNzZXJ0aW9uU2lnIjoiZGVmZ2hpLi4uIn0.signature-bytes"
```

## System Metadata Assertions

System metadata assertions use the TDF's Data Encryption Key (DEK) for signing.

### Assertion ID

```
system-metadata
```

### Statement Format

```json
{
  "format": "json+structured",
  "schema": "urn:opentdf:system:metadata:v1",
  "value": {
    "created": "2025-10-16T12:00:00Z",
    "modified": "2025-10-16T12:00:00Z",
    "creator": "user@example.com"
  }
}
```

### Binding Method

Uses `jws` with HMAC-SHA256 using the DEK as the key.

## Custom Assertion Providers

When implementing custom assertion providers, ensure:

1. **Unique Assertion IDs**: Use a prefix or namespace to avoid collisions
   - Good: `myapp-custom-assertion-v1`
   - Bad: `assertion1`

2. **Standard Binding Method**: Use `jws` for the binding method

3. **Well-Defined Schema**: Provide a URN for the statement schema
   - Example: `urn:myorg:myapp:custom:v1`

4. **Signature Format**: Follow JWS Compact Serialization with:
   ```json
   {
     "assertionHash": "<sha256-of-statement>",
     "assertionSig": "<signature-over-manifest>",
     "assertionSchema": "<schema-uri>"
   }
   ```

   **Important**: The `assertionSchema` claim is required for production use to prevent schema substitution attacks. Include it in all custom assertion implementations.

## Validation Requirements

When validating assertions:

1. **Verify Schema**: Check that `statement.schema` matches the expected schema for this validator (defense against schema substitution attacks)
2. **Verify Signature**: Check cryptographic signature using `assertionSig`
3. **Verify Binding**: Confirm `assertionHash` matches SHA-256 of statement
4. **Verify Schema Claim**: Confirm `assertionSchema` claim in JWT matches `statement.schema` (prevents tampering after signing)
5. **Check Trust**: Validate signer is trusted (certificate chain, key ownership)
6. **Policy Enforcement**: Apply any policy rules specific to the assertion type

## Algorithm Support

| Algorithm | Key Type | Assertion Signing | Assertion Validation |
|-----------|----------|-------------------|----------------------|
| RS256     | RSA 2048+ | ✅ | ✅ |
| RS384     | RSA 2048+ | ✅ | ✅ |
| RS512     | RSA 2048+ | ✅ | ✅ |
| ES256     | ECDSA P-256 | ✅ | ✅ |
| ES384     | ECDSA P-384 | ✅ | ✅ |
| HS256     | HMAC (DEK) | ✅ | ✅ |

## Interoperability Checklist

- [ ] Assertion ID follows namespace convention
- [ ] Statement schema is a valid URN
- [ ] Binding method is `jws`
- [ ] Signature follows JWS Compact Serialization
- [ ] `assertionHash` is SHA-256 of statement JSON
- [ ] `assertionSig` covers the manifest signature
- [ ] Algorithm (`alg`) is from supported list
- [ ] Validator can verify signatures from other tools

## Testing Interoperability

To test cross-tool compatibility:

```bash
# Create TDF with examples-cli
./examples-cli encrypt test.txt --private-key-path key.pem -o test.tdf

# Verify with another tool that implements the spec
other-tool decrypt test.tdf --verify-assertions
```

## Backwards Compatibility

### System Metadata Assertion Schema Versions

The SDK supports multiple schema versions for system metadata assertions to maintain backwards compatibility with TDFs created by older SDK versions.

**Signature Payload**:
```json
{
  "assertionHash": "<sha256-of-statement>",
  "assertionSig": "<base64(rootSignature)>"
}
```

**Advantages**:
- Simpler binding mechanism
- Directly reuses the already-signed root signature
- Reduces redundant hash concatenation
- **Cryptographically binds schema to prevent substitution attacks**

#### Schema Version 1 (Legacy - `system-metadata-v1` or empty)

**Used by**: SDK v1.24-
**Signature Binding**: Uses concatenated `aggregateHash + assertionHash`

```json
{
  "id": "system-metadata",
  "statement": {
    "schema": "system-metadata-v1",  // or omitted entirely
    "format": "json",
    "value": "{...}"
  },
  "binding": {
    "signature": "eyJ...  // JWT containing composite hash"
  }
}
```

**Signature Payload**:
```json
{
  "assertionHash": "<sha256-of-statement>",
  "assertionSig": "<base64(aggregateHash + assertionHash)>"
}
```

where `aggregateHash` is the raw concatenation of all segment hashes.

### Dual-Mode Validation

The SDK automatically detects the assertion schema version and applies the appropriate validation logic:

```go
// V2 validation (current)
if assertion.Statement.Schema == "system-metadata-v2" {
    // Verify signature against rootSignature
    if assertionSig != manifest.RootSignature.Signature {
        return ErrAssertionFailure
    }
}

// V1 validation (legacy)
if assertion.Statement.Schema == "system-metadata-v1" || assertion.Statement.Schema == "" {
    // Verify signature against aggregateHash + assertionHash
    expectedSig := base64(aggregateHash + assertionHash)
    if assertionSig != expectedSig {
        return ErrAssertionFailure
    }
}
```

### Migration Guide

#### Reading Old TDFs with New SDK

✅ **Fully Supported**: The new SDK can read and validate TDFs created by older SDK versions (v1.x) through automatic schema detection.

```bash
# TDF created with SDK v1.x
old-sdk encrypt data.txt -o old.tdf

# Can be read with SDK v2.0+
new-sdk decrypt old.tdf  # ✅ Works automatically
```

#### Reading New TDFs with Old SDK

⚠️ **Not Supported**: Older SDK versions (v1.x) cannot read TDFs created by the new SDK (v2.0+) because they don't recognize the v2 schema.

**Workaround**: Continue using SDK v1.x for TDF creation during migration period, or coordinate simultaneous upgrades.

#### Creating TDFs During Migration

To ensure maximum compatibility during a migration period:

1. **Default Behavior** (Recommended): New SDK creates TDFs with v2 schema
   ```go
   sdk.CreateTDF(output, input, WithSystemMetadataAssertion())
   // Uses system-metadata-v2
   ```

2. **All Consumers Must Upgrade**: Plan for coordinated upgrade when using v2 schema

3. **Phased Migration**:
   - Phase 1: Upgrade all readers to SDK v2.0+ (can read both v1 and v2)
   - Phase 2: Upgrade writers to SDK v2.0+ (starts creating v2 TDFs)
   - Phase 3: Decommission SDK v1.x entirely

### Compatibility Matrix

| TDF Creator | TDF Reader | Result |
|------------|-----------|--------|
| SDK v1.x (v1 schema) | SDK v1.x | ✅ Works |
| SDK v1.x (v1 schema) | SDK v2.0+ | ✅ Works (auto-detects v1) |
| SDK v2.0+ (v2 schema) | SDK v1.x | ❌ Fails (v1 doesn't recognize v2) |
| SDK v2.0+ (v2 schema) | SDK v2.0+ | ✅ Works |

### Version Detection

The SDK determines the schema version using this logic:

1. **Explicit v2**: `statement.schema == "system-metadata-v2"` → Use v2 validation
2. **Explicit v1**: `statement.schema == "system-metadata-v1"` → Use v1 validation
3. **Empty/Missing**: `statement.schema == ""` → Use v1 validation (backwards compatible)

### Testing Backwards Compatibility

```go
// Unit tests verify dual-mode validation
func TestSystemMetadataAssertion_SchemaVersionDetection(t *testing.T) {
    // Tests v1, v2, and empty schema validation paths
}
```

See `sdk/assertion_provider_sm_test.go` for complete test coverage.

## References

- [OpenTDF Specification](https://github.com/opentdf/spec)
- [JWS (RFC 7515)](https://datatracker.ietf.org/doc/html/rfc7515)
- [JWT (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519)
- [Backwards Compatibility Analysis](../BACKWARDS_COMPATIBILITY_ANALYSIS.md) (detailed technical analysis)
