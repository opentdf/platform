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
  "assertionSig": "<signature-over-manifest>"
}
```

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
     "assertionSig": "<signature-over-manifest>"
   }
   ```

## Validation Requirements

When validating assertions:

1. **Verify Signature**: Check cryptographic signature using `assertionSig`
2. **Verify Binding**: Confirm `assertionHash` matches SHA-256 of statement
3. **Check Trust**: Validate signer is trusted (certificate chain, key ownership)
4. **Policy Enforcement**: Apply any policy rules specific to the assertion type

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

## References

- [OpenTDF Specification](https://github.com/opentdf/spec)
- [JWS (RFC 7515)](https://datatracker.ietf.org/doc/html/rfc7515)
- [JWT (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519)
