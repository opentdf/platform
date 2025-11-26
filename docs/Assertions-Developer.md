---
sidebar_position: 2
---

# Assertions Developer Guide

This guide explains how to implement and use assertions with the OpenTDF SDK. It provides practical code examples, type definitions, and implementation patterns for developers integrating assertions into their applications.

For conceptual information about assertions (structure, lifecycle, security features), see [Assertions.md](./Assertions.md).

## Creating a simple assertion

The simplest path to creating a custom assertion follows four steps:

1. Design a small payload (for example, a document classification).
2. Serialize that payload (commonly to JSON).
3. Build an `AssertionConfig` with the required fields and optional `SigningKey`.
4. Pass the config to the relevant SDK API when creating or updating your TDF object.

### Minimal Go example

```go
package main

import (
    "encoding/json"
    "log"

    "github.com/google/uuid"
    sdk "github.com/opentdf/platform/sdk"
)

// 1) Design your payload
type DocClassification struct {
    Classification string `json:"classification"`
    Owner          string `json:"owner"`
}

func buildAssertionConfig() sdk.AssertionConfig {
    // 2) Serialize your payload
    classification := DocClassification{
        Classification: "internal",
        Owner:          "team-a",
    }

    payloadBytes, err := json.Marshal(classification)
    if err != nil {
        log.Fatalf("marshal classification: %v", err)
    }

    // 3) Build AssertionConfig (no SigningKey in this minimal example)
    cfg := sdk.AssertionConfig{
        ID:             uuid.New().String(), // Generate unique ID for this assertion
        Type:           sdk.HandlingAssertion, // or sdk.BaseAssertion
        Scope:          sdk.PayloadScope,      // applies to the payload
        AppliesToState: sdk.Unencrypted,       // or sdk.Encrypted
        Statement: sdk.Statement{
            Format: "json",
            Schema: "urn:myorg:doc-classification-schema:v2",
            Value:  string(payloadBytes),
        },
        // Optional: SigningKey if you want a cryptographic binding
        // SigningKey: sdk.AssertionKey{ Alg: sdk.AssertionKeyAlgRS256, Key: myPrivateKey },
    }
    return cfg
}
```

Once you have the config, pass it to the SDK where you create the TDF or attach assertions. The exact function varies by SDK surface; look for creation options or APIs that accept `AssertionConfig` or a list of assertion configs.

---

## AssertionConfig overview

`AssertionConfig` is a configuration-time representation of an assertion. It mirrors the data that will ultimately appear in an `Assertion`, with one important addition: a signing key.

```go
type AssertionConfig struct {
    ID             string         `validate:"required"`
    Type           AssertionType  `validate:"required"`
    Scope          Scope          `validate:"required"`
    AppliesToState AppliesToState `validate:"required"`
    Statement      Statement
    SigningKey     AssertionKey
}
```

It is used when creating an assertion:

- You specify what the assertion is about (`Statement`).
- You specify where it applies (`Scope`) and when it applies (`AppliesToState`).
- You specify what kind of assertion it is (`Type`).
- You provide a unique identifier (`ID`) for this assertion within the TDF manifest, used for internal referencing.
- Optionally, you provide a signing key (`SigningKey`) so the created assertion can be cryptographically bound.

At runtime, the SDK code takes an `AssertionConfig`, turns it into an `Assertion`, and (if a key is present) signs it.

---

## Fields you must set

When implementing a custom assertion, you will typically set:

### ID

A unique string that identifies your assertion instance or assertion family within this TDF manifest.

**Recommended approach:** Use UUIDs for assertion IDs to guarantee uniqueness. The SDK uses the `github.com/google/uuid` package internally for generating unique identifiers:

```go
import "github.com/google/uuid"

// Generate a unique assertion ID
assertionID := uuid.New().String()
// Result: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

**Alternative approaches:**
- Namespaced descriptive IDs: `"myapp-doc-classification-v1"`, `"urn:myorg:pii-tag:v1"`
- Composite IDs with timestamp: `"doc-classification-2025-01-15T10:30:00Z"`

**Examples:** `"f47ac10b-58cc-4372-a567-0e02b2c3d479"`, `"doc-classification-v1"`, `"pii-tag"`, `"customer-policy-123"`

### Type (`AssertionType`)

A classification of the assertion. Common values in the SDK include:

| Constant | Value | Description |
|----------|-------|-------------|
| `sdk.HandlingAssertion` | `"handling"` | For handling/usage/policy-related assertions |
| `sdk.MetadataAssertion` | `"metadata"` | For general information assertions |
| `sdk.BaseAssertion` | `"other"` | For general or other types of assertions |

### Scope (`Scope`)

What this assertion applies to:

| Constant | Value | Description |
|----------|-------|-------------|
| `sdk.TrustedDataObjScope` | `"tdo"` | The whole trusted data object (container) |
| `sdk.PayloadScope` | `"payload"` | The payload inside the container |

### AppliesToState (`AppliesToState`)

Whether the assertion applies to encrypted or unencrypted form:

| Constant | Value | Description |
|----------|-------|-------------|
| `sdk.Encrypted` | `"encrypted"` | Assertion applies to encrypted data |
| `sdk.Unencrypted` | `"unencrypted"` | Assertion applies to unencrypted data |

### Statement (`Statement`)

The actual payload of your assertion:

```go
type Statement struct {
    Format string `json:"format,omitempty" validate:"required"`
    Schema string `json:"schema,omitempty" validate:"required"`
    Value  string `json:"value,omitempty"  validate:"required"`
}
```

| Field | Description |
|-------|-------------|
| `Format` | How `Value` is encoded, for example `"json"` or `"string"`. Use `sdk.StatementFormatJSON` or `sdk.StatementFormatString` constants. |
| `Schema` | Logical schema name or version for your payload, e.g. `"doc-classification-v1"` |
| `Value` | The payload itself, usually a JSON string if `Format` is `"json"` |

### SigningKey (`AssertionKey`)

A key plus algorithm used to sign the assertion during creation. If present, the SDK will produce a cryptographic binding so the assertion can't be tampered with or moved to another object undetected.

```go
type AssertionKey struct {
    Alg AssertionKeyAlg  // Algorithm: sdk.AssertionKeyAlgRS256 or sdk.AssertionKeyAlgHS256
    Key interface{}      // The key value (e.g., *rsa.PrivateKey for RS256)
}
```

---

## Implementing a simple custom assertion

This section shows how to define a minimal custom assertion that carries some JSON metadata.

### 1. Design your payload

Decide what information you want to carry. For example, a simple document classification assertion:

```json
{
  "classification": "internal",
  "owner": "team-a"
}
```

### 2. Serialize your payload

In Go, you usually marshal your payload struct to JSON, then store it as `Statement.Value`.

```go
type DocClassification struct {
    Classification string `json:"classification"`
    Owner          string `json:"owner"`
}
```

### 3. Build the AssertionConfig

Create an `AssertionConfig` with the required fields:

```go
classification := DocClassification{
    Classification: "internal",
    Owner:          "team-a",
}

// Serialize payload to JSON string
payloadBytes, err := json.Marshal(classification)
if err != nil {
    // handle error
}

cfg := sdk.AssertionConfig{
    ID:             uuid.New().String(),         // unique ID (UUID recommended)
    Type:           sdk.HandlingAssertion,       // or BaseAssertion
    Scope:          sdk.PayloadScope,            // applies to the payload
    AppliesToState: sdk.Unencrypted,             // or Encrypted

    Statement: sdk.Statement{
        Format: "json",                         // payload is JSON
        Schema: "doc-classification-schema-v1", // your schema name/version
        Value:  string(payloadBytes),            // JSON as string
    },

    // Optional: add signing key if you want this assertion cryptographically bound
    // SigningKey: sdk.AssertionKey{
    //     Alg: sdk.AssertionKeyAlgRS256,
    //     Key: myPrivateKey, // e.g. *rsa.PrivateKey
    // },
}
```

### 4. Use the config in your integration

The exact function you call to "attach" this assertion depends on the rest of the SDK, but the pattern is:

1. Build an `AssertionConfig` as above.
2. Pass it into the relevant creation API (for example, when creating a TDF / payload / envelope).
3. The SDK:
   - Converts `AssertionConfig` into an `Assertion`.
   - Calculates a canonical hash over the assertion.
   - Signs it using `SigningKey`, embedding the signature in the assertion's binding.
   - Embeds the assertion into your object.

Your code outside the SDK only needs to know how to construct `AssertionConfig` correctly; the signing and binding is handled for you.

---

## Advanced: Implementing custom assertion providers

For more control over assertion creation and verification, you can implement the `AssertionBinder` and `AssertionValidator` interfaces.

### AssertionBinder interface

The `AssertionBinder` interface allows you to create custom assertions during TDF creation:

```go
// AssertionBinder creates assertions during TDF creation
type AssertionBinder interface {
    Bind(ctx context.Context, manifest Manifest) (Assertion, error)
}
```

### AssertionValidator interface

The `AssertionValidator` interface allows you to verify and validate assertions during TDF reading:

```go
// AssertionValidator verifies and validates assertions during TDF reading
type AssertionValidator interface {
    // Verify checks the cryptographic binding of the assertion
    Verify(ctx context.Context, assertion Assertion, reader Reader) error
    // Validate performs business logic validation on the assertion
    Validate(ctx context.Context, assertion Assertion, reader Reader) error
    // Schema returns the schema URI this validator handles
    Schema() string
}
```

### Example: Custom assertion provider

Here's a simplified example of a custom assertion provider:

```go
package myapp

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"

    "github.com/opentdf/platform/sdk"
)

const (
    CustomAssertionSchema = "urn:myorg:custom:assertion:v1"
)

// CustomAssertionProvider implements AssertionBinder and AssertionValidator
type CustomAssertionProvider struct {
    SecretKey []byte
}

// Bind creates the assertion during TDF creation
func (p *CustomAssertionProvider) Bind(ctx context.Context, m sdk.Manifest) (sdk.Assertion, error) {
    // Create your custom payload
    payload := map[string]interface{}{
        "timestamp": time.Now().UTC().Format(time.RFC3339),
        "metadata":  "custom-value",
    }
    
    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        return sdk.Assertion{}, fmt.Errorf("failed to marshal payload: %w", err)
    }

    // Build the assertion
    assertion := sdk.Assertion{
        ID:             CustomAssertionID,
        Type:           sdk.MetadataAssertion,
        Scope:          sdk.PayloadScope,
        AppliesToState: sdk.Unencrypted,
        Statement: sdk.Statement{
            Format: sdk.StatementFormatJSON,
            Schema: CustomAssertionSchema,
            Value:  string(payloadBytes),
        },
    }

    // Get the assertion hash for binding
    assertionHash, err := assertion.GetHash()
    if err != nil {
        return sdk.Assertion{}, fmt.Errorf("failed to get assertion hash: %w", err)
    }

    // Create cryptographic binding (bind to manifest and assertion content)
    bindingHMAC := hmac.New(sha256.New, p.SecretKey)
    bindingHMAC.Write([]byte(m.RootSignature.Signature))
    bindingHMAC.Write(assertionHash)
    signature := hex.EncodeToString(bindingHMAC.Sum(nil))

    assertion.Binding = sdk.Binding{
        Method:    "hmac-sha256",
        Signature: signature,
    }

    return assertion, nil
}

// Verify checks the cryptographic binding
func (p *CustomAssertionProvider) Verify(ctx context.Context, a sdk.Assertion, r sdk.Reader) error {
    if a.Binding.Signature == "" {
        return errors.New("assertion has no cryptographic binding")
    }

    // Recompute and verify the binding signature
    assertionHash, err := a.GetHash()
    if err != nil {
        return fmt.Errorf("failed to get assertion hash: %w", err)
    }

    manifest := r.Manifest()
    bindingHMAC := hmac.New(sha256.New, p.SecretKey)
    bindingHMAC.Write([]byte(manifest.RootSignature.Signature))
    bindingHMAC.Write(assertionHash)
    expectedSignature := hex.EncodeToString(bindingHMAC.Sum(nil))

    if a.Binding.Signature != expectedSignature {
        return errors.New("binding signature verification failed")
    }

    return nil
}

// Validate performs business logic validation
func (p *CustomAssertionProvider) Validate(ctx context.Context, a sdk.Assertion, r sdk.Reader) error {
    // Add your custom validation logic here
    return nil
}

// Schema returns the schema URI this validator handles
func (p *CustomAssertionProvider) Schema() string {
    return CustomAssertionSchema
}
```

---

## Best practices for custom assertions

### Use stable IDs

If your assertion is versioned, include a version in the ID or in the `Statement.Schema`, and be consistent.

### Keep schema explicit

Treat `Statement.Schema` as a contract. When you change the shape of `Value`, bump the schema version so consumers know how to interpret it.

**Good examples (URI):**
- `"urn:myorg:custom:assertion:v1"`
- `"http://myorg.com/schemas/doc-classification/v2"`

### Prefer JSON for complex values

When `Format` is `"json"`, make `Value` a serialized JSON document; this works well with the SDK's JSON handling and keeps things interoperable.

### Sign assertions that affect policy or security

If the assertion controls access or behavior (e.g., usage rules), provide a `SigningKey` so downstream verifiers can trust that the assertion hasn't been tampered with.

### Use unique namespaced IDs

Use a prefix or namespace to avoid collisions with other assertion providers:

**Good:** `"myapp-custom-assertion-v1"`, `"urn:myorg:policy:v1"`

**Bad:** `"assertion1"`, `"custom"`

### Implement proper verification

When implementing a custom `AssertionValidator`:

1. Always verify the cryptographic binding
2. Check that the schema matches what you expect
3. Validate the assertion content against your business rules
4. Return clear error messages for debugging

---

## Related documentation

- [Assertions](./Assertions.md) - Complete assertions format and lifecycle documentation
- [Assertion Specification](https://github.com/opentdf/spec/blob/main/schema/OpenTDF/assertion.md)
